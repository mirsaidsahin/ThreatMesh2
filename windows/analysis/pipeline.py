"""Analiz pipeline'i: snapshot'lari karsilastir -> risk hesapla -> event/finding yaz.

Girdi: DB'deki scans/scan_devices/scan_services (V1 yapisi). Cikti: events + risk_scores.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .diff_engine import DeviceObs, ServiceObs, diff_devices, diff_services
from .finding_engine import build_finding
from .knowledge import load_kb
from .risk_engine import (STATE_TYPES, compute_risk, event_points, load_rules,
                          severity_from_points, state_findings)


@dataclass
class AnalysisResult:
    scan_id: int
    events: int
    risk_rows: int


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_obs(conn, scan_id):
    rows = conn.execute(
        "SELECT sd.device_id, sd.ip, d.mac, d.vendor FROM scan_devices sd "
        "JOIN devices d ON d.device_id = sd.device_id WHERE sd.scan_id=?", (scan_id,))
    return {r["device_id"]: DeviceObs(r["device_id"], r["ip"], r["mac"], r["vendor"]) for r in rows}


def _last_known_ips(conn, scan_id):
    rows = conn.execute(
        "SELECT sd.device_id, sd.ip FROM scan_devices sd WHERE sd.scan_id = "
        "(SELECT MAX(s2.scan_id) FROM scan_devices s2 "
        " WHERE s2.device_id = sd.device_id AND s2.scan_id < ?)", (scan_id,))
    return {r["device_id"]: r["ip"] for r in rows}


def _load_services(conn, scan_id, device_id, kb):
    rows = conn.execute(
        "SELECT port, protocol, service_name, product, version FROM scan_services "
        "WHERE scan_id=? AND device_id=? ORDER BY port, protocol", (scan_id, device_id))
    return [ServiceObs(r["port"], r["protocol"], kb.resolve_service(r["service_name"]),
                       r["product"], r["version"], r["service_name"]) for r in rows]


def _baseline_scan(conn, scan_id, device_id):
    """Cihazin gorundugu, servis verisi iceren en son onceki scan."""
    return conn.execute(
        "SELECT MAX(s.scan_id) FROM scans s JOIN scan_devices sd ON sd.scan_id = s.scan_id "
        "WHERE s.scan_id < ? AND s.has_service_data = 1 AND sd.device_id = ?",
        (scan_id, device_id)).fetchone()[0]


def analyze_scan(conn, scan_id, force=False, kb=None, rules=None):
    """Scan'i analiz eder. Zaten analiz edildiyse None doner (force=True ile yeniden yapilir)."""
    kb = kb or load_kb()
    rules = rules or load_rules()
    scan = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if scan is None:
        raise ValueError(f"Scan bulunamadi: {scan_id}")
    if scan["analyzed_at"] and not force:
        return None
    with conn:
        if force:
            conn.execute("DELETE FROM events WHERE scan_id=?", (scan_id,))
        else:  # V1'in ingest sirasinda yazdigi eski event'ler yeniden uretilecek
            conn.execute("DELETE FROM events WHERE scan_id=? "
                         "AND event_type IN ('NEW_DEVICE','IP_CHANGED')", (scan_id,))
        conn.execute("DELETE FROM risk_scores WHERE scan_id=?", (scan_id,))
        result = _analyze(conn, scan, kb, rules)
        conn.execute("UPDATE scans SET analyzed_at=? WHERE scan_id=?", (_now(), scan_id))
    return result


def analyze_pending(conn, kb=None, rules=None):
    ids = [r[0] for r in conn.execute(
        "SELECT scan_id FROM scans WHERE analyzed_at IS NULL ORDER BY scan_id")]
    return [analyze_scan(conn, i, kb=kb, rules=rules) for i in ids]


def _analyze(conn, scan, kb, rules):
    sid, ts = scan["scan_id"], scan["started_at"]
    has_service = bool(scan["has_service_data"])
    if not has_service:
        has_service = bool(conn.execute(
            "SELECT 1 FROM scan_services WHERE scan_id=? LIMIT 1", (sid,)).fetchone())
    curr = _load_obs(conn, sid)
    roles = {r["device_id"]: r["role"] for r in conn.execute("SELECT device_id, role FROM devices")}
    changes = []

    # 1) Cihaz seviyesi diff (baseline scan'de event yok)
    prev_row = conn.execute(
        "SELECT * FROM scans WHERE scan_id < ? ORDER BY scan_id DESC LIMIT 1", (sid,)).fetchone()
    if prev_row is not None:
        same_scope = (prev_row["target_scope"] or "") == (scan["target_scope"] or "")
        dev_changes = diff_devices(curr, _load_obs(conn, prev_row["scan_id"]),
                                   _last_known_ips(conn, sid), compare_offline=same_scope)
        for c in dev_changes:
            c.prev_scan = prev_row["scan_id"]
        changes += dev_changes

    # 2) Servis seviyesi diff + durum bazli finding'ler (sadece servis verisi olan scan'lerde)
    services_by_dev = {}
    if has_service:
        for did in sorted(curr):
            ip, role = curr[did].ip, roles.get(did)
            cur_svcs = _load_services(conn, sid, did, kb)
            services_by_dev[did] = cur_svcs
            base = _baseline_scan(conn, sid, did)
            prev_keys = set()
            if base is not None:
                prev_svcs = _load_services(conn, base, did, kb)
                for c in diff_services(did, ip, prev_svcs, cur_svcs):
                    c.prev_scan = base
                    changes.append(c)
                prev_keys = {c.finding_key for c in
                             state_findings(did, ip, prev_svcs, role, kb, rules)}
            for c in state_findings(did, ip, cur_svcs, role, kb, rules):
                if c.finding_key not in prev_keys:  # kalici bulgu her scan'de tekrarlanmaz
                    c.prev_scan = base
                    changes.append(c)

    # 3) Baglam (beklenen/beklenmeyen/bilinmeyen) ve puan: diff event'leri icin
    for c in changes:
        if c.event_type in STATE_TYPES:
            continue
        c.expectation = (kb.expectation(roles.get(c.device_id), c.service_id)
                         if c.service_id else "UNKNOWN")
        c.points = event_points(c.event_type, c.expectation, rules)

    # 4) Event + finding yaz
    for c in changes:
        finding = build_finding(kb, c, sid, roles.get(c.device_id))
        severity = finding.severity or severity_from_points(c.points)
        conn.execute(
            "INSERT INTO events(timestamp,scan_id,device_id,event_type,severity,description,"
            "evidence,finding_key,expectation,risk_points,finding_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ts, sid, c.device_id, c.event_type, severity, finding.summary, json.dumps(c.data),
             c.finding_key, c.expectation, c.points, json.dumps(finding.to_dict())))

    # 5) Cihaz basina risk skoru
    risk_rows = 0
    for did in sorted(curr):
        scored = [(c.event_type, c.points, c.expectation,
                   str(c.data.get("port") or c.data.get("service") or ""))
                  for c in changes if c.device_id == did
                  and c.event_type in rules["event_points"] and c.points > 0]
        risk = compute_risk(services_by_dev.get(did, []), roles.get(did), scored, kb, rules,
                            has_service_data=has_service)
        conn.execute(
            "INSERT INTO risk_scores(scan_id,device_id,score,level,factors,timestamp) "
            "VALUES (?,?,?,?,?,?)",
            (sid, did, risk.score, risk.level,
             json.dumps([f.to_dict() for f in risk.factors]), ts))
        risk_rows += 1

    return AnalysisResult(sid, len(changes), risk_rows)