"""Parse edilmis scan'i DB'ye yazar: kimlik cozumleme + snapshot.
Event uretmez; analiz pipeline'a birakilir (analyze=True ile otomatik calisir)."""
import hashlib
import json
import shutil
from pathlib import Path

from .database.db import ROOT
from .parser.nmap_parser import parse_nmap_xml

RAW_DIR = ROOT / "data" / "raw"


def resolve_device(conn, host, ts):
    """Oncelik MAC, yedek IP. Donus: (device_id, is_new, old_ip)."""
    row = None
    if host.mac:
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (host.mac,)).fetchone()
        if row is None:  # daha once MAC'siz gorulmus ayni IP'yi yukselt
            row = conn.execute(
                "SELECT * FROM devices WHERE mac IS NULL AND last_ip=?", (host.ip,)
            ).fetchone()
            if row is not None:
                conn.execute(
                    "UPDATE devices SET mac=?, identity='mac_confirmed' WHERE device_id=?",
                    (host.mac, row["device_id"]),
                )
    else:
        row = conn.execute(
            "SELECT * FROM devices WHERE last_ip=? ORDER BY last_seen DESC", (host.ip,)
        ).fetchone()

    if row is None:
        cur = conn.execute(
            "INSERT INTO devices(mac,identity,vendor,hostname,last_ip,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?)",
            (host.mac, "mac_confirmed" if host.mac else "ip_only",
             host.vendor, host.hostname, host.ip, ts, ts),
        )
        return cur.lastrowid, True, None

    conn.execute(
        "UPDATE devices SET last_ip=?, last_seen=?, vendor=COALESCE(?,vendor), "
        "hostname=COALESCE(?,hostname) WHERE device_id=?",
        (host.ip, ts, host.vendor, host.hostname, row["device_id"]),
    )
    return row["device_id"], False, row["last_ip"]


def ingest_scan(conn, xml_path, analyze=True):
    """Donus: scan_id, ya da dosya daha once yuklendiyse None.

    analyze=True ise ingest sonrasi analysis.pipeline.analyze_scan cagirilir.
    """
    xml_path = Path(xml_path)
    digest = hashlib.sha256(xml_path.read_bytes()).hexdigest()
    if conn.execute("SELECT 1 FROM scans WHERE file_hash=?", (digest,)).fetchone():
        return None

    parsed = parse_nmap_xml(xml_path)
    meta = {}
    sidecar = xml_path.with_suffix(".json")
    if sidecar.exists():
        meta = json.loads(sidecar.read_text(encoding="utf-8"))

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    raw_copy = RAW_DIR / xml_path.name
    if raw_copy.resolve() != xml_path.resolve():
        shutil.copy2(xml_path, raw_copy)

    ts = parsed.started_at
    args_text = meta.get("nmap_args") or parsed.args or ""
    has_service_data = 0 if "-sn" in args_text else 1   

    with conn:
        cur = conn.execute(
            "INSERT INTO scans(started_at,duration,target_scope,mode,sensor_id,profile,"
            "raw_file,file_hash,nmap_args,has_service_data) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ts, parsed.duration, ",".join(meta.get("targets", [])), meta.get("mode"),
             meta.get("sensor_id"), meta.get("profile"), raw_copy.name, digest,
             meta.get("nmap_args") or parsed.args, has_service_data),
        )
        scan_id = cur.lastrowid
        n_services = n_ports = 0

        for host in parsed.hosts:
            device_id, _is_new, _old_ip = resolve_device(conn, host, ts)
            conn.execute(
                "INSERT OR IGNORE INTO scan_devices(scan_id,device_id,ip,hostname,status) "
                "VALUES (?,?,?,?,?)",
                (scan_id, device_id, host.ip, host.hostname, host.status),
            )
            for s in host.services:
                conn.execute(
                    "INSERT OR IGNORE INTO scan_services(scan_id,device_id,port,protocol,state,"
                    "service_name,product,version) VALUES (?,?,?,?,?,?,?,?)",
                    (scan_id, device_id, s.port, s.protocol, s.state, s.name, s.product, s.version),
                )
                n_ports += 1
                n_services += 1 if s.name else 0

        conn.execute(
            "UPDATE scans SET device_count=?, service_count=?, port_count=? WHERE scan_id=?",
            (len(parsed.hosts), n_services, n_ports, scan_id),
        )

    if analyze:
        # dongusel import: pipeline -> diff_engine -> ... ingest'e geri donmesin
        from .analysis.pipeline import analyze_scan
        analyze_scan(conn, scan_id)

    return scan_id