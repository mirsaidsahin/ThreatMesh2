"""Read-only data access for V3.

Uses windows.database.db.connect() so V3 reads the same DB through the same
connection setup as V2 (foreign keys, row_factory, migration on init).
"""
from typing import List

from windows.database.db import connect, init_db

from v3.models import Scan, Device, Service, RiskScore, Event


def get_connection():
    conn = connect()
    try:
        init_db(conn)
    except Exception:
        pass
    return conn


_SEVERITY_ORDER = """
CASE severity
    WHEN 'CRITICAL' THEN 0
    WHEN 'HIGH'     THEN 1
    WHEN 'MEDIUM'   THEN 2
    WHEN 'LOW'      THEN 3
    ELSE 4
END
"""


def get_scans() -> List[Scan]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT scan_id, started_at, device_count "
            "FROM scans ORDER BY scan_id DESC"
        ).fetchall()
        return [Scan(r["scan_id"], r["started_at"], r["device_count"] or 0)
                for r in rows]


def get_devices(scan_id: int) -> List[Device]:
    devices = []
    with get_connection() as conn:
        d_rows = conn.execute(
            "SELECT d.device_id, d.role, sd.ip "
            "FROM devices d JOIN scan_devices sd ON d.device_id = sd.device_id "
            "WHERE sd.scan_id = ? ORDER BY sd.device_id",
            (scan_id,),
        ).fetchall()

        for d in d_rows:
            dev_id = d["device_id"]

            r_row = conn.execute(
                "SELECT score, level FROM risk_scores "
                "WHERE scan_id=? AND device_id=?",
                (scan_id, dev_id),
            ).fetchone()
            risk = RiskScore(r_row["score"], r_row["level"]) if r_row else None

            s_rows = conn.execute(
                "SELECT port, protocol, service_name, state FROM scan_services "
                "WHERE scan_id=? AND device_id=? ORDER BY port",
                (scan_id, dev_id),
            ).fetchall()
            services = [
                Service(s["port"], s["protocol"],
                        s["service_name"] or "unknown",
                        s["state"] or "open")
                for s in s_rows
            ]

            devices.append(Device(
                device_id=dev_id,
                ip=d["ip"],
                role=d["role"] or "UNKNOWN",
                risk=risk,
                services=services,
            ))
    return devices


def get_events(scan_id: int) -> List[Event]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT event_id, device_id, event_type, severity, description, risk_points "
            "FROM events WHERE scan_id=? "
            "ORDER BY " + _SEVERITY_ORDER + ", event_id",
            (scan_id,),
        ).fetchall()
        return [
            Event(
                event_id=r["event_id"],
                device_id=r["device_id"],
                event_type=r["event_type"],
                severity=r["severity"],
                description=r["description"] or "",
                risk_points=r["risk_points"] or 0,
            )
            for r in rows
        ]