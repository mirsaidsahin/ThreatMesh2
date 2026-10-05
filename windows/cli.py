"""ThreatMesh CLI (V1 + V2).  Run from project root: python -m windows.cli <command>"""
import argparse
import json
import sys
from pathlib import Path

from .database.db import ROOT, connect, init_db
from .analysis.knowledge import load_kb
from .analysis.pipeline import analyze_pending, analyze_scan
from .ingest import ingest_scan


def cmd_init(conn, args):
    init_db(conn)
    print("[+] Database ready.")


def cmd_ingest(conn, args):
    init_db(conn)
    p = Path(args.path)
    files = sorted(p.glob("*.xml")) if p.is_dir() else [p]
    if not files:
        print("[i] No XML files found.")
    for f in files:
        try:
            sid = ingest_scan(conn, f, analyze=not args.no_analyze)
        except ValueError as e:
            print(f"[!] {e}")
            continue
        print(f"[=] Already ingested: {f.name}" if sid is None
              else f"[+] Scan #{sid:03d} loaded: {f.name}")


def cmd_scans(conn, args):
    rows = conn.execute("SELECT * FROM scans ORDER BY scan_id").fetchall()
    print(f"{'ID':<5} {'Time (UTC)':<27} {'Mode':<11} {'Devices':<9} {'Ports':<7} Duration")
    for r in rows:
        print(f"{r['scan_id']:<5} {r['started_at']:<27} {(r['mode'] or '-'):<11} "
              f"{r['device_count']:<9} {r['port_count']:<7} {r['duration']}")


def _latest_scan(conn):
    return conn.execute("SELECT MAX(scan_id) FROM scans").fetchone()[0]


def cmd_devices(conn, args):
    latest = _latest_scan(conn)
    rows = conn.execute(
        "SELECT d.*, (SELECT MAX(scan_id) FROM scan_devices sd WHERE sd.device_id=d.device_id) AS last_scan "
        "FROM devices d ORDER BY d.device_id"
    ).fetchall()
    print(f"{'ID':<4}{'IP':<16}{'MAC':<19}{'Vendor':<24}{'Status':<9}Identity")
    for r in rows:
        status = "ONLINE" if r["last_scan"] == latest else "OFFLINE"
        print(f"{r['device_id']:<4}{(r['last_ip'] or '-'):<16}{(r['mac'] or '-'):<19}"
              f"{(r['vendor'] or '-')[:22]:<24}{status:<9}{r['identity']}")


def cmd_show(conn, args):
    q = args.query.upper() if ":" in args.query else args.query
    d = conn.execute("SELECT * FROM devices WHERE last_ip=? OR mac=?", (args.query, q)).fetchone()
    if d is None:
        sys.exit("[!] Device not found.")
    last = conn.execute("SELECT MAX(scan_id) FROM scan_devices WHERE device_id=?",
                        (d["device_id"],)).fetchone()[0]
    status = "ONLINE" if last == _latest_scan(conn) else "OFFLINE"
    print("DEVICE PROFILE")
    print(f"  IP:           {d['last_ip']}")
    print(f"  MAC:          {d['mac'] or '-'}  ({d['identity']})")
    print(f"  Vendor:       {d['vendor'] or '-'}")
    print(f"  Hostname:     {d['hostname'] or '-'}  (DNS name is not a definitive identity)")
    print("  Device type:  Unknown Device  (V2 will add 'Possible ...' estimation)")
    print(f"  Status:       {status}")
    print(f"  Role:         {d['role'] or '-'}  (set via set-role; used for context analysis)")
    rs = conn.execute("SELECT * FROM risk_scores WHERE device_id=? ORDER BY scan_id DESC LIMIT 1",
                      (d["device_id"],)).fetchone()
    if rs:
        print(f"  Risk:         {rs['score']} / 100 {rs['level']}  "
              f"(ThreatMesh Custom Risk Score, scan #{rs['scan_id']:03d})")
    print(f"  First seen:   {d['first_seen']}")
    print(f"  Last seen:    {d['last_seen']}")
    print("  Open ports (latest scan):")
    svcs = conn.execute(
        "SELECT * FROM scan_services WHERE scan_id=? AND device_id=? ORDER BY port",
        (last, d["device_id"])).fetchall()
    for s in svcs or []:
        ver = " ".join(x for x in (s["product"], s["version"]) if x)
        print(f"    {s['port']}/{s['protocol']}  {s['service_name'] or 'unknown'}  {ver}")
    if not svcs:
        print("    (none / no service scan)")
    print("  Events:")
    evs = conn.execute("SELECT * FROM events WHERE device_id=? ORDER BY event_id",
                       (d["device_id"],)).fetchall()
    for e in evs:
        print(f"    [{e['severity']}] {e['timestamp']} {e['event_type']}: {e['description']}")
    if not evs:
        print("    (none)")


def cmd_analyze(conn, args):
    if args.scan:
        res = analyze_scan(conn, args.scan, force=args.force)
        done = [res] if res else []
    else:
        done = [r for r in analyze_pending(conn) if r]
    for r in done:
        print(f"[+] Scan #{r.scan_id:03d} analyzed: {r.events} events, {r.risk_rows} risk scores")
    if not done:
        print("[=] No scans to analyze (rerun with: analyze --scan N --force)")


def cmd_events(conn, args):
    q = ("SELECT e.*, d.last_ip FROM events e LEFT JOIN devices d ON d.device_id=e.device_id")
    params = ()
    if args.scan:
        q += " WHERE e.scan_id=?"
        params = (args.scan,)
    rows = conn.execute(q + " ORDER BY e.event_id", params).fetchall()
    print(f"{'ID':<5}{'Scan':<6}{'Sev':<8}{'Type':<25}{'Expectation':<13}{'Pts':<6}{'Device':<16}Summary")
    for e in rows:
        print(f"{e['event_id']:<5}{e['scan_id']:<6}{e['severity']:<8}{e['event_type']:<25}"
              f"{(e['expectation'] or '-'):<13}{(e['risk_points'] or 0):<6}"
              f"{(e['last_ip'] or '-'):<16}{e['description']}")
    if not rows:
        print("(no events)")


def _bullets(items):
    return "\n".join(f"    - {i}" for i in items)


def cmd_explain(conn, args):
    e = conn.execute("SELECT * FROM events WHERE event_id=?", (args.event_id,)).fetchone()
    if e is None:
        sys.exit("[!] Event not found.")
    if not e["finding_json"]:
        sys.exit("[!] No explanation for this event. Run: analyze --scan N --force")
    f = json.loads(e["finding_json"])
    print(f"FINDING #{e['event_id']}  {e['event_type']}  [{e['severity']}]  "
          f"expectation={e['expectation']}  risk_points={e['risk_points']}")
    print(f"\nWhat happened?\n    {f['what_happened']}")
    if f["context"]:
        print(f"    Context: {f['context']}")
    print(f"\nWhy does it matter?\n    {f['why_it_matters']}")
    print(f"\nHow was it detected?\n    {f['how_detected']}")
    print(f"\nWhat should the normal/recommended state look like?\n    {f['recommended_state']}")
    print(f"\nWhat should be investigated?\n{_bullets(f['investigate'])}")
    print(f"\nWhat should NOT be done?\n{_bullets(f['do_not'])}")
    print(f"\nRecommended mitigation:\n{_bullets(f['mitigation'])}")
    print(f"\nNote: {f['disclaimer']}")


def cmd_risk(conn, args):
    scan = args.scan or conn.execute("SELECT MAX(scan_id) FROM risk_scores").fetchone()[0]
    if scan is None:
        sys.exit("[!] No risk scores. Run ingest/analyze first.")
    rows = conn.execute(
        "SELECT r.*, d.last_ip, d.mac, d.role FROM risk_scores r JOIN devices d "
        "ON d.device_id=r.device_id WHERE r.scan_id=? ORDER BY r.score DESC, r.device_id",
        (scan,)).fetchall()
    print(f"ThreatMesh Custom Risk Score - scan #{scan:03d}  "
          f"(heuristic review priority, not CVSS)")
    print(f"{'ID':<4}{'IP':<16}{'Role':<14}{'Score':<7}Level")
    for r in rows:
        print(f"{r['device_id']:<4}{(r['last_ip'] or '-'):<16}{(r['role'] or '-'):<14}"
              f"{r['score']:<7}{r['level']}")
        for fct in json.loads(r["factors"] or "[]"):
            if fct["points"]:
                print(f"      +{fct['points']:<3}{fct['rule']:<28}{fct['detail']:<16}{fct['expectation']}")
    print("Score alone does not indicate a vulnerability or a compromise.")


def cmd_set_role(conn, args):
    roles = load_kb().roles
    if args.role != "none" and args.role not in roles:
        sys.exit(f"[!] Invalid role. Options: none, {', '.join(sorted(roles))}")
    q = args.query.upper() if ":" in args.query else args.query
    d = conn.execute("SELECT device_id FROM devices WHERE last_ip=? OR mac=?",
                     (args.query, q)).fetchone()
    if d is None:
        sys.exit("[!] Device not found.")
    conn.execute("UPDATE devices SET role=? WHERE device_id=?",
                 (None if args.role == "none" else args.role, d["device_id"]))
    conn.commit()
    print(f"[+] Role set to: {args.role}  (for existing scans: analyze --scan N --force)")


def main():
    ap = argparse.ArgumentParser(prog="threatmesh")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)

    p = sub.add_parser("ingest")
    p.add_argument("path", nargs="?", default=str(ROOT / "data" / "incoming"))
    p.add_argument("--no-analyze", action="store_true",
                   help="Ingest only; run analysis later with 'analyze'")
    p.set_defaults(fn=cmd_ingest)

    sub.add_parser("scans").set_defaults(fn=cmd_scans)
    sub.add_parser("devices").set_defaults(fn=cmd_devices)

    p = sub.add_parser("show")
    p.add_argument("query", help="IP or MAC")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("analyze", help="Analyze pending scans (also upgrades V1 DB)")
    p.add_argument("--scan", type=int)
    p.add_argument("--force", action="store_true", help="Delete and regenerate events")
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("events")
    p.add_argument("--scan", type=int)
    p.set_defaults(fn=cmd_events)

    p = sub.add_parser("explain", help="Show the 7-field explanation for an event")
    p.add_argument("event_id", type=int)
    p.set_defaults(fn=cmd_explain)

    p = sub.add_parser("risk")
    p.add_argument("--scan", type=int)
    p.set_defaults(fn=cmd_risk)

    p = sub.add_parser("set-role", help="Assign a device role (none = clear)")
    p.add_argument("query", help="IP or MAC")
    p.add_argument("role")
    p.set_defaults(fn=cmd_set_role)

    args = ap.parse_args()
    conn = connect()
    try:
        init_db(conn)  # Auto-upgrades V1 databases (idempotent)
        args.fn(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    main()