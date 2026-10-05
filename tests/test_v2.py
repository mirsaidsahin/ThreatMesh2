"""ThreatMesh V2 testleri.  Proje kokunden:  python -m unittest discover -s tests -t . -v"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from windows.analysis.diff_engine import Change, ServiceObs
from windows.analysis.finding_engine import build_finding
from windows.analysis.knowledge import load_kb
from windows.analysis.pipeline import analyze_pending, analyze_scan
from windows.analysis.risk_engine import compute_risk, event_points, level_for, load_rules
from windows.database.db import connect, init_db
from windows.ingest import ingest_scan

MAC_A, MAC_B = "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"


def nmap_xml(hosts, start, args="nmap -sV test"):
    """hosts: [(ip, mac, vendor, [(port, service, product, version)])]"""
    parts = []
    for ip, mac, vendor, ports in hosts:
        addr = f'<address addr="{ip}" addrtype="ipv4"/>'
        if mac:
            addr += f'<address addr="{mac}" addrtype="mac" vendor="{vendor}"/>'
        pp = "".join(
            f'<port protocol="tcp" portid="{n}"><state state="open"/>'
            f'<service name="{s}" product="{pr}" version="{v}"/></port>' for n, s, pr, v in ports)
        parts.append(f'<host><status state="up"/>{addr}<hostnames/><ports>{pp}</ports></host>')
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="{args}" start="{start}">'
            f'{"".join(parts)}<runstats><finished elapsed="1.0"/></runstats></nmaprun>')


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        patcher = mock.patch("windows.ingest.RAW_DIR", self.dir / "raw")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.conn = connect(self.dir / "t.db")
        self.addCleanup(self.conn.close)
        init_db(self.conn)
        self.n = 0

    def scan(self, hosts, args="nmap -sV test", analyze=True):
        self.n += 1
        f = self.dir / f"scan{self.n}.xml"
        f.write_text(nmap_xml(hosts, 1760000000 + self.n * 3600, args), encoding="utf-8")
        return ingest_scan(self.conn, f, analyze=analyze)

    def events(self, scan_id, etype=None):
        q, p = "SELECT * FROM events WHERE scan_id=?", [scan_id]
        if etype:
            q, p = q + " AND event_type=?", p + [etype]
        return self.conn.execute(q + " ORDER BY event_id", p).fetchall()

    def risk(self, scan_id, mac):
        return self.conn.execute(
            "SELECT r.* FROM risk_scores r JOIN devices d USING(device_id) "
            "WHERE r.scan_id=? AND d.mac=?", (scan_id, mac)).fetchone()


class DiffEventTests(Base):
    def test_baseline_scan_has_no_change_events(self):
        s1 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1.2")])])
        types = {e["event_type"] for e in self.events(s1)}
        self.assertNotIn("NEW_DEVICE", types)
        self.assertNotIn("NEW_PORT", types)

    def test_ip_changed(self):
        self.scan([("10.0.0.10", MAC_A, "PC", [])])
        s2 = self.scan([("10.0.0.55", MAC_A, "PC", [])])
        ev = self.events(s2, "IP_CHANGED")
        self.assertEqual(len(ev), 1)
        evidence = json.loads(ev[0]["evidence"])
        self.assertEqual(evidence["previous_ip"], "10.0.0.10")
        self.assertEqual(evidence["current_ip"], "10.0.0.55")
        self.assertEqual(self.events(s2, "NEW_DEVICE"), [])   # ayni kimlik, yeni cihaz degil
        self.assertEqual(ev[0]["description"], "Same device identity observed with a different IP address.")

    def test_new_port_without_new_service(self):
        self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1")])])
        s2 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1"), (8080, "http", "nginx", "1")])])
        ports = self.events(s2, "NEW_PORT")
        self.assertEqual([json.loads(e["evidence"])["port"] for e in ports], [8080])
        self.assertEqual(self.events(s2, "NEW_SERVICE"), [])  # http zaten vardi

    def test_new_service_and_new_port(self):
        self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1")])])
        s2 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1"), (22, "ssh", "OpenSSH", "9")])])
        self.assertEqual(len(self.events(s2, "NEW_PORT")), 1)
        ns = self.events(s2, "NEW_SERVICE")
        self.assertEqual(len(ns), 1)
        self.assertEqual(json.loads(ns[0]["evidence"])["service"], "ssh")

    def test_closed_port_service_removed_and_version_changed(self):
        self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1.2"), (22, "ssh", "OpenSSH", "8")])])
        s2 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1.4")])])
        self.assertEqual(len(self.events(s2, "CLOSED_PORT")), 1)
        self.assertEqual(len(self.events(s2, "SERVICE_REMOVED")), 1)
        vc = self.events(s2, "SERVICE_VERSION_CHANGED")
        self.assertEqual(len(vc), 1)
        self.assertEqual(json.loads(vc[0]["evidence"])["current"], "nginx 1.4")

    def test_new_device_and_device_offline(self):
        self.scan([("10.0.0.1", MAC_A, "R", []), ("10.0.0.2", MAC_B, "PC", [])])
        s2 = self.scan([("10.0.0.1", MAC_A, "R", []), ("10.0.0.3", "AA:BB:CC:00:00:03", "Phone", [])])
        self.assertEqual(len(self.events(s2, "NEW_DEVICE")), 1)
        off = self.events(s2, "DEVICE_OFFLINE")
        self.assertEqual(len(off), 1)
        self.assertEqual(json.loads(off[0]["evidence"])["mac"], MAC_B)

    def test_discovery_scan_does_not_create_false_port_events(self):
        self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1")])])
        s2 = self.scan([("10.0.0.1", MAC_A, "R", [])], args="nmap -sn 10.0.0.0/24")
        types = {e["event_type"] for e in self.events(s2)}
        self.assertNotIn("CLOSED_PORT", types)
        self.assertNotIn("SERVICE_REMOVED", types)
        # sonraki servis scan'i discovery'yi atlayip son servis scan'ine gore karsilastirir
        s3 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1")])])
        self.assertEqual(self.events(s3, "NEW_PORT"), [])


class RiskScoreTests(Base):
    def setUp(self):
        super().setUp()
        self.kb, self.rules = load_kb(), load_rules()

    def test_score_calculation_additive_and_levels(self):
        svcs = [ServiceObs(23, "tcp", "telnet"), ServiceObs(22, "tcp", "ssh")]
        changes = [("NEW_PORT", 10, "UNKNOWN", "23"), ("NEW_PORT", 10, "UNKNOWN", "22"),
                   ("NEW_SERVICE", 10, "UNKNOWN", "telnet"), ("NEW_SERVICE", 10, "UNKNOWN", "ssh")]
        r = compute_risk(svcs, None, changes, self.kb, self.rules)
        # telnet 20 + coklu uzaktan erisim 10 + degisiklikler 40
        self.assertEqual(r.score, 70)
        self.assertEqual(r.level, "HIGH")

    def test_score_is_capped_at_100(self):
        r = compute_risk([ServiceObs(23, "tcp", "telnet")], None,
                         [("NEW_PORT", 60, "UNKNOWN", ""), ("NEW_SERVICE", 60, "UNKNOWN", "")],
                         self.kb, self.rules)
        self.assertEqual(r.score, 100)
        self.assertEqual(r.level, "CRITICAL")

    def test_level_boundaries(self):
        lv = lambda s: level_for(s, self.rules)
        self.assertEqual([lv(0), lv(25), lv(26), lv(50), lv(51), lv(75), lv(76), lv(100)],
                         ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"])

    def test_context_changes_points_not_maliciousness(self):
        telnet = [ServiceObs(23, "tcp", "telnet")]
        score = lambda role: compute_risk(telnet, role, [], self.kb, self.rules).score
        self.assertEqual(score(None), 20)        # UNKNOWN: rol yok
        self.assertEqual(score("router"), 30)    # UNEXPECTED: router'da telnet beklenmez
        smb = [ServiceObs(445, "tcp", "smb")]
        self.assertEqual(compute_risk(smb, "workstation", [], self.kb, self.rules).score, 5)  # EXPECTED
        self.assertEqual(self.kb.expectation("workstation", "smb"), "EXPECTED")

    def test_unknown_service_and_unexpected_ssh_bonus(self):
        r = compute_risk([ServiceObs(9999, "tcp", "unknown")], None, [], self.kb, self.rules)
        self.assertEqual(r.score, 15)
        r = compute_risk([ServiceObs(22, "tcp", "ssh")], "camera", [], self.kb, self.rules)
        self.assertEqual(r.score, 10)            # camera'da ssh beklenmez
        r = compute_risk([ServiceObs(22, "tcp", "ssh")], "router", [], self.kb, self.rules)
        self.assertEqual(r.score, 0)             # router'da ssh beklenir
        self.assertEqual(event_points("NEW_PORT", "EXPECTED", self.rules), 3)

    def test_pipeline_writes_risk_score_for_new_telnet(self):
        self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1")])])
        s2 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1"), (23, "telnet", "", "")])])
        r = self.risk(s2, MAC_A)
        self.assertEqual((r["score"], r["level"]), (40, "MEDIUM"))   # 20 + 10 + 10
        rules = {f["rule"] for f in json.loads(r["factors"])}
        self.assertTrue({"service:telnet", "change:NEW_PORT", "change:NEW_SERVICE"} <= rules)

    def test_pipeline_role_makes_telnet_unexpected(self):
        self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1")])])
        self.conn.execute("UPDATE devices SET role='router' WHERE mac=?", (MAC_A,))
        self.conn.commit()
        s2 = self.scan([("10.0.0.1", MAC_A, "R", [(80, "http", "nginx", "1"), (23, "telnet", "", "")])])
        self.assertEqual(self.risk(s2, MAC_A)["score"], 60)          # 30 + 15 + 15
        exposed = self.events(s2, "EXPOSED_SERVICE")[0]
        self.assertEqual(exposed["expectation"], "UNEXPECTED")


class DuplicateScanTests(Base):
    def test_same_file_twice_creates_nothing_new(self):
        f = self.dir / "dup.xml"
        f.write_text(nmap_xml([("10.0.0.1", MAC_A, "R", [(23, "telnet", "", "")])], 1760000000), encoding="utf-8")
        first = ingest_scan(self.conn, f)
        counts = lambda: tuple(self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                               for t in ("scans", "events", "risk_scores", "scan_devices"))
        before = counts()
        self.assertIsNotNone(first)
        self.assertIsNone(ingest_scan(self.conn, f))
        self.assertEqual(counts(), before)

    def test_reanalysis_is_idempotent(self):
        s1 = self.scan([("10.0.0.1", MAC_A, "R", [(23, "telnet", "", "")])])
        n = len(self.events(s1))
        self.assertIsNone(analyze_scan(self.conn, s1))               # zaten analiz edildi
        analyze_scan(self.conn, s1, force=True)                      # force: sil + yeniden uret
        self.assertEqual(len(self.events(s1)), n)

    def test_backfill_for_v1_style_ingest(self):
        self.scan([("10.0.0.10", MAC_A, "PC", [])], analyze=False)
        s2 = self.scan([("10.0.0.55", MAC_A, "PC", [])], analyze=False)
        self.assertEqual(self.events(s2), [])
        analyze_pending(self.conn)
        self.assertEqual(len(self.events(s2, "IP_CHANGED")), 1)
        analyze_pending(self.conn)
        self.assertEqual(len(self.events(s2, "IP_CHANGED")), 1)


class KnowledgeFindingTests(unittest.TestCase):
    FORBIDDEN = ("attack detected", "vulnerability confirmed", "compromised device", "is malicious")

    def setUp(self):
        self.kb = load_kb()

    def telnet_change(self, expectation="UNKNOWN"):
        return Change("EXPOSED_SERVICE", 1, {"ip": "10.0.0.1", "port": 23, "protocol": "tcp",
                                             "service": "telnet", "category": "REMOTE_ACCESS"},
                      service_id="telnet", finding_key="exposed:telnet:23/tcp", expectation=expectation, points=20)

    def test_telnet_finding_has_all_seven_fields(self):
        f = build_finding(self.kb, self.telnet_change(), scan_id=2)
        for field in ("what_happened", "why_it_matters", "how_detected", "recommended_state"):
            self.assertTrue(getattr(f, field).strip(), field)
        for field in ("investigate", "do_not", "mitigation"):
            self.assertTrue(len(getattr(f, field)) >= 1, field)
        self.assertIn("unencrypted", f.why_it_matters)
        self.assertIn("10.0.0.1", f.what_happened)
        self.assertIn("23/tcp", f.what_happened)

    def test_finding_never_claims_attack_or_confirmed_vulnerability(self):
        for ex in ("UNKNOWN", "UNEXPECTED", "EXPECTED"):
            text = json.dumps(build_finding(self.kb, self.telnet_change(ex), 2, role="router").to_dict()).lower()
            for bad in self.FORBIDDEN:
                self.assertNotIn(bad, text)
        f = build_finding(self.kb, self.telnet_change(), 2)
        self.assertIn("does not confirm", f.disclaimer)

    def test_context_sentence_reflects_expectation(self):
        unk = build_finding(self.kb, self.telnet_change("UNKNOWN"), 2)
        une = build_finding(self.kb, self.telnet_change("UNEXPECTED"), 2, role="router")
        self.assertIn("No device role", unk.context)
        self.assertIn("does not normally include", une.context)
        self.assertIn("router", une.context)

    def test_every_event_type_renders_without_unresolved_placeholders(self):
        data = {"ip": "10.0.0.1", "mac": "AA", "vendor": "V", "port": 80, "protocol": "tcp",
                "service": "http", "ports": "80/tcp", "previous": "a 1", "current": "a 2",
                "previous_ip": "10.0.0.2", "current_ip": "10.0.0.1", "services": "SSH, Telnet",
                "category": "WEB"}
        for etype in self.kb.events:
            c = Change(etype, 1, data, service_id="http", prev_scan=1)
            d = build_finding(self.kb, c, 2).to_dict()
            strings = [v for v in d.values() if isinstance(v, str)]
            strings += [s for v in d.values() if isinstance(v, list) for s in v]
            for s in strings:
                self.assertNotIn("{", s, etype)
                self.assertNotIn("}", s, etype)

    def test_service_name_resolution(self):
        r = self.kb.resolve_service
        self.assertEqual((r("microsoft-ds"), r("ms-wbt-server"), r("domain")), ("smb", "rdp", "dns"))
        self.assertEqual((r(None), r("unknown"), r("someweird")), ("unknown", "unknown", "someweird"))

    def test_unknown_service_without_kb_entry_uses_generic_text(self):
        c = Change("EXPOSED_SERVICE", 1, {"ip": "10.0.0.1", "port": 1234, "protocol": "tcp",
                                          "service": "weird", "category": "OTHER"}, service_id="weird")
        f = build_finding(self.kb, c, 2)
        self.assertIn("weird", f.why_it_matters)


class MigrationTests(unittest.TestCase):
    def test_v1_database_is_upgraded_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "v1.db"
            raw = sqlite3.connect(db)
            raw.executescript("""
                CREATE TABLE scans (scan_id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL,
                    duration REAL, target_scope TEXT, mode TEXT, sensor_id TEXT, profile TEXT, raw_file TEXT,
                    file_hash TEXT UNIQUE NOT NULL, nmap_args TEXT, device_count INTEGER DEFAULT 0,
                    service_count INTEGER DEFAULT 0, port_count INTEGER DEFAULT 0);
                CREATE TABLE devices (device_id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE,
                    identity TEXT NOT NULL, vendor TEXT, hostname TEXT, last_ip TEXT,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
                CREATE TABLE events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                    scan_id INTEGER, device_id INTEGER, event_type TEXT NOT NULL, severity TEXT NOT NULL,
                    description TEXT, evidence TEXT, status TEXT NOT NULL DEFAULT 'NEW');
                INSERT INTO scans(started_at,file_hash,nmap_args) VALUES ('t','h1','nmap -sn 10.0.0.0/24');
                INSERT INTO scans(started_at,file_hash,nmap_args) VALUES ('t','h2','nmap -sV 10.0.0.0/24');
            """)
            raw.commit(); raw.close()
            conn = connect(db)
            init_db(conn); init_db(conn)    # idempotent
            cols = lambda t: {r[1] for r in conn.execute(f"PRAGMA table_info({t})")}
            self.assertIn("role", cols("devices"))
            self.assertTrue({"finding_json", "expectation", "risk_points", "finding_key"} <= cols("events"))
            self.assertTrue({"has_service_data", "analyzed_at"} <= cols("scans"))
            flags = [r[0] for r in conn.execute("SELECT has_service_data FROM scans ORDER BY scan_id")]
            self.assertEqual(flags, [0, 1])
            conn.close()


if __name__ == "__main__":
    unittest.main()
