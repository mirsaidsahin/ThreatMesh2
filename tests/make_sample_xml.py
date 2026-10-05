"""Test icin sahte Nmap XML uretir (Nmap gerekmez)."""
from pathlib import Path

TPL = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV test" start="{start}">
{hosts}
<runstats><finished elapsed="12.5"/></runstats></nmaprun>"""

def host(ip, mac=None, vendor=None, ports=()):
    a = f'<address addr="{ip}" addrtype="ipv4"/>'
    if mac:
        a += f'<address addr="{mac}" addrtype="mac" vendor="{vendor}"/>'
    p = "".join(f'<port protocol="tcp" portid="{n}"><state state="open"/>'
                f'<service name="{s}" product="{pr}" version="{v}"/></port>'
                for n, s, pr, v in ports)
    return f'<host><status state="up"/>{a}<hostnames/><ports>{p}</ports></host>'

out = Path(__file__).resolve().parents[1] / "data" / "incoming"
out.mkdir(parents=True, exist_ok=True)
(out / "sample_1.xml").write_text(TPL.format(start=1760000000, hosts=
    host("192.168.1.1", "AA:BB:CC:00:00:01", "Example Router", [(80, "http", "nginx", "1.2")]) +
    host("192.168.1.10", "AA:BB:CC:00:00:02", "Example PC", [(22, "ssh", "OpenSSH", "9.0")])))
(out / "sample_2.xml").write_text(TPL.format(start=1760003600, hosts=
    host("192.168.1.1", "AA:BB:CC:00:00:01", "Example Router", [(80, "http", "nginx", "1.2")]) +
    host("192.168.1.55", "AA:BB:CC:00:00:02", "Example PC", [(22, "ssh", "OpenSSH", "9.0"), (23, "telnet", "", "")]) +
    host("192.168.1.77", "AA:BB:CC:00:00:03", "New Phone")))
print("ok")
