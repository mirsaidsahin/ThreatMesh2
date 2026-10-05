"""Nmap XML -> yapisal veri. Ham terminal ciktisi parse edilmez."""
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ParsedService:
    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class ParsedHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    status: str = "up"
    services: list[ParsedService] = field(default_factory=list)


@dataclass
class ParsedScan:
    started_at: str
    duration: float
    args: str
    hosts: list[ParsedHost]


def parse_nmap_xml(path) -> ParsedScan:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        raise ValueError(f"Gecersiz XML: {path} ({e})") from e
    if root.tag != "nmaprun":
        raise ValueError(f"Nmap XML degil: {path}")

    start = int(root.get("start", "0"))
    started_at = datetime.fromtimestamp(start, tz=timezone.utc).isoformat(timespec="seconds")
    fin = root.find("runstats/finished")
    duration = float(fin.get("elapsed", "0")) if fin is not None else 0.0

    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        status = st.get("state", "unknown") if st is not None else "unknown"
        if status != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                ip = a.get("addr")
            elif t == "mac":
                mac = (a.get("addr") or "").upper() or None
                vendor = a.get("vendor")
        if ip is None:
            continue
        hn = h.find("hostnames/hostname")
        host = ParsedHost(ip=ip, mac=mac, vendor=vendor,
                          hostname=hn.get("name") if hn is not None else None, status=status)
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue  # V1: sadece acik portlar
            sv = p.find("service")
            host.services.append(ParsedService(
                port=int(p.get("portid")),
                protocol=p.get("protocol", "tcp"),
                state="open",
                name=sv.get("name") if sv is not None else None,
                product=sv.get("product") if sv is not None else None,
                version=sv.get("version") if sv is not None else None,
            ))
        hosts.append(host)

    return ParsedScan(started_at, duration, root.get("args", ""), hosts)