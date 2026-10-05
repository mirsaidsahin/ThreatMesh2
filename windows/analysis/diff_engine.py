"""Diff engine: iki snapshot'i karsilastirir. Saf fonksiyonlar, DB'ye dokunmaz.

Tanimlar:
  NEW_PORT        (port, proto) simdi acik, onceki servis scan'inde acik degildi
  CLOSED_PORT     (port, proto) onceden aciktı, simdi degil
  NEW_SERVICE     servis ADI (kanonik id) cihazda onceden yoktu
  SERVICE_REMOVED servis adi onceden vardi, simdi yok
  SERVICE_VERSION_CHANGED  ayni port + ayni servis, product/version farkli
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceObs:
    device_id: int
    ip: str
    mac: str | None = None
    vendor: str | None = None


@dataclass(frozen=True)
class ServiceObs:
    port: int
    protocol: str
    service_id: str
    product: str | None = None
    version: str | None = None
    name: str | None = None


@dataclass
class Change:
    event_type: str
    device_id: int
    data: dict = field(default_factory=dict)
    service_id: str | None = None
    finding_key: str | None = None
    prev_scan: int | None = None
    expectation: str = "UNKNOWN"
    points: int = 0


def diff_devices(curr, prev, last_known_ip, compare_offline=True):
    """curr/prev: {device_id: DeviceObs}. last_known_ip: {device_id: onceki scan'lerdeki son IP}.

    prev None ise ilk scan'dir (baseline): event uretilmez.
    """
    if prev is None:
        return []
    changes = []
    for did in sorted(curr):
        obs = curr[did]
        if did not in last_known_ip:
            changes.append(Change("NEW_DEVICE", did,
                                  {"ip": obs.ip, "mac": obs.mac, "vendor": obs.vendor}))
        elif last_known_ip[did] != obs.ip:
            changes.append(Change("IP_CHANGED", did,
                                  {"previous_ip": last_known_ip[did], "current_ip": obs.ip,
                                   "mac": obs.mac}))
    if compare_offline:
        for did in sorted(prev):
            if did not in curr:
                o = prev[did]
                changes.append(Change("DEVICE_OFFLINE", did,
                                      {"ip": o.ip, "mac": o.mac, "vendor": o.vendor}))
    return changes


def _ver(s):
    return " ".join(x for x in (s.product, s.version) if x) or "unknown"


def diff_services(device_id, ip, prev, curr):
    """prev/curr: list[ServiceObs] (ayni cihaz, iki servis scan'i)."""
    pk = {(s.port, s.protocol): s for s in prev}
    ck = {(s.port, s.protocol): s for s in curr}
    changes = []

    for key in sorted(ck):
        if key not in pk:
            s = ck[key]
            changes.append(Change("NEW_PORT", device_id,
                                  {"ip": ip, "port": s.port, "protocol": s.protocol,
                                   "service": s.service_id}, service_id=s.service_id))
    for key in sorted(pk):
        if key not in ck:
            s = pk[key]
            changes.append(Change("CLOSED_PORT", device_id,
                                  {"ip": ip, "port": s.port, "protocol": s.protocol,
                                   "service": s.service_id}, service_id=s.service_id))

    prev_ids = {s.service_id for s in prev}
    curr_ids = {s.service_id for s in curr}
    for sid in sorted(curr_ids - prev_ids):
        ports = ", ".join(f"{s.port}/{s.protocol}" for s in sorted(curr, key=lambda x: x.port)
                          if s.service_id == sid)
        changes.append(Change("NEW_SERVICE", device_id,
                              {"ip": ip, "service": sid, "ports": ports}, service_id=sid))
    for sid in sorted(prev_ids - curr_ids):
        ports = ", ".join(f"{s.port}/{s.protocol}" for s in sorted(prev, key=lambda x: x.port)
                          if s.service_id == sid)
        changes.append(Change("SERVICE_REMOVED", device_id,
                              {"ip": ip, "service": sid, "ports": ports}, service_id=sid))

    for key in sorted(set(pk) & set(ck)):
        a, b = pk[key], ck[key]
        if a.service_id == b.service_id and (a.product or "", a.version or "") != (b.product or "", b.version or ""):
            changes.append(Change("SERVICE_VERSION_CHANGED", device_id,
                                  {"ip": ip, "port": b.port, "protocol": b.protocol,
                                   "service": b.service_id, "previous": _ver(a),
                                   "current": _ver(b)}, service_id=b.service_id))
    return changes