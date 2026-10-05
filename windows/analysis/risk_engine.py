"""ThreatMesh Custom Risk Score. CVSS DEGILDIR; heuristic inceleme onceligidir.

Skor = durum puanlari (acik servisler) + degisiklik puanlari (bu scan'in diff event'leri),
0-100 arasina kirpilir. Kurallar config/rules.yaml'dan gelir. Deterministiktir.
"""
from dataclasses import dataclass, field
from functools import lru_cache

import yaml

from ..database.db import ROOT
from .diff_engine import Change

RULES_PATH = ROOT / "config" / "rules.yaml"
STATE_TYPES = ("EXPOSED_SERVICE", "UNKNOWN_SERVICE", "MULTIPLE_REMOTE_ACCESS")


@lru_cache(maxsize=4)
def _load_rules(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_rules(path=RULES_PATH):
    return _load_rules(str(path))


@dataclass
class Factor:
    rule: str
    points: int
    detail: str = ""
    expectation: str = "UNKNOWN"
    multiplier: float = 1.0

    def to_dict(self):
        return {"rule": self.rule, "points": self.points, "detail": self.detail,
                "expectation": self.expectation, "multiplier": self.multiplier}


@dataclass
class RiskScore:
    score: int
    level: str
    factors: list = field(default_factory=list)


@dataclass
class ServiceAssessment:
    service_id: str
    port: int
    protocol: str
    expectation: str
    points: int
    rule: str
    category: str
    multiplier: float


def scale(base, multiplier):
    """Yukari yuvarlama (0.5 -> 1), banker's rounding kullanilmaz."""
    return int(base * multiplier + 0.5)


def level_for(score, rules):
    for name, low in sorted(rules["levels"].items(), key=lambda kv: kv[1], reverse=True):
        if score >= low:
            return name
    return "LOW"


def severity_from_points(points):
    if points <= 0:
        return "INFO"
    if points <= 10:
        return "LOW"
    if points <= 20:
        return "MEDIUM"
    return "HIGH"


def event_points(event_type, expectation, rules):
    base = rules["event_points"].get(event_type, 0)
    return scale(base, rules["context_multipliers"][expectation]) if base else 0


def assess_services(services, role, kb, rules):
    """Puani > 0 olan servis degerlendirmeleri."""
    out = []
    for s in services:
        sid = s.service_id
        exp = kb.expectation(role, sid)
        mult = rules["context_multipliers"][exp]
        cat = kb.category(sid)
        if sid == "unknown":
            base, rule = rules["unknown_service_points"], "unknown_service"
        else:
            base, rule = rules["service_points"].get(sid, 0), f"service:{sid}"
        if base > 0:
            pts = scale(base, mult)
        elif exp == "UNEXPECTED" and cat in rules["unexpected_bonus_categories"]:
            pts, rule = rules["unexpected_bonus_points"], f"unexpected:{sid}"
        else:
            pts = 0
        if pts > 0:
            out.append(ServiceAssessment(sid, s.port, s.protocol, exp, pts, rule, cat, mult))
    return out


def remote_access_ids(services, kb):
    return sorted({s.service_id for s in services if kb.category(s.service_id) == "REMOTE_ACCESS"})


def state_findings(device_id, ip, services, role, kb, rules):
    """Mevcut durumdan finding'ler (EXPOSED_SERVICE, UNKNOWN_SERVICE, MULTIPLE_REMOTE_ACCESS)."""
    out = []
    for a in assess_services(services, role, kb, rules):
        if a.rule == "unknown_service":
            etype = "UNKNOWN_SERVICE"
            key = f"unknown:{a.port}/{a.protocol}:{a.expectation}"
        else:
            etype = "EXPOSED_SERVICE"
            key = f"exposed:{a.service_id}:{a.port}/{a.protocol}:{a.expectation}"
        out.append(Change(etype, device_id,
                          {"ip": ip, "port": a.port, "protocol": a.protocol,
                           "service": a.service_id, "category": a.category},
                          service_id=a.service_id, finding_key=key,
                          expectation=a.expectation, points=a.points))
    remote = remote_access_ids(services, kb)
    if len(remote) >= 2:
        out.append(Change("MULTIPLE_REMOTE_ACCESS", device_id,
                          {"ip": ip, "services": ", ".join(kb.display(r) for r in remote)},
                          finding_key="multi_remote",
                          points=rules["multiple_remote_access_points"]))
    return out


def compute_risk(services, role, changes, kb, rules, has_service_data=True):
    """services: list[ServiceObs]. changes: [(event_type, points, expectation, detail)]."""
    factors = []
    if has_service_data:
        for a in assess_services(services, role, kb, rules):
            factors.append(Factor(a.rule, a.points, f"{a.port}/{a.protocol}",
                                  a.expectation, a.multiplier))
        remote = remote_access_ids(services, kb)
        if len(remote) >= 2:
            factors.append(Factor("multiple_remote_access",
                                  rules["multiple_remote_access_points"], ", ".join(remote)))
    else:
        factors.append(Factor("no_service_data", 0,
                              "No service data in this scan; score reflects changes only."))
    for etype, pts, expectation, detail in changes:
        if pts > 0:
            factors.append(Factor(f"change:{etype}", pts, detail, expectation,
                                  rules["context_multipliers"][expectation]))
    total = min(rules["score_cap"], sum(f.points for f in factors))
    return RiskScore(total, level_for(total, rules), factors)
