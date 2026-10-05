"""Statik bilgi bankasi (JSON): servisler, roller, finding sablonlari. Harici AI yok."""
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..database.db import ROOT

CONFIG_DIR = ROOT / "config"


@dataclass
class KnowledgeBase:
    services: dict
    roles: dict
    events: dict
    context: dict
    generic: dict
    disclaimer: str
    name_index: dict  # nmap servis adi -> kanonik servis id

    def resolve_service(self, nmap_name):
        """Nmap servis adini kanonik id'ye cevirir. Ad yoksa/'unknown' ise 'unknown'."""
        key = (nmap_name or "").strip().lower()
        if key in ("", "unknown"):
            return "unknown"
        return self.name_index.get(key, key)

    def display(self, service_id):
        if service_id == "unknown":
            return "Unknown service"
        return self.services.get(service_id, {}).get("display", service_id)

    def category(self, service_id):
        if service_id == "unknown":
            return "UNKNOWN"
        return self.services.get(service_id, {}).get("category", "OTHER")

    def expectation(self, role, service_id):
        """EXPECTED / UNEXPECTED / UNKNOWN. Rol yoksa veya servis taninmiyorsa UNKNOWN."""
        if not role or role not in self.roles or service_id in (None, "unknown"):
            return "UNKNOWN"
        expected = self.roles[role].get("expected_services", [])
        return "EXPECTED" if service_id in expected else "UNEXPECTED"


@lru_cache(maxsize=4)
def _load(config_dir):
    kdir = Path(config_dir) / "knowledge"
    read = lambda name: json.loads((kdir / name).read_text(encoding="utf-8"))
    services = read("services.json")["services"]
    roles = read("roles.json")["roles"]
    findings = read("findings.json")
    index = {}
    for sid, info in services.items():
        for n in info.get("nmap_names", []):
            index[n.lower()] = sid
        index.setdefault(sid, sid)
    return KnowledgeBase(
        services=services, roles=roles, events=findings["events"],
        context=findings["context"], generic=findings["generic_service"],
        disclaimer=findings["disclaimer"], name_index=index,
    )


def load_kb(config_dir=CONFIG_DIR):
    return _load(str(config_dir))