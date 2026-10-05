from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RiskScore:
    score: int
    level: str


@dataclass
class Service:
    port: int
    protocol: str
    service_name: str
    state: str


@dataclass
class Device:
    device_id: int
    ip: str
    role: str
    risk: Optional[RiskScore] = None
    services: List[Service] = field(default_factory=list)


@dataclass
class Event:
    event_id: int
    device_id: Optional[int]
    event_type: str
    severity: str
    description: str
    risk_points: int


@dataclass
class Scan:
    scan_id: int
    started_at: str
    device_count: int