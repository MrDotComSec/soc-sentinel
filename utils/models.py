"""
Shared data models used across every layer of SOC Sentinel.
All inter-module data passes through these types — nothing else is coupled.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Severity — ordered enum with comparison support
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        try:
            return cls(value.upper())
        except ValueError:
            return cls.MEDIUM

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return _SEVERITY_RANK[self.value] >= _SEVERITY_RANK[other.value]
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return _SEVERITY_RANK[self.value] > _SEVERITY_RANK[other.value]
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return _SEVERITY_RANK[self.value] <= _SEVERITY_RANK[other.value]
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return _SEVERITY_RANK[self.value] < _SEVERITY_RANK[other.value]
        return NotImplemented


# ---------------------------------------------------------------------------
# Alert type catalogue
# ---------------------------------------------------------------------------
class AlertType(str, Enum):
    CPU_HIGH = "CPU_HIGH"
    RAM_HIGH = "RAM_HIGH"
    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"
    SUSPICIOUS_CONNECTION = "SUSPICIOUS_CONNECTION"
    FAILED_LOGINS = "FAILED_LOGINS"


# Detector-assigned initial severity per alert type (before AI classification)
_ALERT_PRE_SEVERITY: dict[AlertType, Severity] = {
    AlertType.CPU_HIGH: Severity.MEDIUM,
    AlertType.RAM_HIGH: Severity.MEDIUM,
    AlertType.SUSPICIOUS_PROCESS: Severity.HIGH,
    AlertType.SUSPICIOUS_CONNECTION: Severity.HIGH,
    AlertType.FAILED_LOGINS: Severity.MEDIUM,
}


# ---------------------------------------------------------------------------
# Snapshot — raw telemetry collected each cycle
# ---------------------------------------------------------------------------
@dataclass
class NetworkConnection:
    local_addr: str
    remote_addr: str
    remote_port: int
    status: str
    pid: int
    process_name: str


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    username: str


@dataclass
class SystemSnapshot:
    timestamp: datetime
    cpu_percent: float
    ram_percent: float
    processes: list[ProcessInfo]
    connections: list[NetworkConnection]
    failed_logins: int = 0


# ---------------------------------------------------------------------------
# Alert — emitted by the detector, consumed by everything downstream
# ---------------------------------------------------------------------------
@dataclass
class Alert:
    alert_id: str
    alert_type: AlertType
    title: str
    description: str
    raw_data: dict
    pre_severity: Severity
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    @classmethod
    def create(
        cls,
        alert_type: AlertType,
        title: str,
        description: str,
        raw_data: dict,
    ) -> "Alert":
        return cls(
            alert_id=str(uuid.uuid4())[:8].upper(),
            alert_type=alert_type,
            title=title,
            description=description,
            raw_data=raw_data,
            pre_severity=_ALERT_PRE_SEVERITY.get(alert_type, Severity.MEDIUM),
        )

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "pre_severity": self.pre_severity.value,
            "title": self.title,
            "description": self.description,
            "raw_data": self.raw_data,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# AnalysisResult — returned by the AI layer
# ---------------------------------------------------------------------------
@dataclass
class AnalysisResult:
    severity: Severity
    explanation: str
    possible_causes: list[str]
    recommended_action: str
    incident_report: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "explanation": self.explanation,
            "possible_causes": self.possible_causes,
            "recommended_action": self.recommended_action,
            "incident_report": self.incident_report,
        }
