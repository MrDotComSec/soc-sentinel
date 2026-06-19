"""
Immutable rules object built from config at startup.
Shared between SystemMonitor and AnomalyDetector — a single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rules:
    cpu_threshold: float
    ram_threshold: float
    failed_login_threshold: int
    process_whitelist: frozenset[str]
    suspicious_processes: frozenset[str]
    suspicious_ports: frozenset[int]
    suspicious_ips: frozenset[str]

    @classmethod
    def from_config(cls, config: dict) -> "Rules":
        mon = config.get("monitoring", {})
        rules = config.get("rules", {})
        return cls(
            cpu_threshold=float(mon.get("cpu_threshold", 85)),
            ram_threshold=float(mon.get("ram_threshold", 90)),
            failed_login_threshold=int(mon.get("failed_login_threshold", 5)),
            process_whitelist=frozenset(
                p.lower() for p in rules.get("process_whitelist", [])
            ),
            suspicious_processes=frozenset(
                p.lower() for p in rules.get("suspicious_processes", [])
            ),
            suspicious_ports=frozenset(int(p) for p in rules.get("suspicious_ports", [])),
            suspicious_ips=frozenset(rules.get("suspicious_ips", [])),
        )
