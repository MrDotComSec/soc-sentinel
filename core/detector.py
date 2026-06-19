"""
Anomaly detector — pure logic, zero I/O.
Evaluates a SystemSnapshot against the active Rules and emits Alert objects.
"""

from __future__ import annotations

import logging

from core.rules import Rules
from utils.models import Alert, AlertType, SystemSnapshot

log = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Stateless evaluator: same snapshot + rules always produces the same alerts.
    Extend by adding a new _check_* method and calling it from evaluate().
    """

    def __init__(self, rules: Rules) -> None:
        self._rules = rules

    def evaluate(self, snapshot: SystemSnapshot) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._check_cpu(snapshot))
        alerts.extend(self._check_ram(snapshot))
        alerts.extend(self._check_processes(snapshot))
        alerts.extend(self._check_connections(snapshot))
        alerts.extend(self._check_failed_logins(snapshot))
        return alerts

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_cpu(self, s: SystemSnapshot) -> list[Alert]:
        if s.cpu_percent < self._rules.cpu_threshold:
            return []
        return [Alert.create(
            alert_type=AlertType.CPU_HIGH,
            title=f"High CPU Usage: {s.cpu_percent:.1f}%",
            description=(
                f"System CPU is at {s.cpu_percent:.1f}%, "
                f"above the configured threshold of {self._rules.cpu_threshold}%."
            ),
            raw_data={
                "cpu_percent": s.cpu_percent,
                "threshold": self._rules.cpu_threshold,
                "timestamp": s.timestamp.isoformat(),
            },
        )]

    def _check_ram(self, s: SystemSnapshot) -> list[Alert]:
        if s.ram_percent < self._rules.ram_threshold:
            return []
        return [Alert.create(
            alert_type=AlertType.RAM_HIGH,
            title=f"High RAM Usage: {s.ram_percent:.1f}%",
            description=(
                f"System RAM is at {s.ram_percent:.1f}%, "
                f"above the configured threshold of {self._rules.ram_threshold}%."
            ),
            raw_data={
                "ram_percent": s.ram_percent,
                "threshold": self._rules.ram_threshold,
                "timestamp": s.timestamp.isoformat(),
            },
        )]

    def _check_processes(self, s: SystemSnapshot) -> list[Alert]:
        alerts: list[Alert] = []
        # Track emitted process names within this cycle to avoid duplicates
        # (same process may appear multiple times under different PIDs rarely)
        seen: set[str] = set()

        for proc in s.processes:
            name_lower = proc.name.lower()
            if name_lower in self._rules.process_whitelist:
                continue
            if name_lower in self._rules.suspicious_processes and name_lower not in seen:
                seen.add(name_lower)
                alerts.append(Alert.create(
                    alert_type=AlertType.SUSPICIOUS_PROCESS,
                    title=f"Suspicious Process Detected: {proc.name}",
                    description=(
                        f"Process '{proc.name}' (PID {proc.pid}, user: {proc.username}) "
                        f"matches the suspicious process list."
                    ),
                    raw_data={
                        "pid": proc.pid,
                        "name": proc.name,
                        "username": proc.username,
                        "cpu_percent": proc.cpu_percent,
                        "memory_percent": proc.memory_percent,
                    },
                ))

        return alerts

    def _check_connections(self, s: SystemSnapshot) -> list[Alert]:
        alerts: list[Alert] = []
        seen: set[tuple[str, int]] = set()

        for conn in s.connections:
            key = (conn.remote_addr, conn.remote_port)
            if key in seen:
                continue

            reason: str | None = None
            if conn.remote_port in self._rules.suspicious_ports:
                reason = f"outbound connection to suspicious port {conn.remote_port}"
            elif conn.remote_addr in self._rules.suspicious_ips:
                reason = f"outbound connection to flagged IP {conn.remote_addr}"

            if reason:
                seen.add(key)
                alerts.append(Alert.create(
                    alert_type=AlertType.SUSPICIOUS_CONNECTION,
                    title=(
                        f"Suspicious Connection: {conn.remote_addr}:{conn.remote_port}"
                    ),
                    description=(
                        f"'{conn.process_name}' (PID {conn.pid}) has an established "
                        f"{reason}."
                    ),
                    raw_data={
                        "pid": conn.pid,
                        "process_name": conn.process_name,
                        "local_addr": conn.local_addr,
                        "remote_addr": conn.remote_addr,
                        "remote_port": conn.remote_port,
                        "status": conn.status,
                    },
                ))

        return alerts

    def _check_failed_logins(self, s: SystemSnapshot) -> list[Alert]:
        if s.failed_logins < self._rules.failed_login_threshold:
            return []
        return [Alert.create(
            alert_type=AlertType.FAILED_LOGINS,
            title=f"Repeated Failed Login Attempts: {s.failed_logins}",
            description=(
                f"Detected {s.failed_logins} failed authentication attempts in the "
                f"recent log window (threshold: {self._rules.failed_login_threshold})."
            ),
            raw_data={
                "failed_logins": s.failed_logins,
                "threshold": self._rules.failed_login_threshold,
                "timestamp": s.timestamp.isoformat(),
            },
        )]
