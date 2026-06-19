"""
System telemetry collector.
Produces a SystemSnapshot each cycle using psutil.
All per-process access errors are swallowed — a process that exits
mid-collection must not crash the monitoring loop.
"""

from __future__ import annotations

import logging
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil

from utils.models import NetworkConnection, ProcessInfo, SystemSnapshot

log = logging.getLogger(__name__)

# Module-level PID→name cache to reduce repeated syscalls within a cycle.
# Cleared automatically when an entry goes stale (NoSuchProcess).
_PROC_NAME_CACHE: dict[int, str] = {}

# Lines to read from the tail of auth.log per cycle.
# 200 lines ≈ a few KB — intentionally small.
_AUTH_LOG_TAIL = 200


class SystemMonitor:
    """Collects raw system telemetry; no judgement, no side effects."""

    def __init__(self, monitoring_config: dict) -> None:
        self._platform = platform.system()
        # Non-blocking CPU interval — short enough not to add latency to the cycle
        self._cpu_poll_interval = 0.5

    def collect(self) -> SystemSnapshot:
        return SystemSnapshot(
            timestamp=datetime.now(tz=timezone.utc),
            cpu_percent=self._cpu(),
            ram_percent=self._ram(),
            processes=self._processes(),
            connections=self._connections(),
            failed_logins=self._failed_logins(),
        )

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    def _cpu(self) -> float:
        return psutil.cpu_percent(interval=self._cpu_poll_interval)

    def _ram(self) -> float:
        return psutil.virtual_memory().percent

    def _processes(self) -> list[ProcessInfo]:
        attrs = ["pid", "name", "cpu_percent", "memory_percent", "username"]
        procs: list[ProcessInfo] = []

        for proc in psutil.process_iter(attrs, ad_value=None):
            try:
                info = proc.info
                if info["pid"] is None or info["name"] is None:
                    continue
                procs.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info["name"],
                        cpu_percent=info["cpu_percent"] or 0.0,
                        memory_percent=info["memory_percent"] or 0.0,
                        username=info["username"] or "unknown",
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return procs

    def _connections(self) -> list[NetworkConnection]:
        conns: list[NetworkConnection] = []
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.debug("Insufficient privileges to list all network connections.")
            return conns

        for c in raw:
            if c.status != psutil.CONN_ESTABLISHED:
                continue
            if not c.raddr:
                continue
            conns.append(
                NetworkConnection(
                    local_addr=f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    remote_addr=c.raddr.ip,
                    remote_port=c.raddr.port,
                    status=c.status,
                    pid=c.pid or 0,
                    process_name=self._resolve_name(c.pid),
                )
            )

        return conns

    def _failed_logins(self) -> int:
        """
        Parse recent lines of /var/log/auth.log (Linux only).
        Returns a count of failure patterns in the last _AUTH_LOG_TAIL lines.
        On Windows/macOS or permission errors, returns 0.
        """
        if self._platform != "Linux":
            return 0

        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            return 0

        try:
            lines = _tail_lines(auth_log, _AUTH_LOG_TAIL)
        except PermissionError:
            log.debug("Cannot read %s — insufficient permissions.", auth_log)
            return 0

        pattern = re.compile(r"Failed password|authentication failure", re.IGNORECASE)
        return sum(1 for line in lines if pattern.search(line))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_name(self, pid: Optional[int]) -> str:
        if pid is None:
            return "unknown"
        cached = _PROC_NAME_CACHE.get(pid)
        if cached:
            return cached
        try:
            name = psutil.Process(pid).name()
            _PROC_NAME_CACHE[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            _PROC_NAME_CACHE.pop(pid, None)
            return "unknown"


def _tail_lines(path: Path, n: int) -> list[str]:
    """Read the last n lines of a file without loading the whole file into memory."""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        file_size = fh.tell()
        # Estimate block: average 120 bytes per log line
        block_size = min(file_size, n * 120)
        fh.seek(max(0, file_size - block_size))
        raw = fh.read()
    return raw.decode("utf-8", errors="replace").splitlines()[-n:]
