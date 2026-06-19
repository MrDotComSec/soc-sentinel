"""
Thread-safe alert logger.
Writes NDJSON (one JSON object per line) so logs remain grep-friendly
and can be streamed into SIEM tools without a parser.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from utils.models import Alert, AnalysisResult

log = logging.getLogger(__name__)


class AlertLogger:
    """Appends structured records to a single log file, serialised via a lock."""

    def __init__(self, config: dict) -> None:
        self._enabled: bool = config.get("log", True)
        self._path = Path(config["log_path"])
        self._lock = threading.Lock()

        if self._enabled:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write_alert(self, alert: Alert) -> None:
        if not self._enabled:
            return
        self._append({"event": "ALERT", **alert.to_dict()})
        # Mirror to console at WARNING level so alerts show up in the terminal
        log.warning("[%s] %s — %s", alert.alert_id, alert.alert_type.value, alert.title)

    def write_analysis(self, alert: Alert, analysis: AnalysisResult) -> None:
        if not self._enabled:
            return
        self._append({
            "event": "AI_ANALYSIS",
            "alert_id": alert.alert_id,
            "logged_at": datetime.now(tz=timezone.utc).isoformat(),
            **analysis.to_dict(),
        })
        log.info(
            "[%s] AI → severity: %s | %s",
            alert.alert_id,
            analysis.severity.value,
            analysis.explanation[:120],
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _append(self, record: dict) -> None:
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        with self._lock:
            try:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError as exc:
                log.error("Failed to write log record: %s", exc)
