"""
Cross-platform desktop notification via plyer.
Falls back gracefully to a coloured console print if:
  - plyer is not installed
  - the display environment is unavailable (headless server)
"""

from __future__ import annotations

import logging
import threading
from typing import Callable

from utils.models import Alert, Severity

log = logging.getLogger(__name__)

# Maps severity to a short visual prefix for the console fallback
_SEVERITY_PREFIX = {
    Severity.LOW: "[ LOW ]",
    Severity.MEDIUM: "[ MED ]",
    Severity.HIGH: "[HIGH ]",
    Severity.CRITICAL: "[CRIT ]",
}


class PopupAlert:
    def __init__(self, enabled: bool, threshold: str = "MEDIUM") -> None:
        self._enabled = enabled
        self._threshold = Severity.from_string(threshold)
        self._notify: Callable[[Alert], None] = self._resolve()

    def show(self, alert: Alert) -> None:
        if not self._enabled:
            return
        if alert.pre_severity < self._threshold:
            return
        threading.Thread(
            target=self._notify,
            args=(alert,),
            daemon=True,
            name="sentinel-popup",
        ).start()

    # ------------------------------------------------------------------

    def _resolve(self) -> Callable[[Alert], None]:
        try:
            from plyer import notification  # noqa: PLC0415

            def _plyer(alert: Alert) -> None:
                try:
                    notification.notify(
                        title=f"SOC Sentinel — {alert.alert_type.value}",
                        message=alert.title,
                        app_name="SOC Sentinel",
                        timeout=8,
                    )
                except Exception as exc:
                    log.debug("Desktop notification failed: %s", exc)
                    _console(alert)

            return _plyer

        except ImportError:
            log.debug("plyer not available — using console notifications.")
            return _console


def _console(alert: Alert) -> None:
    prefix = _SEVERITY_PREFIX.get(alert.pre_severity, "[????]")
    print(f"\n{prefix} ALERT [{alert.alert_id}]: {alert.title}\n", flush=True)
