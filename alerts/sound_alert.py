"""
Cross-platform audio alert.
Resolution order:
  Windows → winsound.Beep() (stdlib, zero deps)
  macOS   → afplay system sound, fallback osascript beep
  Linux   → beep command, fallback to terminal bell (\a)

Sound runs in a daemon thread so it never blocks the alert pipeline.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import threading
from typing import Callable

from utils.models import Alert, Severity

log = logging.getLogger(__name__)

_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


class SoundAlert:
    def __init__(self, enabled: bool, threshold: str = "MEDIUM") -> None:
        self._enabled = enabled
        self._threshold = Severity.from_string(threshold)
        self._beep: Callable[[], None] = self._resolve()

    def trigger(self, alert: Alert) -> None:
        if not self._enabled:
            return
        if alert.pre_severity < self._threshold:
            return
        threading.Thread(target=self._beep, daemon=True, name="sentinel-beep").start()

    # ------------------------------------------------------------------

    def _resolve(self) -> Callable[[], None]:
        system = platform.system()
        if system == "Windows":
            return _windows_beep
        if system == "Darwin":
            return _macos_beep
        return _linux_beep


# Standalone functions so they can be targeted by Thread without holding self

def _windows_beep() -> None:
    try:
        import winsound  # noqa: PLC0415
        winsound.Beep(1000, 600)
    except Exception as exc:
        log.debug("winsound failed: %s", exc)


def _macos_beep() -> None:
    try:
        result = subprocess.run(
            ["afplay", "/System/Library/Sounds/Sosumi.aiff"],
            check=False,
            capture_output=True,
            timeout=3,
        )
        if result.returncode != 0:
            raise OSError("afplay failed")
    except (FileNotFoundError, OSError):
        subprocess.run(
            ["osascript", "-e", "beep"],
            check=False,
            capture_output=True,
            timeout=3,
        )


def _linux_beep() -> None:
    try:
        result = subprocess.run(
            ["beep", "-f", "1000", "-l", "600"],
            check=False,
            capture_output=True,
            timeout=3,
        )
        if result.returncode != 0:
            raise FileNotFoundError
    except (FileNotFoundError, OSError):
        # Terminal bell — guaranteed to work in any TTY
        print("\a", end="", flush=True)
