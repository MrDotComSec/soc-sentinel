"""
Cross-platform service installer.
--install  → registers SOC Sentinel to launch automatically on system startup.
--uninstall → removes that registration.

Linux  : systemd user service  (~/.config/systemd/user/)
Windows: HKCU Run registry key
macOS  : launchd user agent   (~/Library/LaunchAgents/)
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

log = logging.getLogger(__name__)

_SERVICE_NAME = "soc-sentinel"
_DISPLAY_NAME = "SOC Sentinel HIDS"

# Resolved at import time so --install captures the correct paths
_PYTHON = str(Path(sys.executable).resolve())
_SCRIPT = str(Path(sys.argv[0]).resolve())


def install_service() -> None:
    _dispatch(_install_systemd, _install_windows_registry, _install_launchd)


def uninstall_service() -> None:
    _dispatch(_uninstall_systemd, _uninstall_windows_registry, _uninstall_launchd)


def _dispatch(linux_fn, windows_fn, macos_fn) -> None:
    system = platform.system()
    handlers = {"Linux": linux_fn, "Windows": windows_fn, "Darwin": macos_fn}
    fn = handlers.get(system)
    if fn is None:
        log.error("Autostart not supported on %s", system)
        return
    fn()


# ---------------------------------------------------------------------------
# Linux — systemd user service
# ---------------------------------------------------------------------------
_UNIT_TEMPLATE = dedent("""\
    [Unit]
    Description=SOC Sentinel Host-based Intrusion Detection System
    After=network.target

    [Service]
    Type=simple
    ExecStart={python} {script}
    Restart=on-failure
    RestartSec=10
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=default.target
""")


def _systemd_unit_path() -> Path:
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    return unit_dir / f"{_SERVICE_NAME}.service"


def _install_systemd() -> None:
    unit_path = _systemd_unit_path()
    unit_path.write_text(_UNIT_TEMPLATE.format(python=_PYTHON, script=_SCRIPT))
    _run(["systemctl", "--user", "daemon-reload"])
    _run(["systemctl", "--user", "enable", "--now", _SERVICE_NAME])
    log.info("Installed systemd user service at %s", unit_path)
    log.info("Manage with: systemctl --user {start|stop|restart|status} %s", _SERVICE_NAME)


def _uninstall_systemd() -> None:
    _run(["systemctl", "--user", "disable", "--now", _SERVICE_NAME], check=False)
    unit_path = _systemd_unit_path()
    if unit_path.exists():
        unit_path.unlink()
        _run(["systemctl", "--user", "daemon-reload"])
        log.info("Removed systemd user service.")
    else:
        log.warning("Unit file not found — already removed?")


# ---------------------------------------------------------------------------
# Windows — HKCU Run registry key (current user, no admin required)
# ---------------------------------------------------------------------------
_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _install_windows_registry() -> None:
    import winreg  # noqa: PLC0415 — Windows-only import

    cmd = f'"{_PYTHON}" "{_SCRIPT}"'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, _DISPLAY_NAME, 0, winreg.REG_SZ, cmd)
    log.info("Added startup registry key: HKCU\\%s\\%s", _REG_KEY, _DISPLAY_NAME)


def _uninstall_windows_registry() -> None:
    import winreg  # noqa: PLC0415

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, _DISPLAY_NAME)
        log.info("Removed startup registry key.")
    except FileNotFoundError:
        log.warning("Registry key not found — already removed?")


# ---------------------------------------------------------------------------
# macOS — launchd user agent
# ---------------------------------------------------------------------------
_PLIST_TEMPLATE = dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.{name}</string>
        <key>ProgramArguments</key>
        <array>
            <string>{python}</string>
            <string>{script}</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>StandardOutPath</key>
        <string>/tmp/{name}.stdout.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/{name}.stderr.log</string>
    </dict>
    </plist>
""")


def _launchd_plist_path() -> Path:
    agents_dir = Path.home() / "Library" / "LaunchAgents"
    agents_dir.mkdir(exist_ok=True)
    return agents_dir / f"com.{_SERVICE_NAME}.plist"


def _install_launchd() -> None:
    plist_path = _launchd_plist_path()
    plist_path.write_text(
        _PLIST_TEMPLATE.format(name=_SERVICE_NAME, python=_PYTHON, script=_SCRIPT)
    )
    _run(["launchctl", "load", str(plist_path)])
    log.info("Installed launchd agent at %s", plist_path)


def _uninstall_launchd() -> None:
    plist_path = _launchd_plist_path()
    if plist_path.exists():
        _run(["launchctl", "unload", str(plist_path)], check=False)
        plist_path.unlink()
        log.info("Removed launchd agent.")
    else:
        log.warning("Plist not found — already removed?")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run(cmd: list[str], check: bool = True) -> None:
    try:
        subprocess.run(cmd, check=check, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        log.error("Command failed: %s — %s", " ".join(cmd), exc)
