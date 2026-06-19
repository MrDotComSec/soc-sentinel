"""
Configuration loader with deep-merge defaults.
Call load_config() once at startup; pass the resulting dict everywhere.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

_DEFAULTS: dict[str, Any] = {
    "monitoring": {
        "interval": 5,
        "cpu_threshold": 85,
        "ram_threshold": 90,
        "failed_login_threshold": 5,
    },
    "rules": {
        "process_whitelist": [],
        "suspicious_processes": [],
        "suspicious_ports": [],
        "suspicious_ips": [],
    },
    "alerts": {
        "sound": True,
        "popup": True,
        "log": True,
        "log_path": "logs/sentinel.log",
        "log_format": "json",
        "notify_threshold": "MEDIUM",
    },
    "ai": {
        "enabled": True,
        "provider": "ollama",
        "ollama": {
            "url": "http://localhost:11434",
            "model": "llama3",
        },
        "api": {
            "url": "",
            "key": "",
            "model": "",
        },
        "timeout": 30,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Path) -> dict:
    """
    Load YAML config from path and deep-merge over built-in defaults.
    Partial configs are valid — any omitted key falls back to its default.
    """
    with path.open("r", encoding="utf-8") as fh:
        user_config: dict = yaml.safe_load(fh) or {}
    return _deep_merge(_DEFAULTS, user_config)
