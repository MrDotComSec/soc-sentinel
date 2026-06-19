"""
AI analysis layer — sends an Alert to a local Ollama model or an HTTP API
and returns a structured AnalysisResult.

Failure modes are handled defensively:
  - Timeout        → returns _FALLBACK_ANALYSIS (logged as WARNING)
  - Parse error    → same fallback (logged as WARNING)
  - AI disabled    → returns fallback silently
The original alert is always persisted before this module is called,
so a failure here never loses alert data.
"""

from __future__ import annotations

import json
import logging
import re

import requests

from ai.prompt_engine import build_prompt
from utils.models import Alert, AnalysisResult, Severity

log = logging.getLogger(__name__)

_FALLBACK = AnalysisResult(
    severity=Severity.MEDIUM,
    explanation="AI analysis unavailable — manual review required.",
    possible_causes=[
        "AI service offline or not running",
        "Network timeout reaching Ollama",
        "Model not loaded in Ollama",
    ],
    recommended_action=(
        "Review the raw alert in the log file and escalate to a senior analyst "
        "if the alert type is SUSPICIOUS_PROCESS or SUSPICIOUS_CONNECTION."
    ),
    incident_report=(
        "Automated AI classification could not be completed for this alert. "
        "The raw alert data has been persisted to the log for manual review. "
        "A SOC analyst should triage based on the alert type and context. "
        "Ensure the Ollama service is running and the configured model is available."
    ),
)


class AIAnalyzer:
    """Routes Alert → prompt → model → AnalysisResult."""

    def __init__(self, config: dict) -> None:
        self._enabled: bool = config.get("enabled", True)
        self._provider: str = config.get("provider", "ollama")
        self._timeout: int = int(config.get("timeout", 30))
        self._ollama = config.get("ollama", {})
        self._api = config.get("api", {})

    def analyze(self, alert: Alert) -> AnalysisResult:
        if not self._enabled:
            return _FALLBACK
        try:
            if self._provider == "ollama":
                return self._ollama_call(alert)
            return self._api_call(alert)
        except requests.Timeout:
            log.warning("[%s] AI request timed out after %ds.", alert.alert_id, self._timeout)
        except requests.RequestException as exc:
            log.warning("[%s] AI request failed: %s", alert.alert_id, exc)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            log.warning("[%s] AI response parse error: %s", alert.alert_id, exc)
        return _FALLBACK

    # ------------------------------------------------------------------
    # Provider implementations
    # ------------------------------------------------------------------

    def _ollama_call(self, alert: Alert) -> AnalysisResult:
        system_prompt, user_msg = build_prompt(alert)
        url = f"{self._ollama.get('url', 'http://localhost:11434').rstrip('/')}/api/chat"
        payload = {
            "model": self._ollama.get("model", "llama3"),
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
        }
        resp = requests.post(url, json=payload, timeout=self._timeout)
        resp.raise_for_status()
        content: str = resp.json()["message"]["content"]
        return _parse(content, alert.alert_id)

    def _api_call(self, alert: Alert) -> AnalysisResult:
        url = self._api.get("url", "")
        key = self._api.get("key", "")
        if not url or not key:
            raise ValueError("API provider selected but url/key are not configured.")

        system_prompt, user_msg = build_prompt(alert)
        payload = {
            "model": self._api.get("model", ""),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
        }
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return _parse(content, alert.alert_id)


# ---------------------------------------------------------------------------
# Parser — module-level so it can be unit-tested independently
# ---------------------------------------------------------------------------

def _parse(content: str, alert_id: str) -> AnalysisResult:
    """
    Extract the JSON object from the model's response.
    Models occasionally wrap output in markdown code fences — strip them first.
    """
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in response: {content[:300]!r}")

    data = json.loads(match.group())

    return AnalysisResult(
        severity=Severity.from_string(data.get("severity", "MEDIUM")),
        explanation=str(data.get("explanation", "")),
        possible_causes=list(data.get("possible_causes", [])),
        recommended_action=str(data.get("recommended_action", "")),
        incident_report=str(data.get("incident_report", "")),
    )
