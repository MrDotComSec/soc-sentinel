"""
Builds structured prompts for the AI analysis layer.
Separated from analyzer.py so the prompt can be iterated independently.
"""

from __future__ import annotations

import json

from utils.models import Alert

_SYSTEM_PROMPT = """\
You are a SOC (Security Operations Center) analyst assistant integrated into a \
Host-based Intrusion Detection System (HIDS).

Your role is STRICTLY limited to:
1. Classifying the severity of the alert you receive.
2. Explaining what the alert means in plain English.
3. Listing plausible causes.
4. Suggesting a concrete action for the responding analyst.
5. Writing a short, professional SOC-style incident report.

You must NOT:
- Access the internet or any external resource.
- Execute commands or modify any system.
- Perform vulnerability scans or threat lookups.
- Invent data not present in the alert JSON.

Respond ONLY with a single valid JSON object that matches this schema exactly — \
no markdown, no preamble, no trailing text:

{
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "explanation": "<1–2 sentences: what this alert means>",
  "possible_causes": ["<cause 1>", "<cause 2>", "<cause 3>"],
  "recommended_action": "<one clear, actionable step for the SOC analyst>",
  "incident_report": "<3–5 sentence professional SOC incident summary>"
}
"""


def build_prompt(alert: Alert) -> tuple[str, str]:
    """
    Returns (system_prompt, user_message) ready for a chat-completion call.
    The alert is serialised to JSON so the model sees structured, unambiguous data.
    """
    user_msg = (
        "Analyse the following HIDS alert and return the JSON report:\n\n"
        f"{json.dumps(alert.to_dict(), indent=2, default=str)}"
    )
    return _SYSTEM_PROMPT, user_msg
