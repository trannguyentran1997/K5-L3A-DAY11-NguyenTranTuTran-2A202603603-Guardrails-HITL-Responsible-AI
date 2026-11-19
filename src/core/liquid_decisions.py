"""
Liquid AI Decisions (System One) API client.

Endpoint: https://api.liquid.ai/decisions/v1/systemone
Model:    d1 (supports ``choice``, ``noul``, and ``score`` questions)

Bổ sung song song với OpenRouter — không xóa kết nối OpenRouter.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
import requests

_SRC_DIR = str(Path(__file__).resolve().parent.parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from core.config import (
    get_liquid_api_key,
    get_liquid_decisions_model,
    get_liquid_decisions_url,
)


def call_liquid_decisions(
    state: str,
    questions: dict[str, dict[str, Any]],
    *,
    model: str | None = None,
    api_key: str | None = None,
    url: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Call Liquid AI System One Decisions endpoint.

    Args:
        state: Input text/state to evaluate.
        questions: Mapping of question name to System One schema
            (``type`` in ``{"choice", "noul", "score"}`` for ``d1``).
        model: Override model (default from ``LIQUID_DECISIONS_MODEL`` = ``d1``).
        api_key: Override API key (default from ``LIQUID_API_KEY``).
        url: Override endpoint URL (default from ``LIQUID_DECISIONS_URL``).
        timeout: HTTP timeout in seconds.

    Returns:
        Parsed JSON response dict containing ``model``, ``answers``, and ``usage``.
    """
    token = (api_key or get_liquid_api_key()).strip()
    if not token:
        raise RuntimeError(
            "Missing LIQUID_API_KEY. Set LIQUID_API_KEY in .env before calling Liquid Decisions."
        )

    endpoint = url or get_liquid_decisions_url()
    payload = {
        "model": model or get_liquid_decisions_model(),
        "state": state,
        "questions": questions,
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()


def demo_triage(state: str = "Help! My payouts have been failing for 3 days.") -> dict[str, Any]:
    """Sample System One decision call (department, is_urgent, frustration)."""
    questions = {
        "department": {
            "type": "choice",
            "instructions": "Which team should handle this?",
            "criteria": {
                "billing": "Payments, invoicing, refunds",
                "technical": "Bugs, outages, integrations",
                "sales": "Pricing, upgrades, new accounts",
            },
        },
        "is_urgent": {
            "type": "noul",
            "instructions": "Does this convey urgency?",
        },
        "frustration": {
            "type": "score",
            "instructions": "How frustrated is the customer?",
            "criteria": ["Calm", "Frustrated", "Very angry"],
        },
    }
    return call_liquid_decisions(state=state, questions=questions)


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    result = demo_triage()
    print(json.dumps(result, ensure_ascii=False, indent=2))
