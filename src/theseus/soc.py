"""SOC integration helpers — webhook delivery + verdict-to-action mapping."""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("theseus.soc")


def push_to_webhook(url: str, report: dict[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
    """POST the report to a SOAR/SIEM webhook. Returns the response body (if JSON) or status info."""
    headers = {"Content-Type": "application/json", "User-Agent": "theseus/0.1"}
    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, json=report, headers=headers)
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            return {"status_code": r.status_code, "text_excerpt": r.text[:200]}


def summarize_for_ticket(report: dict[str, Any]) -> str:
    """One-paragraph plain-text summary suitable for a SOC ticket body."""
    meta = report.get("meta", {})
    triage = report.get("triage") or {}
    verdict = report.get("verdict") or {}
    caps = report.get("capabilities") or []
    iocs = report.get("iocs") or []

    top_caps = ", ".join(
        f"{c.get('technique_id')} ({c.get('confidence', 0):.2f})"
        for c in sorted(caps, key=lambda x: x.get("confidence", 0), reverse=True)[:5]
    ) or "none"
    top_iocs = ", ".join(i.get("value", "?") for i in iocs[:5]) or "none"

    return (
        f"Theseus verdict: {verdict.get('label', 'unknown').upper()} "
        f"(score={verdict.get('score', 0):.2f}). "
        f"Binary {meta.get('sha256', '')[:12]} ({triage.get('format', '?')}, {triage.get('arch', '?')}). "
        f"Recommended action: {verdict.get('soc_action', 'escalate')}. "
        f"Top techniques: {top_caps}. "
        f"IoCs: {top_iocs}. "
        f"Reasoning: {verdict.get('reasoning', '')}"
    )
