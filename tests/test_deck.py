"""Smoke test: render the reveal.js deck from a synthetic report."""

from __future__ import annotations

import json
from pathlib import Path

from theseus.deck import render_deck


def _sample_report() -> dict:
    return {
        "meta": {
            "binary_path": "C:/samples/sample.exe",
            "sha256": "a" * 64,
            "size_bytes": 102400,
            "analyzed_at": "2026-05-11T12:00:00Z",
            "duration_seconds": 73.4,
            "model": "claude-opus-4-7",
        },
        "triage": {
            "entry_point": "0x401000",
            "arch": "x86:LE:64:default",
            "format": "PE",
            "packed": False,
            "pack_evidence": "",
            "suspicion_score": 78,
            "function_count": 312,
            "import_count": 84,
            "string_count": 1204,
            "notable_imports": [
                {"name": "VirtualAllocEx", "category": "injection", "reason": "Remote alloc"},
                {"name": "WriteProcessMemory", "category": "injection", "reason": "Write target"},
                {"name": "CreateRemoteThread", "category": "injection", "reason": "Spawn in target"},
                {"name": "WinHttpOpen", "category": "network", "reason": "C2 channel"},
            ],
            "notable_strings": [
                {"value": "http://c2.example.com/beacon", "address": "0x10040020", "category": "url"},
            ],
        },
        "capabilities": [
            {
                "technique_id": "T1055.002",
                "name": "Process Injection: PE Injection",
                "tactic": "Defense Evasion",
                "confidence": 0.88,
                "evidence": [{"address": "0x401820", "function": "Inject", "snippet": "alloc+write+thread chain"}],
            },
            {
                "technique_id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "confidence": 0.75,
                "evidence": [{"address": "0x402100", "function": "Beacon", "snippet": "WinHttpOpen → SendRequest"}],
            },
        ],
        "iocs": [
            {"type": "url", "value": "http://c2.example.com/beacon", "source_address": "0x10040020", "xref_count": 3, "confidence": 0.9},
            {"type": "mutex", "value": "Global\\theseusmtx_42", "source_address": "0x10040044", "xref_count": 1, "confidence": 0.7},
        ],
        "verdict": {
            "label": "malicious",
            "score": 0.84,
            "reasoning": "Injection chain corroborated by hardcoded C2 URL.",
            "soc_action": "escalate",
            "yara_rule": "rule theseus_aaaaaaaa { strings: $s1 = \"http://c2.example.com/beacon\" ascii condition: $s1 }",
        },
        "cost": {
            "input_tokens": 18000,
            "output_tokens": 3200,
            "cache_read_tokens": 12000,
            "cache_write_tokens": 1500,
            "usd": 0.42,
        },
    }


def test_render_deck(tmp_path: Path) -> None:
    report = _sample_report()
    out = render_deck(report, tmp_path / "deck.html")
    text = out.read_text(encoding="utf-8")
    assert "Theseus" in text
    assert "T1055.002" in text
    assert "c2.example.com" in text
    assert "MALICIOUS" in text
    assert "reveal.js" in text


if __name__ == "__main__":
    out = Path("reports/demo_deck.html")
    out.parent.mkdir(exist_ok=True)
    rendered = render_deck(_sample_report(), out)
    print(f"wrote {rendered}")
