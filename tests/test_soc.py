from theseus.soc import summarize_for_ticket


def test_summarize_basic() -> None:
    report = {
        "meta": {"sha256": "deadbeef" + "0" * 56},
        "triage": {"format": "PE", "arch": "x86:LE:64"},
        "verdict": {"label": "malicious", "score": 0.91, "soc_action": "escalate", "reasoning": "injection + c2"},
        "capabilities": [
            {"technique_id": "T1055.002", "confidence": 0.9},
            {"technique_id": "T1071.001", "confidence": 0.7},
        ],
        "iocs": [{"value": "http://bad.example/c2"}],
    }
    s = summarize_for_ticket(report)
    assert "MALICIOUS" in s
    assert "T1055.002" in s
    assert "escalate" in s
