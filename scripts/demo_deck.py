"""Generate a demo reveal.js deck from a synthetic report so you can preview output
without running Ghidra. Useful for hackathon dry-runs and tweaking the deck template.

Run: `python scripts/demo_deck.py`
Then open `reports/demo_deck.html` in a browser. Press F for fullscreen.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.test_deck import _sample_report  # noqa: E402
from theseus.deck import render_deck  # noqa: E402


def main() -> None:
    out = ROOT / "reports" / "demo_deck.html"
    out.parent.mkdir(exist_ok=True)
    rendered = render_deck(_sample_report(), out)
    print(f"wrote {rendered}")
    print(f"open: file://{rendered.resolve()}")


if __name__ == "__main__":
    main()
