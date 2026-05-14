"""Render a Theseus report as a reveal.js HTML presentation.

Drops a single self-contained HTML file that loads reveal.js from CDN. Open in any
browser, press `F` for fullscreen, arrow keys to navigate.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from jinja2 import Template

_TEMPLATE = Template(
    r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Theseus — {{ sha8 }}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@5/dist/reset.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@5/dist/reveal.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@5/dist/theme/black.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@5/plugin/highlight/monokai.css">
<style>
  .reveal section { text-align: left; }
  .reveal h1, .reveal h2, .reveal h3 { text-transform: none; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.6em; margin-right: 6px; }
  .b-malicious { background: #c0392b; }
  .b-vulnerable { background: #8e44ad; }
  .b-suspicious { background: #d35400; }
  .b-clean { background: #27ae60; }
  .b-unknown { background: #7f8c8d; }
  table { width: 100%; border-collapse: collapse; font-size: 0.5em; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #444; }
  th { color: #ccc; text-align: left; }
  .ev { font-family: monospace; font-size: 0.4em; opacity: 0.8; }
  .score-bar { display: inline-block; height: 12px; background: linear-gradient(90deg, #27ae60, #d35400, #c0392b); border-radius: 6px; }
  pre code { font-size: 0.55em; }
  .verdict-reasoning {
    font-size: 0.45em;
    line-height: 1.4;
    opacity: 0.85;
    max-height: 55vh;
    overflow-y: auto;
    padding-right: 12px;
    white-space: pre-wrap;
  }
</style>
</head>
<body>
<div class="reveal"><div class="slides">

<section data-background-gradient="linear-gradient(to bottom, #111, #001a33)">
  <h1>Theseus</h1>
  <h3>Navigate any binary.</h3>
  <p style="opacity:0.6;">SHA-256: <code>{{ sha8 }}…</code></p>
  <p style="opacity:0.5; font-size:0.6em;">{{ meta.binary_path }}</p>
</section>

<section>
  <h2><span class="badge b-{{ verdict.label }}">{{ verdict.label|upper }}</span> Verdict</h2>
  <p style="font-size:0.7em;">Score: <strong>{{ "%.2f"|format(verdict.score) }}</strong> / 1.00 &nbsp;&nbsp; SOC action: <strong>{{ verdict.soc_action|upper }}</strong></p>
  <div class="verdict-reasoning">{{ verdict.reasoning }}</div>
</section>

<section>
  <h2>Triage</h2>
  <ul style="font-size:0.7em;">
    <li>Format: <code>{{ triage.format }}</code> &nbsp; Arch: <code>{{ triage.arch }}</code></li>
    <li>Entry: <code>{{ triage.entry_point }}</code></li>
    <li>Packed: {{ "yes" if triage.packed else "no" }}{% if triage.pack_evidence %} — {{ triage.pack_evidence }}{% endif %}</li>
    <li>Functions: {{ triage.function_count }} &nbsp; Imports: {{ triage.import_count }} &nbsp; Strings: {{ triage.string_count }}</li>
    <li>Suspicion score: {{ triage.suspicion_score }}/100</li>
  </ul>
</section>

<section>
  <h2>Notable imports</h2>
  <table>
    <tr><th>Import</th><th>Category</th><th>Why it matters</th></tr>
    {% for imp in triage.notable_imports[:12] %}
    <tr><td><code>{{ imp.name }}</code></td><td>{{ imp.category }}</td><td>{{ imp.reason }}</td></tr>
    {% endfor %}
  </table>
</section>

<section>
  <h2>MITRE ATT&CK capabilities</h2>
  <table>
    <tr><th>Technique</th><th>Name</th><th>Conf.</th><th>Evidence</th></tr>
    {% for cap in capabilities[:10] %}
    <tr>
      <td><code>{{ cap.technique_id }}</code></td>
      <td>{{ cap.name }}</td>
      <td>{{ "%.2f"|format(cap.confidence) }}</td>
      <td class="ev">
        {% for ev in cap.evidence[:2] %}{{ ev.address }} {{ ev.snippet[:80] }}<br>{% endfor %}
      </td>
    </tr>
    {% endfor %}
  </table>
</section>

<section>
  <h2>Indicators of Compromise</h2>
  <table>
    <tr><th>Type</th><th>Value</th><th>Xrefs</th><th>Conf.</th></tr>
    {% for ioc in iocs[:15] %}
    <tr>
      <td>{{ ioc.type }}</td>
      <td class="ev">{{ ioc.value }}</td>
      <td>{{ ioc.xref_count or "-" }}</td>
      <td>{{ "%.2f"|format(ioc.confidence) }}</td>
    </tr>
    {% endfor %}
  </table>
</section>

{% if verdict.yara_rule %}
<section>
  <h2>Auto-generated YARA</h2>
  <pre><code class="yara">{{ verdict.yara_rule }}</code></pre>
</section>
{% endif %}

<section>
  <h2>Cost telemetry</h2>
  <ul style="font-size:0.7em;">
    <li>Model: <code>{{ meta.model }}</code></li>
    <li>Input tokens: {{ cost.input_tokens }} &nbsp; Output: {{ cost.output_tokens }}</li>
    <li>Cache read: {{ cost.cache_read_tokens }} &nbsp; Cache write: {{ cost.cache_write_tokens }}</li>
    <li>Estimated cost: <strong>${{ "%.4f"|format(cost.usd) }}</strong></li>
    <li>Wall time: {{ "%.1f"|format(meta.duration_seconds) }}s</li>
  </ul>
  <p style="opacity:0.6; font-size:0.6em;">Triage in seconds. Cost in cents. Scales to SOC volume.</p>
</section>

<section data-background-gradient="linear-gradient(to bottom, #001a33, #111)">
  <h2>Theseus</h2>
  <p>SIEM -&gt; quarantine -&gt; Theseus -&gt; verdict -&gt; SOAR</p>
  <p style="opacity:0.6;">Built on Ghidra + libghidra + ghidrasql + Claude.</p>
</section>

</div></div>

<script src="https://cdn.jsdelivr.net/npm/reveal.js@5/dist/reveal.js"></script>
<script src="https://cdn.jsdelivr.net/npm/reveal.js@5/plugin/highlight/highlight.js"></script>
<script>
Reveal.initialize({
  hash: true,
  controls: true,
  progress: true,
  plugins: [ RevealHighlight ]
});
</script>
</body>
</html>
"""
)


def render_deck(report: dict[str, Any], output: Path) -> Path:
    """Render report → reveal.js HTML at `output`. Returns the path."""
    sha = (report.get("meta", {}).get("sha256") or "")[:12] or "unknown"
    ctx = {
        "sha8": sha,
        "meta": report.get("meta", {}),
        "triage": report.get("triage") or {},
        "capabilities": report.get("capabilities") or [],
        "iocs": report.get("iocs") or [],
        "verdict": report.get("verdict") or {"label": "unknown", "score": 0.0, "reasoning": "", "soc_action": "escalate"},
        "cost": report.get("cost") or {},
    }
    html_out = _TEMPLATE.render(**ctx)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_out, encoding="utf-8")
    return output
