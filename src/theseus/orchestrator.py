"""Theseus pipeline orchestrator.

Runs the four phases (triage, capability, ioc, verdict) through a pluggable LLM
backend against a running Ghidra/ghidrasql stack, and emits a structured JSON report.

Public entry point: `analyze(binary_path, ...)`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .backends import PhaseResult, get_backend
from .headless_runner import GhidrasqlRunner, HeadlessRunner, find_free_port

log = logging.getLogger("theseus.orchestrator")

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schema" / "report.schema.json"

DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-7")
MAX_AGENT_TURNS = int(os.getenv("THESEUS_MAX_TURNS", "40"))  # safety cap per phase


@dataclass
class PipelineConfig:
    ghidra_home: Path
    project_dir: Path
    model: str = DEFAULT_MODEL
    backend: Optional[str] = None  # picks via $THESEUS_BACKEND if None
    libghidra_port: Optional[int] = None
    ghidrasql_port: Optional[int] = None
    max_turns: int = MAX_AGENT_TURNS

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        return cls(
            ghidra_home=Path(os.environ["GHIDRA_HOME"]),
            project_dir=Path(os.environ.get("GHIDRA_PROJECT_DIR", "./ghidra_projects")),
            model=os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL),
            backend=os.environ.get("THESEUS_BACKEND"),
        )


@dataclass
class PipelineCallbacks:
    on_log: Optional[Callable[[str], None]] = None
    on_phase_start: Optional[Callable[[str], None]] = None
    on_phase_progress: Optional[Callable[[str, float], None]] = None  # (phase, 0..1)
    on_phase_done: Optional[Callable[[str, Any], None]] = None
    on_token: Optional[Callable[[int, int], None]] = None  # (in, out) running totals

    def log(self, msg: str) -> None:
        if self.on_log:
            self.on_log(msg)
        else:
            log.info(msg)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def _extract_json(text: str) -> Any:
    """Best-effort: find the largest JSON object/array in `text`."""
    m = _JSON_BLOCK_RE.search(text)
    if m:
        return json.loads(m.group(1))
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start < 0:
            continue
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    raise ValueError(f"no JSON found in model output: {text[:400]}...")


def _sanitize_phase_payload(
    phase: str,
    payload: Any,
    log: Callable[[str], None],
) -> None:
    """Post-extract sanity fixes for known LLM-output drift.

    Currently:
    - `triage.import_count` must be >= len(`triage.notable_imports`). Models
      sometimes guess 0 here when running on kernel drivers because the
      `imports` SQL table is empty for them; we self-heal so downstream
      consumers (deck, GUI, SOC ticket) don't show a contradiction.
    """
    if phase != "triage" or not isinstance(payload, dict):
        return
    notable = payload.get("notable_imports")
    if not isinstance(notable, list) or not notable:
        return
    count = payload.get("import_count")
    if not isinstance(count, int) or count < len(notable):
        bumped = len(notable)
        if count != bumped:
            log(
                f"[triage] import_count={count!r} < len(notable_imports)={bumped};"
                f" bumped to {bumped}."
            )
        payload["import_count"] = bumped


def _build_user_prompt(base: str, prior_context: dict[str, Any]) -> str:
    if not prior_context:
        return base
    return base + "\n\n## Prior phase outputs\n```json\n" + json.dumps(prior_context, indent=2) + "\n```"


def analyze(
    binary_path: Path | str,
    *,
    config: Optional[PipelineConfig] = None,
    callbacks: Optional[PipelineCallbacks] = None,
) -> dict[str, Any]:
    """Run the full pipeline against `binary_path` and return the report dict."""
    cb = callbacks or PipelineCallbacks()
    cfg = config or PipelineConfig.from_env()
    binary = Path(binary_path).resolve()
    if not binary.exists():
        raise FileNotFoundError(binary)

    started = time.monotonic()
    started_iso = dt.datetime.now(dt.timezone.utc).isoformat()

    libghidra_port = cfg.libghidra_port or find_free_port(18080, 18180)
    ghidrasql_port = cfg.ghidrasql_port or find_free_port(8081, 8181)

    startup_timeout = float(
        os.environ.get("GHIDRA_STARTUP_TIMEOUT")
        or HeadlessRunner.__dataclass_fields__["startup_timeout"].default
    )
    headless = HeadlessRunner(
        binary=binary,
        project_dir=cfg.project_dir,
        ghidra_home=cfg.ghidra_home,
        port=libghidra_port,
        log_cb=cb.on_log,
        startup_timeout=startup_timeout,
    )
    sql = GhidrasqlRunner(
        libghidra_url=headless.base_url,
        port=ghidrasql_port,
        log_cb=cb.on_log,
    )

    system_prompt = _load_prompt("system.md")
    phase_prompts = {
        "triage": _load_prompt("triage.md"),
        "capability": _load_prompt("capability.md"),
        "ioc": _load_prompt("ioc.md"),
        "verdict": _load_prompt("verdict.md"),
    }

    phase_payloads: dict[str, Any] = {}
    totals = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost_usd": 0.0}
    phase_costs: dict[str, dict[str, float | int]] = {}

    try:
        with headless, sql:
            backend = get_backend(
                cfg.backend,
                ghidrasql_url=sql.base_url,
                libghidra_url=headless.base_url,
                model=cfg.model,
            )
            with backend:
                for phase, prompt_text in phase_prompts.items():
                    if cb.on_phase_start:
                        cb.on_phase_start(phase)

                    if phase == "capability":
                        prior = {"triage": phase_payloads.get("triage")}
                    elif phase == "ioc":
                        prior = {"triage": phase_payloads.get("triage")}
                    elif phase == "verdict":
                        prior = {
                            "triage": phase_payloads.get("triage"),
                            "capabilities": phase_payloads.get("capability"),
                            "iocs": phase_payloads.get("ioc"),
                        }
                    else:
                        prior = {}

                    pr: PhaseResult = backend.run_phase(
                        system=system_prompt,
                        user_prompt=_build_user_prompt(prompt_text, prior),
                        phase_name=phase,
                        max_turns=cfg.max_turns,
                        log=cb.log,
                        on_token=cb.on_token,
                        on_progress=cb.on_phase_progress,
                    )

                    totals["input"] += pr.input_tokens
                    totals["output"] += pr.output_tokens
                    totals["cache_read"] += pr.cache_read_tokens
                    totals["cache_write"] += pr.cache_write_tokens
                    totals["cost_usd"] += pr.cost_usd

                    phase_usd = pr.cost_usd
                    if not phase_usd:
                        phase_usd = _estimate_cost_usd(cfg.model, {
                            "input": pr.input_tokens,
                            "output": pr.output_tokens,
                            "cache_read": pr.cache_read_tokens,
                            "cache_write": pr.cache_write_tokens,
                        })
                    phase_costs[phase] = {
                        "input_tokens": pr.input_tokens,
                        "output_tokens": pr.output_tokens,
                        "cache_read_tokens": pr.cache_read_tokens,
                        "cache_write_tokens": pr.cache_write_tokens,
                        "cost_usd": round(phase_usd, 4),
                    }

                    try:
                        payload = _extract_json(pr.raw_text)
                    except ValueError as e:
                        cb.log(f"[{phase}] JSON extract failed: {e}")
                        payload = {"error": "json_extract_failed", "raw": pr.raw_text}
                    _sanitize_phase_payload(phase, payload, cb.log)
                    phase_payloads[phase] = payload

                    if cb.on_phase_done:
                        cb.on_phase_done(phase, payload)
    except Exception:
        cb.log("pipeline failed; tearing down")
        raise

    duration = time.monotonic() - started

    backend_reported_cost = totals["cost_usd"]
    estimated_cost = _estimate_cost_usd(cfg.model, totals)

    report = {
        "meta": {
            "binary_path": str(binary),
            "sha256": _sha256_file(binary),
            "size_bytes": binary.stat().st_size,
            "analyzed_at": started_iso,
            "duration_seconds": round(duration, 2),
            "model": cfg.model,
            "backend": (cfg.backend or os.environ.get("THESEUS_BACKEND") or "anthropic"),
        },
        "triage": phase_payloads.get("triage"),
        "capabilities": phase_payloads.get("capability") or [],
        "iocs": phase_payloads.get("ioc") or [],
        "verdict": phase_payloads.get("verdict"),
        "cost": {
            "input_tokens": totals["input"],
            "output_tokens": totals["output"],
            "cache_read_tokens": totals["cache_read"],
            "cache_write_tokens": totals["cache_write"],
            "usd": round(backend_reported_cost, 4) if backend_reported_cost else estimated_cost,
            "phases": phase_costs,
        },
    }
    return report


_PRICING_PER_MTOK = {
    # USD per million tokens — approximate, update with current pricing.
    # Only used when the backend does not report its own cost (e.g. AnthropicBackend).
    "claude-opus-4-7": {"input": 15.0, "output": 75.0, "cache_read": 1.5, "cache_write": 18.75},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0, "cache_read": 0.1, "cache_write": 1.25},
}


def _estimate_cost_usd(model: str, totals: dict[str, float]) -> float:
    key = next((k for k in _PRICING_PER_MTOK if model.startswith(k)), None)
    if not key:
        return 0.0
    p = _PRICING_PER_MTOK[key]
    cost = (
        totals["input"] * p["input"]
        + totals["output"] * p["output"]
        + totals["cache_read"] * p["cache_read"]
        + totals["cache_write"] * p["cache_write"]
    ) / 1_000_000.0
    return round(cost, 4)
