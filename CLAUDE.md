# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Theseus is an AI-assisted reverse-engineering pipeline. Given a binary, it spawns Ghidra headless, exposes the analyzed program DB as SQL via `ghidrasql`, and drives a four-phase Claude tool-use loop (triage → capability → ioc → verdict). Final output is a JSON report (schema in `schema/report.schema.json`) and a reveal.js HTML deck.

The system is a thin orchestrator over three external pieces it does not own: **Ghidra** (analyzer), **libghidra** (HTTP RPC over Ghidra), and **ghidrasql** (SQL frontend over libghidra). See `docs/ghidra_extension_install.md` for the LibGhidraHost extension install (lives in `C:\Users\leal\Desktop\ghidra_12.0.4_PUBLIC\Ghidra\Extensions\LibGhidraHost\`).

## Commands

Install (editable, src-layout). Python 3.12+ required (`pyproject.toml`):

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt
pip install -e .                                   # exposes `theseus` script
```

Run the CLI:

```bash
theseus run path/to/binary.exe                     # writes reports/report.json
theseus run binary.exe --deck reports/deck.html    # also render reveal.js deck
theseus run binary.exe --webhook https://soar/in   # push to SOAR
theseus deck reports/report.json -o deck.html      # render deck from existing report
theseus serve --port 8090                          # FastAPI ingest (requires fastapi+uvicorn+python-multipart, not in requirements.txt)
theseus gui                                        # DearPyGui frontend
```

Tests (pytest):

```bash
pytest                                             # all
pytest tests/test_orchestrator_extract.py -k extract_fenced_json   # single test
```

`tests/` runs without Ghidra/Anthropic — the only network-touching code (`orchestrator.analyze`, `HeadlessRunner`, `ToolRouter`) is not exercised; only pure helpers (`_extract_json`, `summarize_for_ticket`, `render_deck`) are tested.

Deck preview without running a binary:

```bash
python scripts/demo_deck.py                        # renders reports/demo_deck.html from synthetic report
```

There is no lint/format config in this repo.

## Required environment

Copy `.env.example` → `.env`. `PipelineConfig.from_env()` requires `GHIDRA_HOME`. `ANTHROPIC_MODEL` defaults to `claude-opus-4-7`. `GHIDRA_PROJECT_DIR` defaults to `./ghidra_projects`. Ports auto-pick via `find_free_port` if unset. `GHIDRASQL_BIN` may pin the ghidrasql executable path; otherwise PATH lookup.

`THESEUS_BACKEND` selects the LLM provider:
- `anthropic` (default) — direct Anthropic API, requires `ANTHROPIC_API_KEY`, pay per token.
- `claude_code` — Claude Agent SDK via `claude` CLI OAuth (Max/Pro subscription). Run `claude login` once; no API key needed.

## Architecture

```
CLI / GUI / FastAPI  ──► orchestrator.analyze(binary)
                              │
                              ├─► HeadlessRunner   (subprocess: analyzeHeadless.bat -postScript LibGhidraHeadlessServer.java)
                              │       └─► libghidra HTTP :180xx
                              │
                              ├─► GhidrasqlRunner  (subprocess: ghidrasql --url <libghidra> --http --max-runtime 0)
                              │       └─► ghidrasql HTTP :80xx  (POST /query, raw SQL body)
                              │
                              └─► for phase in [triage, capability, ioc, verdict]:
                                      backend.run_phase(...)  ──► one of:
                                          - AnthropicBackend     (Anthropic Messages API + ToolRouter)
                                          - ClaudeCodeBackend    (Claude Agent SDK + in-process MCP server)
                                          - (future) OpenAI-compatible local model
                                      Tool exposed: ghidrasql_query → POST {ghidrasql}/query (raw SQL)
```

Key invariants when editing:

- **Phases are sequential and feed forward.** `capability` and `ioc` get `triage` as `prior_context`; `verdict` gets all three. Re-ordering phases breaks the dependency graph. Adding a phase means updating both `phase_prompts` and the `prior` dict in `orchestrator.analyze`.
- **Each phase ends in JSON.** `_extract_json` (in `orchestrator.py`) parses fenced ```json``` blocks first, then falls back to brace-matching the largest object/array. The system prompt (`prompts/system.md`) instructs the model to emit JSON only — keep it that way; don't add prose-friendly response shaping.
- **LLM backends are pluggable.** All live under `src/theseus/backends/`. `get_backend(name, ghidrasql_url, libghidra_url, model)` returns a context manager implementing `run_phase(...)`. Adding a backend means (1) implement the method, (2) register the name in `backends/base.py:get_backend`. AnthropicBackend uses `tools.py:ToolRouter`; ClaudeCodeBackend ships its own in-process MCP tool definition pointing at the same ghidrasql URL.
- **Tool schemas live in `tools.py` as `TOOL_SCHEMAS`.** Only Anthropic-style schemas; ClaudeCodeBackend defines the same tool inline via `@tool` for the Agent SDK. If you add or rename a tool, update both. Real ghidrasql `/query` endpoint expects **raw SQL in the request body** (not JSON) and returns `{"results":[{"columns":[...], "rows":[...]}]}`.
- **libghidra `/rpc` is protobuf**, not JSON. Theseus does not call it directly — agent uses the `pseudocode` ghidrasql table instead.
- **Ghidra startup is slow.** `HeadlessRunner.startup_timeout = 180s`. Don't tighten it without checking large-binary auto-analysis times. Project name is unique per run (`theseus-<uuid8>`) and `-deleteProject` cleans up on exit.
- **`prompts/*.md` are loaded at runtime** from `<repo>/prompts/`, resolved via `Path(__file__).resolve().parents[2]` from `orchestrator.py`. Don't move the package depth without updating that.
- **Report shape is contract.** `schema/report.schema.json` is the authority. Fields consumed by `deck.py` (Jinja template), `soc.summarize_for_ticket`, and the GUI must stay aligned with the schema's required/enum constraints (`verdict.label` ∈ {clean, suspicious, vulnerable, malicious, unknown}; `verdict.soc_action` ∈ {ignore, enrich, monitor, escalate, quarantine}; `iocs[].type` enum; etc.). `vulnerable` is the BYOVD / dual-use bucket — weapon-grade primitive with no payload of its own.
- **Pricing in `_PRICING_PER_MTOK`** is hard-coded per-million-token USD. Update when Anthropic pricing changes; `_estimate_cost_usd` matches by model name prefix.

## GUI threading

`gui.py` runs the pipeline on a daemon thread and ships events via a thread-safe `queue.Queue` (`EVENTS`). The main loop drains it once per frame via `_frame_pump`. **Never touch `dpg.*` from the worker thread** — emit an event and handle it in `_handle_event` instead. `STATE` is a shared dict; mutate from worker only for fields not read by `_handle_event` mid-flight (currently safe because `_handle_event` only reads `STATE["report"]` after the `done` event).

`gui_drop.py` enables OS drag-drop on the DearPyGui viewport (Windows-only; no-op elsewhere). It subclasses the viewport HWND's WndProc via Win32 `SetWindowLongPtr`. The new `WNDPROC` callback and the original proc pointer are kept in **module globals** (`_new_wndproc_ref`, `_old_wndproc`) — without those refs, ctypes garbage-collects the trampoline and Windows crashes calling a freed pointer. Don't move them to function scope.

## Sample data safety

Never execute analyzed binaries. The system prompt instructs the model not to fetch observed URLs/IPs — keep that guardrail when editing prompts. The README points users at MalwareBazaar; analysis is static-only and assumed to run inside an isolated VM.
