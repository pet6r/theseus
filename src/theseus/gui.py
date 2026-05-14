"""Theseus DearPyGui frontend.

Drop-zone + tabs (Pipeline / Verdict / MITRE / IoCs / Triage / Cost / SOC).
Threaded calls into the orchestrator. Live progress + verdict + reveal.js
deck launch. Pipeline tab renders the Conti et al. VizSEC 2008 byte panels
(byteview, byte presence, strings, hex) from `byteviz.py`.

Run via: `theseus gui` or `python -m theseus.gui`.
"""

from __future__ import annotations

import json
import os
import queue
import textwrap
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

import dearpygui.dearpygui as dpg

from .byteviz import byte_presence_texture, byteview_texture, extract_strings
from .deck import render_deck
from .hex_view import hexdump, human_size
from .orchestrator import PipelineCallbacks, PipelineConfig, analyze
from .soc import push_to_webhook


# ---------------------------------------------------------------------------
# Cross-thread event queue
# ---------------------------------------------------------------------------

EVENTS: "queue.Queue[dict[str, Any]]" = queue.Queue()
STATE: dict[str, Any] = {
    "running": False,
    "current_binary": None,
    "report": None,
    "deck_path": None,
    "log": [],
    "phase_progress": {"triage": 0.0, "capability": 0.0, "ioc": 0.0, "verdict": 0.0},
    "current_phase": None,
    "start_monotonic": 0.0,
    "last_tokens": (0, 0),
}

PHASES = ("triage", "capability", "ioc", "verdict")
PHASE_BAR_TAGS = {p: f"p_{p}" for p in PHASES}


def _emit(kind: str, **payload: Any) -> None:
    EVENTS.put({"kind": kind, **payload})


def _overall_progress() -> float:
    return sum(STATE["phase_progress"].values()) / len(PHASES)


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def _worker(binary_path: Path) -> None:
    STATE["running"] = True
    STATE["current_binary"] = str(binary_path)
    STATE["report"] = None

    # File metadata + hex dump first — instant feedback while Ghidra spins up.
    sample: bytes = b""
    try:
        size = binary_path.stat().st_size
        with open(binary_path, "rb") as f:
            # Read up to 1 MB so byteview can fill its 1024 x 1023 texture
            # at near 1 pixel per byte for typical executables; strings
            # extractor benefits from the larger window too.
            sample = f.read(1024 * 1024)
        head = sample[:4096]
        _emit(
            "meta",
            name=binary_path.name,
            size=size,
            head_bytes=head,
        )
        _emit("hex", text=hexdump(head, max_bytes=4096))
    except Exception as e:  # noqa: BLE001
        _emit("log", msg=f"[warn] meta/hex failed: {e}")

    # Byteview / byte presence / strings panels (Conti et al. VizSEC 2008).
    if sample:
        try:
            bv, _, _ = byteview_texture(sample, width=1024, height=1023)
            _emit("byteview", data=bv)
            bp, _, _ = byte_presence_texture(sample)
            _emit("byte_presence", data=bp)
            s = extract_strings(sample, min_len=4, max_strings=500)
            _emit("strings", rows=s)
        except Exception as e:  # noqa: BLE001
            _emit("log", msg=f"[warn] byteviz failed: {e}")


    cb = PipelineCallbacks(
        on_log=lambda m: _emit("log", msg=m),
        on_phase_start=lambda p: _emit("phase_start", phase=p),
        on_phase_progress=lambda p, v: _emit("phase_progress", phase=p, value=v),
        on_phase_done=lambda p, payload: _emit("phase_done", phase=p, payload=payload),
        on_token=lambda i, o: _emit("token", input=i, output=o),
    )

    try:
        cfg = PipelineConfig.from_env()
    except KeyError as e:
        _emit("error", msg=f"Missing env var: {e}. Copy .env.example to .env and fill it in.")
        STATE["running"] = False
        return

    try:
        report = analyze(binary_path, config=cfg, callbacks=cb)
    except Exception as e:  # noqa: BLE001
        _emit("error", msg=f"Pipeline failed: {e}")
        STATE["running"] = False
        return

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    sha8 = (report.get("meta", {}).get("sha256") or "unknown")[:8]
    report_path = out_dir / f"report_{sha8}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    deck_path = out_dir / f"deck_{sha8}.html"
    render_deck(report, deck_path)
    STATE["deck_path"] = str(deck_path)
    STATE["report"] = report

    _emit("done", report_path=str(report_path), deck_path=str(deck_path))
    STATE["running"] = False


# ---------------------------------------------------------------------------
# Event dispatcher (runs on GUI thread via _frame_pump)
# ---------------------------------------------------------------------------

# Soft wrap widths in characters. Picked to match the Cascadia Mono 16px column
# sizes (log column ~1000px, reasoning column ~290px). Approximate — DPG
# does not give us widget pixel widths post-layout.
_LOG_WRAP = 120
_REASONING_WRAP = 110


def _wrap_text(text: str, width: int) -> str:
    """Wrap each line individually, preserving blank lines and existing breaks."""
    if not text:
        return text
    out: list[str] = []
    for ln in text.split("\n"):
        if not ln:
            out.append("")
        elif len(ln) <= width:
            out.append(ln)
        else:
            out.extend(textwrap.wrap(
                ln, width=width,
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
                drop_whitespace=False,
            ) or [""])
    return "\n".join(out)


_LOG_TAIL_LINES = 20


def _append_log(line: str) -> None:
    STATE["log"].append(_wrap_text(line, _LOG_WRAP))
    # Tail to the last N lines so the textbox never needs to scroll. New
    # entries push older ones off the top — naturally bottom-anchored.
    tail = "\n".join(STATE["log"][-_LOG_TAIL_LINES:])
    dpg.set_value("log", tail)


_VERDICT_PALETTE = {
    "clean": (61, 164, 107),      # corporate green
    "suspicious": (212, 168, 53),  # muted amber
    "vulnerable": (220, 130, 60),  # orange
    "malicious": (201, 48, 48),    # muted red
    "unknown": (154, 160, 166),    # cool grey
}


def _handle_event(ev: dict[str, Any]) -> None:
    kind = ev["kind"]

    if kind == "log":
        _append_log(ev["msg"])

    elif kind == "file_drop":
        _start_analysis(Path(ev["path"]))

    elif kind == "meta":
        if dpg.does_item_exist("stat_file"):
            dpg.set_value("stat_file", str(ev["name"]))
            dpg.set_value("stat_size", human_size(int(ev["size"])))

    elif kind == "hex":
        if dpg.does_item_exist("hex_dump"):
            dpg.set_value("hex_dump", ev["text"])

    elif kind == "byteview":
        if dpg.does_item_exist("byteview_tex"):
            dpg.set_value("byteview_tex", ev["data"])

    elif kind == "byte_presence":
        if dpg.does_item_exist("byte_presence_tex"):
            dpg.set_value("byte_presence_tex", ev["data"])

    elif kind == "strings":
        _refresh_strings_table(ev["rows"])

    elif kind == "phase_start":
        STATE["current_phase"] = ev["phase"]
        _append_log(f"[run] phase {ev['phase']} starting")

    elif kind == "phase_progress":
        STATE["phase_progress"][ev["phase"]] = float(ev["value"])
        tag = PHASE_BAR_TAGS.get(ev["phase"])
        if tag:
            dpg.set_value(tag, ev["value"])

    elif kind == "phase_done":
        STATE["phase_progress"][ev["phase"]] = 1.0
        tag = PHASE_BAR_TAGS.get(ev["phase"])
        if tag:
            dpg.set_value(tag, 1.0)
        _append_log(f"[ok]  phase {ev['phase']} done")

    elif kind == "token":
        STATE["last_tokens"] = (int(ev["input"]), int(ev["output"]))
        dpg.set_value("tok_in", f"input: {ev['input']:,}")
        dpg.set_value("tok_out", f"output: {ev['output']:,}")
        if dpg.does_item_exist("stat_tokens"):
            dpg.set_value(
                "stat_tokens",
                f"{ev['input']:,} in / {ev['output']:,} out",
            )

    elif kind == "done":
        report = STATE["report"] or {}
        verdict = report.get("verdict") or {}
        triage = report.get("triage") or {}
        caps = report.get("capabilities") or []
        iocs = report.get("iocs") or []
        cost = report.get("cost") or {}

        label = (verdict.get("label") or "unknown").lower()
        label_upper = (verdict.get("label") or "?").upper()
        score_str = f"{verdict.get('score', 0):.2f}"
        action_str = str(verdict.get("soc_action", "?"))
        verdict_color = _VERDICT_PALETTE.get(label, _VERDICT_PALETTE["unknown"])

        # Pipeline tab stat strip.
        if dpg.does_item_exist("stat_verdict"):
            dpg.set_value("stat_verdict", label_upper)
            dpg.configure_item("stat_verdict", color=verdict_color)
        if dpg.does_item_exist("stat_cost"):
            dpg.set_value("stat_cost", f"${cost.get('usd', 0):.4f}")
        if dpg.does_item_exist("stat_sha"):
            sha = (report.get("meta", {}).get("sha256") or "")[:12]
            dpg.set_value("stat_sha", sha or "--")

        # Verdict tab (full).
        dpg.set_value("verdict_label_big", label_upper)
        dpg.configure_item("verdict_label_big", color=verdict_color)
        dpg.set_value("verdict_score_big", score_str)
        dpg.set_value("verdict_action_big", action_str)
        dpg.set_value(
            "verdict_reasoning",
            _wrap_text(verdict.get("reasoning", ""), _REASONING_WRAP),
        )
        dpg.set_value("verdict_yara", verdict.get("yara_rule", "") or "")

        dpg.set_value("triage_summary", json.dumps(triage, indent=2)[:4000])

        _refresh_mitre_plot(caps)
        _refresh_mitre_details(caps)
        _refresh_ioc_table(iocs)
        _refresh_cost_plots(cost)

        dpg.set_value("cost_usd", f"Cost: ${cost.get('usd', 0):.4f}")
        dpg.set_value("cost_breakdown", json.dumps(cost, indent=2))

        _append_log(f"[done] report={ev['report_path']} deck={ev['deck_path']}")
        dpg.configure_item("menu_open_deck", enabled=True)
        dpg.configure_item("menu_open_binary", enabled=True)


    elif kind == "error":
        _append_log(f"[err] {ev['msg']}")
        dpg.configure_item("menu_open_binary", enabled=True)


def _drain_events() -> None:
    try:
        while True:
            ev = EVENTS.get_nowait()
            _handle_event(ev)
    except queue.Empty:
        pass


# ---------------------------------------------------------------------------
# Plot / table refreshers
# ---------------------------------------------------------------------------

def _refresh_mitre_plot(caps: list[dict]) -> None:
    if not caps:
        return
    sorted_caps = sorted(caps, key=lambda c: c.get("confidence", 0), reverse=True)[:15]
    labels = [c.get("technique_id", "?") for c in sorted_caps]
    values = [c.get("confidence", 0.0) for c in sorted_caps]
    indices = list(range(len(labels)))

    dpg.delete_item("mitre_series", children_only=False)
    dpg.set_axis_ticks("mitre_x_axis", tuple((lbl, i) for i, lbl in enumerate(labels)))
    dpg.add_bar_series(
        indices, values,
        label="confidence", parent="mitre_y_axis", tag="mitre_series", weight=0.6,
    )
    dpg.fit_axis_data("mitre_y_axis")
    dpg.fit_axis_data("mitre_x_axis")


def _attack_url(technique_id: str) -> str:
    """Build the MITRE ATT&CK reference URL for a `Txxxx[.yyy]` id."""
    tid = (technique_id or "").strip().upper()
    if not tid.startswith("T"):
        return "https://attack.mitre.org/techniques/"
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def _refresh_mitre_details(caps: list[dict]) -> None:
    """Render a per-technique details card below the chart, sorted by confidence."""
    if not dpg.does_item_exist("mitre_details"):
        return
    for child in dpg.get_item_children("mitre_details", 1) or []:
        dpg.delete_item(child)
    if not caps:
        dpg.add_text(
            "No techniques detected.",
            parent="mitre_details", color=_TEXT_DIM,
        )
        return
    sorted_caps = sorted(
        caps, key=lambda c: float(c.get("confidence", 0.0) or 0.0), reverse=True,
    )
    for cap in sorted_caps:
        tid = str(cap.get("technique_id", "?"))
        name = str(cap.get("name", ""))
        tactic = str(cap.get("tactic", ""))
        conf = float(cap.get("confidence", 0.0) or 0.0)
        ev = cap.get("evidence") or []
        url = _attack_url(tid)

        header_parts = [tid]
        if name:
            header_parts.append(name)
        header_parts.append(f"conf {conf:.2f}")
        if tactic:
            header_parts.append(f"[{tactic}]")
        header = "   ".join(header_parts)

        with dpg.collapsing_header(
            label=header, parent="mitre_details", default_open=True,
        ):
            with dpg.group(horizontal=True):
                dpg.add_text("Source:", color=_TEXT_DIM)
                # readonly input_text is the only DPG widget whose text is
                # selectable + copyable. width=-110 leaves room for the button.
                dpg.add_input_text(
                    default_value=url, readonly=True, width=-110,
                )
                dpg.add_button(
                    label="open",
                    user_data=url,
                    callback=lambda _s, _a, u: webbrowser.open(u),
                )
            if ev:
                dpg.add_text("Evidence:", color=_TEXT_DIM)
                for e in ev[:8]:
                    addr = str(e.get("address", ""))
                    fn = str(e.get("function", ""))
                    snip = str(e.get("snippet", ""))
                    prefix = f"{addr}"
                    if fn:
                        prefix += f" ({fn})"
                    line = f"  {prefix}: {snip}" if snip else f"  {prefix}"
                    dpg.add_text(_wrap_text(line, 110), color=_TEXT)
            dpg.add_spacer(height=4)


def _refresh_cost_plots(cost: dict) -> None:
    """Bar plot of USD per phase (sorted desc) and a tokens-per-phase plot."""
    phases = cost.get("phases") or {}
    if not phases:
        return
    items = sorted(
        phases.items(),
        key=lambda kv: float(kv[1].get("cost_usd", 0.0) or 0.0),
        reverse=True,
    )
    labels = [name for name, _ in items]
    indices = list(range(len(labels)))
    usds = [float(v.get("cost_usd", 0.0) or 0.0) for _, v in items]
    in_toks = [int(v.get("input_tokens", 0) or 0) for _, v in items]
    out_toks = [int(v.get("output_tokens", 0) or 0) for _, v in items]

    if dpg.does_item_exist("cost_series"):
        dpg.delete_item("cost_series")
    dpg.set_axis_ticks(
        "cost_x_axis", tuple((lbl, i) for i, lbl in enumerate(labels)),
    )
    dpg.add_bar_series(
        indices, usds, label="usd", parent="cost_y_axis",
        tag="cost_series", weight=0.6,
    )
    dpg.fit_axis_data("cost_x_axis")
    dpg.fit_axis_data("cost_y_axis")

    if dpg.does_item_exist("tok_series_in"):
        dpg.delete_item("tok_series_in")
    if dpg.does_item_exist("tok_series_out"):
        dpg.delete_item("tok_series_out")
    dpg.set_axis_ticks(
        "tok_x_axis", tuple((lbl, i) for i, lbl in enumerate(labels)),
    )
    in_x = [i - 0.18 for i in indices]
    out_x = [i + 0.18 for i in indices]
    dpg.add_bar_series(
        in_x, in_toks, label="input", parent="tok_y_axis",
        tag="tok_series_in", weight=0.32,
    )
    dpg.add_bar_series(
        out_x, out_toks, label="output", parent="tok_y_axis",
        tag="tok_series_out", weight=0.32,
    )
    dpg.fit_axis_data("tok_x_axis")
    dpg.fit_axis_data("tok_y_axis")


def _refresh_strings_table(rows: list[tuple[int, str]]) -> None:
    """Repopulate the byte-level strings table on the Pipeline tab."""
    if not dpg.does_item_exist("strings_table"):
        return
    for child in dpg.get_item_children("strings_table", 1) or []:
        dpg.delete_item(child)
    for offset, text in rows[:500]:
        with dpg.table_row(parent="strings_table"):
            dpg.add_text(f"0x{offset:08X}", color=_TEXT_DIM)
            # Truncate so a single very long string can't blow out the cell.
            dpg.add_text(text[:160])


def _refresh_ioc_table(iocs: list[dict]) -> None:
    for child in dpg.get_item_children("ioc_table", 1) or []:
        dpg.delete_item(child)
    for ioc in iocs[:200]:
        with dpg.table_row(parent="ioc_table"):
            dpg.add_text(ioc.get("type", "?"))
            dpg.add_text(ioc.get("value", ""))
            dpg.add_text(ioc.get("source_address", ""))
            dpg.add_text(str(ioc.get("xref_count", "")))
            dpg.add_text(f"{ioc.get('confidence', 0):.2f}")


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

def _on_file_picked(_sender, app_data: dict) -> None:
    selections = app_data.get("selections") or {}
    if not selections:
        return
    path = Path(next(iter(selections.values())))
    _start_analysis(path)


def _start_analysis(path: Path) -> None:
    if STATE["running"]:
        _append_log("already running; wait for current job")
        return
    for tag in PHASE_BAR_TAGS.values():
        dpg.set_value(tag, 0.0)
    STATE["phase_progress"] = {p: 0.0 for p in PHASES}
    STATE["current_phase"] = None
    STATE["start_monotonic"] = time.monotonic()
    STATE["last_tokens"] = (0, 0)

    # Stat strip resets.
    for tag, val in [
        ("stat_file", path.name),
        ("stat_size", "..."),
        ("stat_sha", "..."),
        ("stat_elapsed", "0:00"),
        ("stat_tokens", "0 in / 0 out"),
        ("stat_cost", "$0.0000"),
        ("stat_verdict", "..."),
    ]:
        if dpg.does_item_exist(tag):
            dpg.set_value(tag, val)
    if dpg.does_item_exist("stat_verdict"):
        dpg.configure_item("stat_verdict", color=_TEXT_DIM)

    # Verdict tab resets.
    dpg.set_value("verdict_label_big", "...")
    dpg.configure_item("verdict_label_big", color=_TEXT)
    dpg.set_value("verdict_score_big", "...")
    dpg.set_value("verdict_action_big", "...")
    dpg.set_value("verdict_reasoning", "")
    dpg.set_value("verdict_yara", "")

    # Hex viewer reset.
    if dpg.does_item_exist("hex_dump"):
        dpg.set_value("hex_dump", "(reading...)")

    # Byteview / byte presence / strings reset. Texture dims must match
    # the registry allocations exactly.
    if dpg.does_item_exist("byteview_tex"):
        dpg.set_value("byteview_tex", [0.0] * (1024 * 1023 * 4))
    if dpg.does_item_exist("byte_presence_tex"):
        dpg.set_value("byte_presence_tex", [0.0] * (1024 * 170 * 4))
    if dpg.does_item_exist("strings_table"):
        for child in dpg.get_item_children("strings_table", 1) or []:
            dpg.delete_item(child)

    STATE["log"] = []
    dpg.set_value("log", "")
    dpg.configure_item("menu_open_binary", enabled=False)
    dpg.configure_item("menu_open_deck", enabled=False)

    t = threading.Thread(target=_worker, args=(path,), daemon=True)
    t.start()


def _open_deck(_s, _a) -> None:
    if STATE["deck_path"]:
        webbrowser.open(f"file://{Path(STATE['deck_path']).resolve()}")


def _webhook_send(_s, _a) -> None:
    url = dpg.get_value("webhook_url").strip()
    if not url:
        _append_log("no webhook URL configured")
        return
    if not STATE["report"]:
        _append_log("no report to send")
        return
    try:
        resp = push_to_webhook(url, STATE["report"])
        _append_log(f"webhook 200: {resp}")
    except Exception as e:  # noqa: BLE001
        _append_log(f"webhook failed: {e}")


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

# Corporate palette: black / dark-grey / light-grey / white plus a muted
# green accent. No neon. Designed to read well in a SOC analyst's eyes for
# long sessions and to look at home next to Splunk / Jira / GitHub UIs.
_BG = (14, 17, 22)         # near-black
_PANEL = (26, 31, 37)      # dark grey panel
_PANEL_HI = (42, 48, 56)   # medium grey
_BORDER = (58, 66, 76)     # border grey
_TEXT = (232, 237, 240)    # near-white text
_TEXT_DIM = (154, 160, 166)  # cool grey
_ACCENT = (61, 164, 107)   # corporate green (matches Atlassian green-ish)
_ACCENT_DIM = (31, 105, 67)
_SECONDARY = (200, 207, 213)  # light grey (secondary highlights)
_ALERT = (201, 48, 48)     # muted red


def _build_theme() -> int:
    with dpg.theme() as tag:
        with dpg.theme_component(dpg.mvAll):
            for col, val in [
                (dpg.mvThemeCol_WindowBg, _BG),
                (dpg.mvThemeCol_ChildBg, _PANEL),
                (dpg.mvThemeCol_PopupBg, _PANEL),
                (dpg.mvThemeCol_MenuBarBg, _PANEL),
                (dpg.mvThemeCol_FrameBg, _PANEL),
                (dpg.mvThemeCol_FrameBgHovered, _PANEL_HI),
                (dpg.mvThemeCol_FrameBgActive, _BORDER),
                (dpg.mvThemeCol_Border, _BORDER),
                (dpg.mvThemeCol_Text, _TEXT),
                (dpg.mvThemeCol_TextDisabled, _TEXT_DIM),
                (dpg.mvThemeCol_Button, _PANEL_HI),
                (dpg.mvThemeCol_ButtonHovered, _ACCENT),
                (dpg.mvThemeCol_ButtonActive, _ACCENT_DIM),
                (dpg.mvThemeCol_Tab, _PANEL),
                (dpg.mvThemeCol_TabHovered, _ACCENT),
                (dpg.mvThemeCol_TabActive, _ACCENT_DIM),
                (dpg.mvThemeCol_TabUnfocused, _PANEL),
                (dpg.mvThemeCol_TabUnfocusedActive, _PANEL_HI),
                (dpg.mvThemeCol_TitleBg, _BG),
                (dpg.mvThemeCol_TitleBgActive, _PANEL),
                (dpg.mvThemeCol_TitleBgCollapsed, _BG),
                (dpg.mvThemeCol_Header, _PANEL_HI),
                (dpg.mvThemeCol_HeaderHovered, _ACCENT),
                (dpg.mvThemeCol_HeaderActive, _ACCENT_DIM),
                (dpg.mvThemeCol_PlotHistogram, _ACCENT),
                (dpg.mvThemeCol_PlotHistogramHovered, _ACCENT_DIM),
                (dpg.mvThemeCol_PlotLines, _ACCENT),
                (dpg.mvThemeCol_PlotLinesHovered, _ACCENT_DIM),
                (dpg.mvThemeCol_ScrollbarBg, _BG),
                (dpg.mvThemeCol_ScrollbarGrab, _PANEL_HI),
                (dpg.mvThemeCol_ScrollbarGrabHovered, _ACCENT),
                (dpg.mvThemeCol_ScrollbarGrabActive, _ACCENT),
                (dpg.mvThemeCol_Separator, _BORDER),
                (dpg.mvThemeCol_SeparatorHovered, _ACCENT),
                (dpg.mvThemeCol_CheckMark, _ACCENT),
                (dpg.mvThemeCol_SliderGrab, _ACCENT),
                (dpg.mvThemeCol_SliderGrabActive, _ACCENT_DIM),
                (dpg.mvThemeCol_ResizeGrip, _BORDER),
                (dpg.mvThemeCol_ResizeGripHovered, _ACCENT),
                (dpg.mvThemeCol_ResizeGripActive, _ACCENT_DIM),
                (dpg.mvThemeCol_TableHeaderBg, _PANEL_HI),
                (dpg.mvThemeCol_TableBorderStrong, _BORDER),
                (dpg.mvThemeCol_TableBorderLight, _PANEL_HI),
                (dpg.mvThemeCol_TableRowBg, _PANEL),
                (dpg.mvThemeCol_TableRowBgAlt, _BG),
            ]:
                dpg.add_theme_color(col, val)
            for sty, *vals in [
                (dpg.mvStyleVar_WindowPadding, 8, 8),
                (dpg.mvStyleVar_FramePadding, 6, 4),
                (dpg.mvStyleVar_ItemSpacing, 6, 4),
                (dpg.mvStyleVar_ItemInnerSpacing, 4, 4),
                # Catppuccin-style soft rounding everywhere.
                (dpg.mvStyleVar_FrameRounding, 6),
                (dpg.mvStyleVar_GrabRounding, 6),
                (dpg.mvStyleVar_TabRounding, 6),
                (dpg.mvStyleVar_ScrollbarRounding, 10),
                (dpg.mvStyleVar_ChildRounding, 10),
                (dpg.mvStyleVar_PopupRounding, 8),
                (dpg.mvStyleVar_WindowBorderSize, 0),
                (dpg.mvStyleVar_ChildBorderSize, 1),
                (dpg.mvStyleVar_TabBorderSize, 0),
                (dpg.mvStyleVar_IndentSpacing, 16),
            ]:
                dpg.add_theme_style(sty, *vals)
    return tag


def _build_progress_theme() -> int:
    """Empty progress bars need a visibly-lighter track than the panel bg."""
    with dpg.theme() as tag:
        with dpg.theme_component(dpg.mvProgressBar):
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, _PANEL_HI)
            dpg.add_theme_color(dpg.mvThemeCol_PlotHistogram, _ACCENT)
    return tag


def _build_tight_card_theme() -> int:
    """Per-card theme that drops inner padding so big images fill the card."""
    with dpg.theme() as tag:
        with dpg.theme_component(dpg.mvChildWindow):
            dpg.add_theme_style(dpg.mvStyleVar_WindowPadding, 6, 4)
            dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 4, 2)
    return tag


def _build_accent_button_theme() -> int:
    """Used to make the primary 'drop' button stand out in accent color."""
    with dpg.theme() as tag:
        with dpg.theme_component(dpg.mvButton):
            dpg.add_theme_color(dpg.mvThemeCol_Button, _ACCENT_DIM)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, _ACCENT)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, _BORDER)
            dpg.add_theme_color(dpg.mvThemeCol_Text, _BG)
            dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 14, 10)
    return tag


# Fonts. We try Cascadia Mono (ships with modern Windows) first, then fall back
# to Consolas and Segoe UI. Two sizes: body for general use, display for the
# verdict label and headings.
_FONT_BODY: int | None = None
_FONT_DISPLAY: int | None = None
_FONT_TITLE: int | None = None

_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\CascadiaMono.ttf",
    r"C:\Windows\Fonts\CascadiaCode.ttf",
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\segoeui.ttf",
]


def _build_fonts() -> None:
    """Register fonts. Caller must invoke before `bind_font`."""
    global _FONT_BODY, _FONT_DISPLAY, _FONT_TITLE
    chosen: str | None = None
    for path in _FONT_CANDIDATES:
        if Path(path).exists():
            chosen = path
            break
    if chosen is None:
        return
    with dpg.font_registry():
        _FONT_BODY = dpg.add_font(chosen, 16)
        _FONT_DISPLAY = dpg.add_font(chosen, 26)
        _FONT_TITLE = dpg.add_font(chosen, 20)


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

def _build_ui() -> None:
    # Texture registry holds the byteview + byte-presence raster targets.
    # `add_image` collapses height when the texture is perfectly square, so
    # byteview is allocated 256 x 255 (visually square, aspect 1.004) to
    # dodge that DPG bug. Byte presence is wide-and-short (1024 x 170) so
    # aspect-locked rendering produces the strip we want.
    with dpg.texture_registry():
        # High-res texture so the expanded modal stays crisp at ~700px.
        dpg.add_raw_texture(
            1024, 1023, [0.0] * (1024 * 1023 * 4),
            format=dpg.mvFormat_Float_rgba, tag="byteview_tex",
        )
        dpg.add_raw_texture(
            1024, 170, [0.0] * (1024 * 170 * 4),
            format=dpg.mvFormat_Float_rgba, tag="byte_presence_tex",
        )

    # Expanded byte plot — hidden modal window, shown via the "expand"
    # button on the Pipeline tab. Texture is shared with the inline panel
    # so it updates in real time as the worker emits.
    with dpg.window(
        label="Byte Plot — expanded",
        tag="byteplot_expanded",
        modal=True, show=False,
        width=740, height=760,
        no_collapse=True,
    ):
        dpg.add_text(
            "Each byte rendered as one pixel. "
            "0x00 grey, control bytes red, ASCII green, high bytes white.",
            color=_TEXT_DIM,
        )
        dpg.add_image(
            "byteview_tex",
            width=700, height=697,  # matches texture aspect 256:255
        )
        dpg.add_spacer(height=6)
        dpg.add_button(
            label="close",
            callback=lambda: dpg.configure_item("byteplot_expanded", show=False),
        )

    with dpg.file_dialog(
        directory_selector=False,
        show=False,
        callback=_on_file_picked,
        tag="file_picker",
        width=700, height=400,
    ):
        dpg.add_file_extension(".*")
        dpg.add_file_extension(".exe", color=(200, 200, 200))
        dpg.add_file_extension(".dll", color=(200, 200, 200))
        dpg.add_file_extension(".so", color=(160, 162, 160))
        dpg.add_file_extension(".elf", color=(160, 162, 160))

    progress_theme = _build_progress_theme()
    tight_card_theme = _build_tight_card_theme()

    # Viewport-level menu bar — corporate-standard "File / View / Help" feel.
    with dpg.viewport_menu_bar():
        with dpg.menu(label="File"):
            dpg.add_menu_item(
                label="Open binary...",
                tag="menu_open_binary",
                callback=lambda: dpg.show_item("file_picker"),
            )
            dpg.add_menu_item(
                label="Open deck",
                tag="menu_open_deck",
                callback=_open_deck,
                enabled=False,
            )
            dpg.add_separator()
            dpg.add_menu_item(
                label="Exit",
                callback=lambda: dpg.stop_dearpygui(),
            )

    with dpg.window(
        label="Theseus", tag="main_window",
        no_title_bar=True, no_move=True, no_resize=True,
        no_bring_to_front_on_focus=True,
    ):
        with dpg.tab_bar():
            # --- Pipeline ------------------------------------------------
            #
            # CAN-Explorer-inspired split: stat strip on top, cube + hex
            # side-by-side in the main pane, compact phase bars middle,
            # log strip on bottom.
            with dpg.tab(label="Pipeline"):
                # Top stat strip — two inline rows so the full filename can
                # be shown without crowding the SIZE/SHA/.../VERDICT pills.
                with dpg.child_window(
                    width=-1, height=70, border=True,
                    no_scrollbar=True, no_scroll_with_mouse=True,
                ):
                    with dpg.group(horizontal=True):
                        dpg.add_text("FILE", color=_TEXT_DIM)
                        dpg.add_text("--", tag="stat_file", color=_TEXT)
                    with dpg.group(horizontal=True):
                        for hdr, val_tag, val_color in [
                            ("SIZE", "stat_size", _TEXT),
                            ("SHA", "stat_sha", _TEXT),
                            ("ELAPSED", "stat_elapsed", _TEXT),
                            ("TOKENS", "stat_tokens", _TEXT),
                            ("COST", "stat_cost", _ACCENT),
                            ("VERDICT", "stat_verdict", _TEXT_DIM),
                        ]:
                            dpg.add_text(hdr, color=_TEXT_DIM)
                            dpg.add_text("--", tag=val_tag, color=val_color)
                            dpg.add_spacer(width=14)

                # 2x2 panel grid (Conti et al. VizSEC 2008, page 9 / Fig 1):
                # top row    -> byte plot   | byte presence
                # bottom row -> strings     | hex / ascii
                # Byte plot keeps a square texture; aspect-locked `add_image`
                # gives 170 x 170. Byte presence uses a 1024 x 170 texture so
                # the same aspect lock produces a wide-and-short render.
                # Each image lives inside a no-border child_window with
                # explicit pixel dimensions — this forces DPG to give it a
                # bounded canvas instead of clamping height to something
                # smaller.
                # Both panels: texture is allocated wide-and-short so
                # aspect-locked `add_image` gives the render proportions we
                # want. Byte plot uses a 4-wide column replication of the
                # 256-byte rows, byte presence does the same.
                with dpg.group(horizontal=True):
                    with dpg.child_window(
                        tag="byteplot_card",
                        width=190, height=210, border=True,
                        no_scrollbar=True, no_scroll_with_mouse=True,
                    ):
                        with dpg.group(horizontal=True):
                            dpg.add_text("BYTE PLOT", color=_TEXT_DIM)
                            dpg.add_button(
                                label="expand",
                                callback=lambda: dpg.configure_item(
                                    "byteplot_expanded", show=True,
                                ),
                            )
                        dpg.add_image(
                            "byteview_tex",
                            tag="byteview_img",
                            width=170, height=170,
                        )
                    dpg.add_spacer(width=6)
                    with dpg.child_window(
                        tag="bytepresence_card",
                        width=-1, height=210, border=True,
                        no_scrollbar=True, no_scroll_with_mouse=True,
                    ):
                        dpg.add_text("BYTE PRESENCE  (256 vals x rows)", color=_TEXT_DIM)
                        dpg.add_image(
                            "byte_presence_tex",
                            tag="byte_presence_img",
                            width=960, height=170,
                        )

                dpg.add_spacer(height=6)

                # Strings + Hex on the same row, 50/50 widths. Widths are
                # finalised by `_on_viewport_resize` so they track window
                # resizes.
                with dpg.group(horizontal=True):
                    with dpg.child_window(
                        tag="strings_card",
                        width=580, height=280, border=True,
                        no_scrollbar=True, no_scroll_with_mouse=True,
                    ):
                        with dpg.group(horizontal=True):
                            dpg.add_text("STRINGS", color=_TEXT_DIM)
                            dpg.add_spacer(width=10)
                            dpg.add_text(">= 4 printable ASCII", color=_TEXT_DIM)
                        with dpg.table(
                            tag="strings_table",
                            header_row=True,
                            freeze_rows=1,
                            scrollY=True,
                            clipper=True,
                            policy=dpg.mvTable_SizingStretchProp,
                            borders_innerH=True,
                            borders_outerH=True,
                            borders_innerV=True,
                            resizable=True,
                            row_background=True,
                            height=-1,
                        ):
                            dpg.add_table_column(
                                label="offset", init_width_or_weight=0.24,
                            )
                            dpg.add_table_column(
                                label="string", init_width_or_weight=0.76,
                            )
                    dpg.add_spacer(width=6)
                    with dpg.child_window(
                        tag="hex_card",
                        width=580, height=280, border=True,
                    ):
                        with dpg.group(horizontal=True):
                            dpg.add_text("HEX", color=_TEXT_DIM)
                            dpg.add_spacer(width=8)
                            dpg.add_text(
                                "(first 4 KB of file)", color=_TEXT_DIM,
                            )
                        dpg.add_input_text(
                            tag="hex_dump",
                            multiline=True, readonly=True,
                            default_value="(drop a binary to view header bytes)",
                            width=-1, height=-1,
                        )

                dpg.add_spacer(height=4)

                # Phase bars in a 2x2 grid: triage | capability on top,
                # ioc | verdict below. Table handles equal-width column
                # sizing; bars are tall enough for the overlay label to
                # render without clipping in Cascadia Mono.
                with dpg.child_window(
                    width=-1, height=84, border=True,
                    no_scrollbar=True, no_scroll_with_mouse=True,
                ):
                    with dpg.table(
                        header_row=False,
                        policy=dpg.mvTable_SizingStretchSame,
                        no_pad_innerX=False,
                    ):
                        dpg.add_table_column()
                        dpg.add_table_column()
                        rows = [PHASES[0:2], PHASES[2:4]]
                        for row_phases in rows:
                            with dpg.table_row():
                                for p in row_phases:
                                    dpg.add_progress_bar(
                                        tag=PHASE_BAR_TAGS[p],
                                        default_value=0, overlay=p,
                                        width=-1, height=26,
                                    )
                                    dpg.bind_item_theme(
                                        PHASE_BAR_TAGS[p], progress_theme,
                                    )

                dpg.add_spacer(height=4)

                # Log strip — bordered textbox holding the most recent log
                # lines. We tail the buffer in `_append_log` so the visible
                # content always fits and the textbox never needs to scroll.
                with dpg.child_window(
                    width=-1, height=-1, border=True,
                    no_scrollbar=True, no_scroll_with_mouse=True,
                ):
                    dpg.add_text("LOG", color=_TEXT_DIM)
                    dpg.add_spacer(height=4)
                    dpg.add_input_text(
                        tag="log",
                        multiline=True, readonly=True,
                        width=-1, height=-1,
                    )

            # --- Verdict -------------------------------------------------
            with dpg.tab(label="Verdict"):
                with dpg.group(horizontal=True):
                    with dpg.group():
                        dpg.add_text("VERDICT", color=_TEXT_DIM)
                        verdict_label_big = dpg.add_text(
                            "...", tag="verdict_label_big", color=_TEXT,
                        )
                        if _FONT_DISPLAY is not None:
                            dpg.bind_item_font(verdict_label_big, _FONT_DISPLAY)
                    dpg.add_spacer(width=40)
                    with dpg.group():
                        dpg.add_text("SCORE", color=_TEXT_DIM)
                        score_item = dpg.add_text(
                            "...", tag="verdict_score_big", color=_TEXT,
                        )
                        if _FONT_TITLE is not None:
                            dpg.bind_item_font(score_item, _FONT_TITLE)
                    dpg.add_spacer(width=40)
                    with dpg.group():
                        dpg.add_text("SOC ACTION", color=_TEXT_DIM)
                        action_item = dpg.add_text(
                            "...", tag="verdict_action_big", color=_TEXT,
                        )
                        if _FONT_TITLE is not None:
                            dpg.bind_item_font(action_item, _FONT_TITLE)
                dpg.add_spacer(height=10)
                dpg.add_separator()
                dpg.add_spacer(height=8)
                dpg.add_text("REASONING", color=_TEXT_DIM)
                dpg.add_input_text(
                    tag="verdict_reasoning",
                    multiline=True, readonly=True,
                    width=-1, height=380,
                )
                dpg.add_spacer(height=10)
                dpg.add_text("YARA RULE (if generated)", color=_TEXT_DIM)
                dpg.add_input_text(
                    tag="verdict_yara",
                    multiline=True, readonly=True,
                    width=-1, height=-1,
                )

            # --- MITRE ---------------------------------------------------
            with dpg.tab(label="MITRE ATT&CK"):
                with dpg.collapsing_header(
                    label="Capabilities by confidence",
                    default_open=True,
                ):
                    with dpg.plot(
                        label="", height=300, width=-1, tag="mitre_plot",
                    ):
                        dpg.add_plot_legend()
                        dpg.add_plot_axis(dpg.mvXAxis, label="technique", tag="mitre_x_axis")
                        dpg.add_plot_axis(dpg.mvYAxis, label="confidence", tag="mitre_y_axis")

                with dpg.collapsing_header(
                    label="Techniques  (sorted by confidence; click source link to open MITRE page)",
                    default_open=True,
                ):
                    dpg.add_child_window(
                        tag="mitre_details", width=-1, height=-1, border=False,
                    )

            # --- IoCs ----------------------------------------------------
            with dpg.tab(label="IoCs"):
                with dpg.table(
                    tag="ioc_table", header_row=True, borders_innerH=True,
                    borders_outerH=True, borders_innerV=True, resizable=True,
                    row_background=True,
                ):
                    dpg.add_table_column(label="type")
                    dpg.add_table_column(label="value")
                    dpg.add_table_column(label="addr")
                    dpg.add_table_column(label="xrefs")
                    dpg.add_table_column(label="conf")

            # --- Triage raw ---------------------------------------------
            with dpg.tab(label="Triage"):
                dpg.add_input_text(
                    tag="triage_summary",
                    multiline=True, readonly=True,
                    width=-1, height=-1,
                )

            # --- Cost ----------------------------------------------------
            with dpg.tab(label="Cost"):
                with dpg.group(horizontal=True):
                    with dpg.group():
                        dpg.add_text("TOTAL", color=_TEXT_DIM)
                        dpg.add_text("", tag="cost_usd", color=_ACCENT)
                    dpg.add_spacer(width=32)
                    with dpg.group():
                        dpg.add_text("INPUT TOKENS", color=_TEXT_DIM)
                        dpg.add_text("", tag="tok_in", color=_TEXT)
                    dpg.add_spacer(width=32)
                    with dpg.group():
                        dpg.add_text("OUTPUT TOKENS", color=_TEXT_DIM)
                        dpg.add_text("", tag="tok_out", color=_TEXT)
                dpg.add_spacer(height=6)
                dpg.add_separator()

                with dpg.collapsing_header(
                    label="USD per phase  (sorted by cost, largest first)",
                    default_open=True,
                ):
                    with dpg.plot(label="", height=260, width=-1, tag="cost_plot"):
                        dpg.add_plot_axis(dpg.mvXAxis, label="phase", tag="cost_x_axis")
                        dpg.add_plot_axis(dpg.mvYAxis, label="usd", tag="cost_y_axis")

                with dpg.collapsing_header(
                    label="Tokens per phase",
                    default_open=False,
                ):
                    with dpg.plot(label="", height=260, width=-1, tag="tok_plot"):
                        dpg.add_plot_legend()
                        dpg.add_plot_axis(dpg.mvXAxis, label="phase", tag="tok_x_axis")
                        dpg.add_plot_axis(dpg.mvYAxis, label="tokens", tag="tok_y_axis")

                with dpg.collapsing_header(
                    label="Raw breakdown",
                    default_open=False,
                ):
                    dpg.add_input_text(
                        tag="cost_breakdown",
                        multiline=True, readonly=True,
                        width=-1, height=260,
                    )

            # --- SOC -----------------------------------------------------
            with dpg.tab(label="SOC"):
                dpg.add_text("Webhook URL", color=_TEXT_DIM)
                dpg.add_input_text(
                    tag="webhook_url",
                    default_value=os.getenv("SOC_WEBHOOK_URL", ""),
                    width=-1,
                )
                dpg.add_spacer(height=8)
                dpg.add_button(label="send latest report", callback=_webhook_send)


_LAST_ELAPSED_UPDATE = 0.0


def _frame_pump() -> None:
    global _LAST_ELAPSED_UPDATE
    _drain_events()
    # Live elapsed timer — only refresh once per second to keep cheap.
    if STATE.get("running") and STATE.get("start_monotonic"):
        now = time.monotonic()
        if now - _LAST_ELAPSED_UPDATE >= 1.0:
            _LAST_ELAPSED_UPDATE = now
            elapsed = int(now - STATE["start_monotonic"])
            mins, secs = divmod(elapsed, 60)
            if dpg.does_item_exist("stat_elapsed"):
                dpg.set_value("stat_elapsed", f"{mins}:{secs:02d}")


_MENU_BAR_H = 24


def _on_viewport_resize(_sender=None, _data=None) -> None:
    """Resize handler: pin main window below the viewport menu bar and keep
    variable-width Pipeline panels in sync with viewport resizes.

    DPG's `set_primary_window` fills the whole viewport including the menu
    bar area, which hides the tab bar. So we forgo the primary-window flag
    and pin `main_window` manually each frame.
    """
    try:
        vp_w = dpg.get_viewport_client_width()
        vp_h = dpg.get_viewport_client_height()
    except Exception:  # noqa: BLE001
        return
    if vp_w <= 0 or vp_h <= 0:
        return

    if dpg.does_item_exist("main_window"):
        dpg.configure_item(
            "main_window",
            pos=(0, _MENU_BAR_H),
            width=vp_w,
            height=vp_h - _MENU_BAR_H,
        )

    # 16 px window padding (8 each side) + 6 px spacer between the two cards.
    half = max(280, (vp_w - 22) // 2)
    if dpg.does_item_exist("strings_card"):
        dpg.configure_item("strings_card", width=half)
    if dpg.does_item_exist("hex_card"):
        dpg.configure_item("hex_card", width=half)

    # Byte presence image: aspect-locked at 1024 x 170. Pin width to fill
    # the row alongside the byte plot card.
    bp_w = max(280, vp_w - 190 - 6 - 16 - 24)
    if dpg.does_item_exist("byte_presence_img"):
        dpg.configure_item("byte_presence_img", width=bp_w)


def main() -> None:
    dpg.create_context()
    dpg.create_viewport(
        title="Theseus", width=1200, height=800,
        clear_color=(_BG[0] / 255, _BG[1] / 255, _BG[2] / 255, 1.0),
    )

    # Layout persistence — DPG writes tab selection, collapsing-header state,
    # column widths, and scrollback positions to this file on close, then
    # restores them on next launch.
    layout_dir = Path.home() / ".theseus"
    layout_dir.mkdir(parents=True, exist_ok=True)
    layout_file = str(layout_dir / "layout.ini")
    dpg.configure_app(
        init_file=layout_file,
        load_init_file=True,
        auto_save_init_file=True,
    )

    _build_fonts()
    theme = _build_theme()
    _build_ui()
    dpg.bind_theme(theme)
    if _FONT_BODY is not None:
        dpg.bind_font(_FONT_BODY)
    dpg.setup_dearpygui()
    # Pin main_window below the menu bar via the resize callback rather than
    # using `set_primary_window`, which would cover the menu bar area.
    dpg.set_viewport_resize_callback(_on_viewport_resize)
    dpg.show_viewport()
    _on_viewport_resize()

    # OS file drag-drop (Windows only; no-op elsewhere).
    try:
        from .gui_drop import install_file_drop_handler

        install_file_drop_handler("Theseus", lambda p: _emit("file_drop", path=p))
    except Exception:  # noqa: BLE001
        pass

    while dpg.is_dearpygui_running():
        _frame_pump()
        dpg.render_dearpygui_frame()

    dpg.destroy_context()


if __name__ == "__main__":
    main()
