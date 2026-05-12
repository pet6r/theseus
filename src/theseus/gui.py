"""Theseus DearPyGui frontend.

Drop-zone + tabs (Pipeline / MITRE / IoCs / Cost / Report). Threaded calls into
the orchestrator. Live progress + verdict + reveal.js deck launch.

Run via: `theseus gui` or `python -m theseus.gui`.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Optional

import dearpygui.dearpygui as dpg

from .deck import render_deck
from .orchestrator import PipelineCallbacks, PipelineConfig, analyze
from .soc import push_to_webhook, summarize_for_ticket


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
}


def _emit(kind: str, **payload: Any) -> None:
    EVENTS.put({"kind": kind, **payload})


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def _worker(binary_path: Path) -> None:
    STATE["running"] = True
    STATE["current_binary"] = str(binary_path)
    STATE["report"] = None

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
# Event dispatcher (runs on GUI thread via dpg.set_frame_callback)
# ---------------------------------------------------------------------------

PHASE_BAR_TAGS = {
    "triage": "p_triage",
    "capability": "p_capability",
    "ioc": "p_ioc",
    "verdict": "p_verdict",
}


def _append_log(line: str) -> None:
    STATE["log"].append(line)
    tail = "\n".join(STATE["log"][-400:])
    dpg.set_value("log", tail)


def _handle_event(ev: dict[str, Any]) -> None:
    kind = ev["kind"]

    if kind == "log":
        _append_log(ev["msg"])

    elif kind == "file_drop":
        _start_analysis(Path(ev["path"]))

    elif kind == "phase_start":
        _append_log(f"▶ phase {ev['phase']} starting")

    elif kind == "phase_progress":
        tag = PHASE_BAR_TAGS.get(ev["phase"])
        if tag:
            dpg.set_value(tag, ev["value"])

    elif kind == "phase_done":
        tag = PHASE_BAR_TAGS.get(ev["phase"])
        if tag:
            dpg.set_value(tag, 1.0)
        _append_log(f"✓ phase {ev['phase']} done")

    elif kind == "token":
        dpg.set_value("tok_in", f"input: {ev['input']:,}")
        dpg.set_value("tok_out", f"output: {ev['output']:,}")

    elif kind == "done":
        report = STATE["report"] or {}
        verdict = report.get("verdict") or {}
        triage = report.get("triage") or {}
        caps = report.get("capabilities") or []
        iocs = report.get("iocs") or []
        cost = report.get("cost") or {}

        dpg.set_value("verdict_label", f"Verdict: {verdict.get('label', '?').upper()}")
        dpg.set_value("verdict_score", f"Score: {verdict.get('score', 0):.2f}")
        dpg.set_value("verdict_action", f"SOC action: {verdict.get('soc_action', '?')}")
        dpg.set_value("verdict_reasoning", verdict.get("reasoning", ""))

        dpg.set_value("triage_summary", json.dumps(triage, indent=2)[:4000])

        _refresh_mitre_plot(caps)
        _refresh_ioc_table(iocs)

        dpg.set_value("cost_usd", f"Cost: ${cost.get('usd', 0):.4f}")
        dpg.set_value("cost_breakdown", json.dumps(cost, indent=2))

        _append_log(f"✓ done. report={ev['report_path']} deck={ev['deck_path']}")
        dpg.configure_item("open_deck_btn", enabled=True)
        dpg.configure_item("drop_btn", enabled=True)

    elif kind == "error":
        _append_log(f"✗ ERROR: {ev['msg']}")
        dpg.configure_item("drop_btn", enabled=True)


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

    # rebuild axis labels + bar series
    dpg.delete_item("mitre_series", children_only=False)
    dpg.set_axis_ticks("mitre_x_axis", tuple((lbl, i) for i, lbl in enumerate(labels)))
    dpg.add_bar_series(
        indices, values,
        label="confidence", parent="mitre_y_axis", tag="mitre_series", weight=0.6,
    )
    dpg.fit_axis_data("mitre_y_axis")
    dpg.fit_axis_data("mitre_x_axis")


def _refresh_ioc_table(iocs: list[dict]) -> None:
    # clear existing rows
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
        _append_log("already running — wait for current job")
        return
    # reset progress + outputs
    for tag in PHASE_BAR_TAGS.values():
        dpg.set_value(tag, 0.0)
    dpg.set_value("verdict_label", "Verdict: …")
    dpg.set_value("verdict_score", "Score: …")
    dpg.set_value("verdict_action", "SOC action: …")
    dpg.set_value("verdict_reasoning", "")
    STATE["log"] = []
    dpg.set_value("log", "")
    dpg.configure_item("drop_btn", enabled=False)
    dpg.configure_item("open_deck_btn", enabled=False)
    dpg.set_value("current_binary", f"Binary: {path}")

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
# Layout
# ---------------------------------------------------------------------------

def _build_ui() -> None:
    with dpg.file_dialog(
        directory_selector=False,
        show=False,
        callback=_on_file_picked,
        tag="file_picker",
        width=700, height=400,
    ):
        dpg.add_file_extension(".*")
        dpg.add_file_extension(".exe", color=(255, 180, 180))
        dpg.add_file_extension(".dll", color=(255, 180, 180))
        dpg.add_file_extension(".so", color=(180, 220, 255))
        dpg.add_file_extension(".elf", color=(180, 220, 255))

    with dpg.window(label="Theseus", tag="main_window", no_title_bar=True):
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="  Drop / pick binary  ",
                tag="drop_btn",
                callback=lambda: dpg.show_item("file_picker"),
                height=36,
            )
            dpg.add_button(label="Open deck", tag="open_deck_btn", callback=_open_deck, enabled=False)
            dpg.add_text("", tag="current_binary", color=(180, 180, 180))

        dpg.add_separator()

        with dpg.tab_bar():
            # --- Pipeline ---
            with dpg.tab(label="Pipeline"):
                dpg.add_progress_bar(tag="p_triage", default_value=0, overlay="triage", width=-1)
                dpg.add_progress_bar(tag="p_capability", default_value=0, overlay="capability", width=-1)
                dpg.add_progress_bar(tag="p_ioc", default_value=0, overlay="ioc", width=-1)
                dpg.add_progress_bar(tag="p_verdict", default_value=0, overlay="verdict", width=-1)
                dpg.add_separator()
                with dpg.group(horizontal=True):
                    dpg.add_text("", tag="verdict_label", color=(255, 220, 100))
                    dpg.add_text("", tag="verdict_score")
                    dpg.add_text("", tag="verdict_action")
                dpg.add_input_text(tag="verdict_reasoning", multiline=True, readonly=True, width=-1, height=80)
                dpg.add_separator()
                dpg.add_text("Log")
                dpg.add_input_text(tag="log", multiline=True, readonly=True, width=-1, height=-1)

            # --- MITRE ---
            with dpg.tab(label="MITRE ATT&CK"):
                with dpg.plot(label="Capabilities by confidence", height=-1, width=-1):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="technique", tag="mitre_x_axis")
                    dpg.add_plot_axis(dpg.mvYAxis, label="confidence", tag="mitre_y_axis")

            # --- IoCs ---
            with dpg.tab(label="IoCs"):
                with dpg.table(
                    tag="ioc_table", header_row=True, borders_innerH=True,
                    borders_outerH=True, borders_innerV=True, resizable=True,
                ):
                    dpg.add_table_column(label="type")
                    dpg.add_table_column(label="value")
                    dpg.add_table_column(label="addr")
                    dpg.add_table_column(label="xrefs")
                    dpg.add_table_column(label="conf")

            # --- Triage raw ---
            with dpg.tab(label="Triage"):
                dpg.add_input_text(tag="triage_summary", multiline=True, readonly=True, width=-1, height=-1)

            # --- Cost ---
            with dpg.tab(label="Cost"):
                dpg.add_text("", tag="cost_usd", color=(120, 220, 120))
                dpg.add_text("", tag="tok_in")
                dpg.add_text("", tag="tok_out")
                dpg.add_input_text(tag="cost_breakdown", multiline=True, readonly=True, width=-1, height=200)

            # --- SOC ---
            with dpg.tab(label="SOC"):
                dpg.add_text("Webhook URL")
                dpg.add_input_text(tag="webhook_url", default_value=os.getenv("SOC_WEBHOOK_URL", ""), width=-1)
                dpg.add_button(label="Send latest report", callback=_webhook_send)


def _frame_pump() -> None:
    _drain_events()


def main() -> None:
    dpg.create_context()
    dpg.create_viewport(title="Theseus", width=1400, height=900)
    _build_ui()
    dpg.setup_dearpygui()
    dpg.set_primary_window("main_window", True)
    dpg.show_viewport()

    # Wire OS file drag-drop (Windows only; no-op elsewhere).
    try:
        from .gui_drop import install_file_drop_handler

        install_file_drop_handler("Theseus", lambda p: _emit("file_drop", path=p))
    except Exception:  # noqa: BLE001
        pass

    # Drain event queue once per frame
    while dpg.is_dearpygui_running():
        _frame_pump()
        dpg.render_dearpygui_frame()

    dpg.destroy_context()


if __name__ == "__main__":
    main()
