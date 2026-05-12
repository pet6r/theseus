"""Theseus CLI.

Subcommands:
  theseus run <binary>            — analyze one binary, write report.json
  theseus serve --port 8090       — HTTP ingest API for SOC pipelines
  theseus gui                     — launch DearPyGui frontend
  theseus deck <report.json>      — render reveal.js deck from existing report
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import sys

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler

# Force UTF-8 on Windows when stdout is redirected, so Rich's box-drawing chars
# don't trip cp1252.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from .deck import render_deck
from .orchestrator import PipelineCallbacks, PipelineConfig, analyze
from .soc import push_to_webhook, summarize_for_ticket

app = typer.Typer(no_args_is_help=True, help="Theseus — navigate any binary.")
console = Console()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, markup=False, show_time=False, show_path=False)],
    )


@app.command()
def run(
    binary: Path = typer.Argument(..., exists=True, readable=True, help="Binary to analyze"),
    report: Path = typer.Option(Path("reports/report.json"), "--report", "-r", help="Where to write report JSON"),
    deck: Optional[Path] = typer.Option(None, "--deck", help="Also render reveal.js deck to this path"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="SOAR/SIEM webhook URL to POST report"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Analyze one binary end-to-end."""
    load_dotenv()
    _setup_logging(verbose)

    cfg = PipelineConfig.from_env()
    cb = PipelineCallbacks(
        on_log=lambda m: console.print(f"[dim]{m}[/dim]"),
        on_phase_start=lambda p: console.print(f"\n[bold cyan]── phase: {p} ──[/bold cyan]"),
        on_phase_done=lambda p, _r: console.print(f"[green]✓ {p} done[/green]"),
    )

    result = analyze(binary, config=cfg, callbacks=cb)

    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    console.print(f"\n[bold]Report:[/bold] {report}")
    console.print(f"[bold]Summary:[/bold] {summarize_for_ticket(result)}")

    if deck:
        path = render_deck(result, deck)
        console.print(f"[bold]Deck:[/bold] {path}")

    if webhook:
        console.print(f"[bold]Pushing to webhook:[/bold] {webhook}")
        resp = push_to_webhook(webhook, result)
        console.print(f"[dim]webhook response: {resp}[/dim]")


@app.command()
def deck(
    report: Path = typer.Argument(..., exists=True, readable=True, help="Path to existing report.json"),
    output: Path = typer.Option(Path("reports/deck.html"), "--output", "-o"),
) -> None:
    """Render reveal.js demo deck from an existing report.json."""
    data = json.loads(Path(report).read_text(encoding="utf-8"))
    path = render_deck(data, output)
    console.print(f"[bold]Deck:[/bold] {path}")


@app.command()
def serve(
    port: int = typer.Option(8090, "--port", "-p"),
    host: str = typer.Option("127.0.0.1", "--host"),
) -> None:
    """Run HTTP ingest API. POST /analyze with {"binary_path": "..."} or multipart file."""
    load_dotenv()
    _setup_logging(False)
    try:
        import uvicorn
        from fastapi import FastAPI, UploadFile, File, HTTPException
    except ImportError:
        console.print("[red]Install: pip install fastapi uvicorn python-multipart[/red]")
        raise SystemExit(1)

    api = FastAPI(title="Theseus", version="0.1.0")
    cfg = PipelineConfig.from_env()

    @api.post("/analyze/path")
    def analyze_path(payload: dict):
        bin_path = Path(payload.get("binary_path", ""))
        if not bin_path.exists():
            raise HTTPException(404, f"binary not found: {bin_path}")
        return analyze(bin_path, config=cfg)

    @api.post("/analyze/upload")
    async def analyze_upload(file: UploadFile = File(...)):
        tmp = Path("samples") / file.filename
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(await file.read())
        return analyze(tmp, config=cfg)

    @api.get("/health")
    def health():
        return {"ok": True, "service": "theseus", "model": cfg.model}

    uvicorn.run(api, host=host, port=port, log_level="info")


@app.command()
def gui() -> None:
    """Launch the DearPyGui frontend."""
    load_dotenv()
    from .gui import main as gui_main

    gui_main()


if __name__ == "__main__":
    app()
