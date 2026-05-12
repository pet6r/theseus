"""LLM backend interface + selection.

Each backend wraps one LLM provider (Anthropic API, Claude Code CLI via Agent SDK,
OpenAI-compatible local server, etc.) and exposes a uniform `run_phase` method.

The orchestrator only talks to `LLMBackend`. Add a new backend by:
1. Subclassing / implementing `LLMBackend.run_phase`.
2. Registering it in `get_backend` below.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Protocol


@dataclass
class PhaseResult:
    name: str
    raw_text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    turns: int = 0
    cost_usd: float = 0.0


class LLMBackend(Protocol):
    """Run a single phase as a tool-use loop and return the final assistant text + usage."""

    def run_phase(
        self,
        *,
        system: str,
        user_prompt: str,
        phase_name: str,
        max_turns: int,
        log: Callable[[str], None],
        on_token: Callable[[int, int], None] | None = None,
        on_progress: Callable[[str, float], None] | None = None,
    ) -> PhaseResult: ...


def get_backend(name: str | None, *, ghidrasql_url: str, libghidra_url: str, model: str) -> LLMBackend:
    """Resolve a backend by name. Falls back to $THESEUS_BACKEND env or 'anthropic'."""
    name = (name or os.environ.get("THESEUS_BACKEND") or "anthropic").lower()
    if name == "anthropic":
        from .anthropic_backend import AnthropicBackend

        return AnthropicBackend(ghidrasql_url=ghidrasql_url, libghidra_url=libghidra_url, model=model)
    if name in ("claude_code", "claude-code", "cc"):
        from .claude_code import ClaudeCodeBackend

        return ClaudeCodeBackend(ghidrasql_url=ghidrasql_url, libghidra_url=libghidra_url, model=model)
    raise ValueError(f"unknown THESEUS_BACKEND: {name!r} (expected: anthropic, claude_code)")
