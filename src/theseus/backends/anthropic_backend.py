"""Anthropic Messages API backend (default).

Drives the tool-use loop via `anthropic.Anthropic().messages.create(...)`, dispatching
ghidrasql_query via the existing `ToolRouter`. Requires `ANTHROPIC_API_KEY`.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from anthropic import Anthropic
from anthropic.types import Message, MessageParam, TextBlock, ToolUseBlock

from ..tools import TOOL_SCHEMAS, ToolRouter
from .base import PhaseResult

log = logging.getLogger("theseus.backends.anthropic")

MAX_TOKENS_PER_TURN = 4096


class AnthropicBackend:
    def __init__(self, *, ghidrasql_url: str, libghidra_url: str, model: str):
        self.client = Anthropic()
        self.model = model
        self.router = ToolRouter(ghidrasql_url, libghidra_url)

    def __enter__(self) -> "AnthropicBackend":
        return self

    def __exit__(self, *_exc) -> None:
        self.router.close()

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
    ) -> PhaseResult:
        messages: list[MessageParam] = [{"role": "user", "content": user_prompt}]
        result = PhaseResult(name=phase_name)
        final_text_parts: list[str] = []

        for turn in range(max_turns):
            log(f"[{phase_name}] turn {turn + 1}/{max_turns}")
            resp: Message = self.client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS_PER_TURN,
                system=[
                    {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}},
                ],
                tools=TOOL_SCHEMAS,
                messages=messages,
            )

            usage = resp.usage
            result.input_tokens += getattr(usage, "input_tokens", 0) or 0
            result.output_tokens += getattr(usage, "output_tokens", 0) or 0
            result.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
            result.cache_write_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
            result.turns = turn + 1

            if on_token:
                on_token(result.input_tokens, result.output_tokens)
            if on_progress:
                on_progress(phase_name, min(0.95, (turn + 1) / max_turns))

            tool_uses: list[ToolUseBlock] = []
            for block in resp.content:
                if isinstance(block, ToolUseBlock):
                    tool_uses.append(block)
                elif isinstance(block, TextBlock):
                    final_text_parts.append(block.text)

            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason == "end_turn" or not tool_uses:
                break

            tool_results: list[dict[str, Any]] = []
            for tu in tool_uses:
                log(f"[{phase_name}]   tool {tu.name} {json.dumps(tu.input)[:200]}")
                output = self.router.dispatch(tu.name, tu.input)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": output,
                    }
                )
            messages.append({"role": "user", "content": tool_results})
        else:
            log(f"[{phase_name}] hit max_turns={max_turns} without end_turn")

        result.raw_text = "\n".join(final_text_parts)
        if on_progress:
            on_progress(phase_name, 1.0)
        return result
