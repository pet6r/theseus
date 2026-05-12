"""Claude Code backend via Claude Agent SDK.

Routes the tool-use loop through the user's `claude` CLI OAuth session (Claude Max
or Pro subscription) instead of a raw API key. Exposes `ghidrasql_query` as an
in-process MCP tool; all default Claude Code tools (Read/Bash/Grep/...) are disabled.

Requires `pip install claude-agent-sdk` and a prior `claude login`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

import httpx

from .base import PhaseResult

log = logging.getLogger("theseus.backends.claude_code")


class ClaudeCodeBackend:
    def __init__(self, *, ghidrasql_url: str, libghidra_url: str, model: str):
        self.ghidrasql_url = ghidrasql_url.rstrip("/")
        self.libghidra_url = libghidra_url.rstrip("/")
        self.model = model

    def __enter__(self) -> "ClaudeCodeBackend":
        return self

    def __exit__(self, *_exc) -> None:
        return None

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
        return asyncio.run(
            self._run_phase_async(
                system=system,
                user_prompt=user_prompt,
                phase_name=phase_name,
                max_turns=max_turns,
                log=log,
                on_token=on_token,
                on_progress=on_progress,
            )
        )

    async def _run_phase_async(
        self,
        *,
        system: str,
        user_prompt: str,
        phase_name: str,
        max_turns: int,
        log: Callable[[str], None],
        on_token: Callable[[int, int], None] | None,
        on_progress: Callable[[str, float], None] | None,
    ) -> PhaseResult:
        try:
            from claude_agent_sdk import (
                ClaudeAgentOptions,
                ResultMessage,
                create_sdk_mcp_server,
                query,
                tool,
            )
        except ImportError as e:
            raise RuntimeError(
                "claude-agent-sdk not installed. Run: pip install claude-agent-sdk"
            ) from e

        ghidrasql_url = self.ghidrasql_url

        @tool(
            "ghidrasql_query",
            "Execute a SQL query against the ghidrasql HTTP server (raw SQL body). "
            "ALWAYS use LIMIT to cap result size.",
            {"sql": str},
        )
        async def ghidrasql_query(args: dict[str, Any]) -> dict[str, Any]:
            sql = (args.get("sql") or "").strip()
            if not sql:
                return {"content": [{"type": "text", "text": '{"error":"empty sql"}'}], "is_error": True}
            async with httpx.AsyncClient(timeout=60.0) as c:
                resp = await c.post(
                    f"{ghidrasql_url}/query",
                    content=sql.encode("utf-8"),
                    headers={"Content-Type": "text/plain"},
                )
                resp.raise_for_status()
                return {"content": [{"type": "text", "text": resp.text}]}

        server = create_sdk_mcp_server(name="ghidrasql", version="1.0.0", tools=[ghidrasql_query])

        options = ClaudeAgentOptions(
            system_prompt=system,
            mcp_servers={"ghidrasql": server},
            allowed_tools=["mcp__ghidrasql__ghidrasql_query"],
            max_turns=max_turns,
            model=self.model,
        )

        result = PhaseResult(name=phase_name)
        final_text_parts: list[str] = []
        turn = 0

        try:
            async for message in query(prompt=user_prompt, options=options):
                cls_name = type(message).__name__
                if cls_name == "AssistantMessage":
                    turn += 1
                    result.turns = turn
                    if on_progress:
                        on_progress(phase_name, min(0.95, turn / max_turns))
                    content = getattr(message, "content", None) or []
                    for block in content:
                        text = getattr(block, "text", None)
                        if text:
                            final_text_parts.append(text)
                elif isinstance(message, ResultMessage):
                    usage = getattr(message, "usage", {}) or {}
                    result.input_tokens = int(usage.get("input_tokens", 0) or 0)
                    result.output_tokens = int(usage.get("output_tokens", 0) or 0)
                    result.cache_read_tokens = int(usage.get("cache_read_input_tokens", 0) or 0)
                    result.cache_write_tokens = int(usage.get("cache_creation_input_tokens", 0) or 0)
                    result.cost_usd = float(getattr(message, "total_cost_usd", 0.0) or 0.0)
                    subtype = getattr(message, "subtype", None)
                    if subtype == "success":
                        final_text = getattr(message, "result", None)
                        if final_text and not final_text_parts:
                            final_text_parts.append(final_text)
                    else:
                        log(f"[{phase_name}] SDK result subtype={subtype!r}, using partial output ({turn} turns)")
                    if on_token:
                        on_token(result.input_tokens, result.output_tokens)
        except Exception as e:  # noqa: BLE001
            # SDK raises on max-turns / aborted runs. Treat as soft failure:
            # use whatever assistant text we accumulated; orchestrator's
            # _extract_json will recover the largest valid JSON object/array.
            log(f"[{phase_name}] SDK raised {type(e).__name__}: {e} (continuing with partial output)")

        result.raw_text = "\n".join(final_text_parts)
        if on_progress:
            on_progress(phase_name, 1.0)
        return result
