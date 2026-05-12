"""Tool definitions exposed to Claude for binary analysis.

We register a single `ghidrasql_query` tool that POSTs SQL to the ghidrasql HTTP server.
Output is JSON. The agent is responsible for crafting safe, narrow queries.

If you need direct libghidra method access (e.g. get_decompilation), add a second tool
that proxies to the libghidra HTTP server.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

log = logging.getLogger("theseus.tools")

GHIDRASQL_TOOL_SCHEMA: dict[str, Any] = {
    "name": "ghidrasql_query",
    "description": (
        "Execute a SQL query against the ghidrasql HTTP server, which exposes the analyzed "
        "Ghidra program database as 57+ tables and 77+ views. Returns rows as JSON. "
        "ALWAYS use LIMIT to cap result size. Prefer specific columns over SELECT *. "
        "Read-only by default; UPDATE/DELETE persist back to Ghidra (use sparingly)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "sql": {
                "type": "string",
                "description": "A single SQL statement. Use LIMIT N to cap rows.",
            },
            "max_rows": {
                "type": "integer",
                "description": "Hard cap on rows returned to the agent. Defaults to 200.",
                "default": 200,
            },
        },
        "required": ["sql"],
    },
}

TOOL_SCHEMAS = [GHIDRASQL_TOOL_SCHEMA]


class ToolRouter:
    """Routes tool_use blocks from Claude to the right backend."""

    def __init__(self, ghidrasql_url: str, libghidra_url: str, timeout: float = 60.0):
        self.ghidrasql_url = ghidrasql_url.rstrip("/")
        self.libghidra_url = libghidra_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "ToolRouter":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def dispatch(self, name: str, params: dict[str, Any]) -> str:
        """Execute a tool call. Returns a JSON-serializable string for tool_result."""
        try:
            if name == "ghidrasql_query":
                return self._ghidrasql_query(params)
            return json.dumps({"error": f"unknown tool: {name}"})
        except Exception as e:  # noqa: BLE001
            log.exception("tool %s failed", name)
            return json.dumps({"error": str(e), "tool": name})

    def _ghidrasql_query(self, params: dict[str, Any]) -> str:
        sql = params["sql"].strip()
        max_rows = int(params.get("max_rows", 200))
        if not sql:
            return json.dumps({"error": "empty sql"})
        # ghidrasql /query expects raw SQL in the request body (NOT JSON).
        # Response wraps per-statement results in a `results` array.
        resp = self.client.post(
            f"{self.ghidrasql_url}/query",
            content=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results") if isinstance(data, dict) else None
        if isinstance(results, list) and results:
            rows = results[0].get("rows") if isinstance(results[0], dict) else None
            if isinstance(rows, list) and len(rows) > max_rows:
                results[0]["rows"] = rows[:max_rows]
                results[0]["truncated"] = True
                results[0]["total_rows"] = len(rows)
                data["results"] = results
        return json.dumps(data)

