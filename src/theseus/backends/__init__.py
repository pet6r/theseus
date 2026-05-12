"""Pluggable LLM backends for the Theseus pipeline.

A backend implements `LLMBackend.run_phase(...)` and returns a `PhaseResult`.
The orchestrator is backend-agnostic; pick via `THESEUS_BACKEND` env var.
"""

from .base import LLMBackend, PhaseResult, get_backend

__all__ = ["LLMBackend", "PhaseResult", "get_backend"]
