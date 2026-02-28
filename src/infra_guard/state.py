"""
State schema for the Infra-Guard observability agent.

Design decisions:
- Three separate schemas: InputState (caller-facing in), OutputState (caller-facing out),
  and OverallState (internal working state). This prevents internal plumbing fields from
  leaking into the external API surface (per LangGraph multiple-schema best practice).
- Accumulating fields use Annotated reducers instead of last-write-wins.
  reasoning_path is appended to by every node — if it used last-write-wins, each
  node would silently discard all prior trace entries.
- RemainingSteps is managed automatically by LangGraph and enables graceful degradation
  before hitting the recursion limit, rather than a hard RuntimeError.
- Non-state dependencies (LLM instance, API keys) are NOT stored here. They are
  instantiated inside nodes from runtime config/env, keeping state purely data.
"""

from __future__ import annotations

import operator
from typing import Annotated

from langgraph.managed import RemainingSteps
from typing_extensions import TypedDict


class InputState(TypedDict):
    """External API surface — what callers must provide."""

    raw_logs: list[dict]


class OutputState(TypedDict):
    """External API surface — what callers receive back."""

    anomaly_score: int
    reasoning_path: list[str]
    final_report: str | None
    error_context: str | None


class OverallState(TypedDict):
    """
    Internal working state — encompasses both InputState and OutputState fields,
    plus internal plumbing that is never exposed externally.

    Field design:
    - raw_logs: mutable during validation (timestamps are added).
    - anomaly_score: last-write-wins is correct — only one node writes this.
    - reasoning_path: uses operator.add reducer so every node's trace entry
      is appended rather than overwriting prior entries.
    - final_report / error_context: last-write-wins; set by terminal nodes.
    - remaining_steps: automatically decremented by LangGraph each super-step.
    """

    # ── Input ──────────────────────────────────────────────────────────────
    raw_logs: list[dict]

    # ── Computed ───────────────────────────────────────────────────────────
    anomaly_score: int

    # ── Accumulating — MUST have a reducer ────────────────────────────────
    reasoning_path: Annotated[list[str], operator.add]

    # ── Output ─────────────────────────────────────────────────────────────
    final_report: str | None
    error_context: str | None

    # ── LangGraph-managed ──────────────────────────────────────────────────
    remaining_steps: RemainingSteps
