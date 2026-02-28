"""
LangGraph graph definition for the Infra-Guard observability agent.

Architecture choice — prompt-chaining + routing workflow (not a full autonomous agent):

The problem structure is well-defined and sequential:
  1. Validate input
  2. Detect anomalies (one LLM call)
  3. Route based on score
  4. Optionally synthesize RCA (one LLM call)

A full autonomous agent loop (LLM dynamically chooses tools, loops until done) would
add complexity with no benefit here. Per Anthropic's guidance, complexity should only
be added when a simpler pattern demonstrably fails.

Routing design:
- The router function (_route_after_detection) is a plain Python function, not embedded
  in a node's return value. This follows LangGraph's "nodes do work, edges route"
  principle and avoids the Command+static-edge ambiguity bug.
- The router is a Literal-typed function so the conditional edge mapping is
  statically verifiable.

State schema separation:
- input_schema=InputState  → callers only need to supply raw_logs
- output_schema=OutputState → callers only receive the fields they care about
- OverallState              → internal plumbing never leaks externally
"""

from __future__ import annotations

import logging
from typing import Literal

from langgraph.graph import END, START, StateGraph

from .nodes import anomaly_detection_node, rca_synthesis_node, validate_logs_node
from .state import InputState, OutputState, OverallState

logger = logging.getLogger(__name__)

# ── Router ────────────────────────────────────────────────────────────────────


def _route_after_detection(
    state: OverallState,
) -> Literal["rca_synthesis", "__end__"]:
    """
    FR-202 (Logical Router):
      - score < 7  → END  (verdict: "System Healthy")
      - score >= 7 → rca_synthesis node (proceed to RCA)

    Error handling: if error_context is set AND score is 0, the detection node
    failed entirely. Route to END so the error is returned to the caller rather
    than sending zero-signal state into the RCA node.

    This function is deliberately kept free of side effects. It reads state and
    returns a string — nothing else. LangGraph calls it on every edge traversal.
    """
    score: int = state.get("anomaly_score", 0)
    error: str | None = state.get("error_context")

    if error:
        logger.warning("Routing to END due to upstream error: %s", error)
        return "__end__"

    if score >= 7:
        logger.info("Anomaly score=%d/10 → routing to rca_synthesis", score)
        return "rca_synthesis"

    logger.info("Anomaly score=%d/10 → routing to END (system healthy)", score)
    return "__end__"


# ── Graph factory ─────────────────────────────────────────────────────────────


def build_graph() -> StateGraph:
    """
    Construct and compile the Infra-Guard LangGraph workflow.

    Returned as a compiled graph ready for .invoke() / .stream().
    Called once at module level to create the singleton `graph` instance,
    but exposed as a factory for test isolation (each test builds its own
    graph so patches apply cleanly).
    """
    builder = StateGraph(
        OverallState,
        input_schema=InputState,
        output_schema=OutputState,
    )

    # ── Nodes ──────────────────────────────────────────────────────────────
    builder.add_node("validate_logs", validate_logs_node)
    builder.add_node("anomaly_detection", anomaly_detection_node)
    builder.add_node("rca_synthesis", rca_synthesis_node)

    # ── Edges ──────────────────────────────────────────────────────────────
    # Linear chain: START → validate → detect
    builder.add_edge(START, "validate_logs")
    builder.add_edge("validate_logs", "anomaly_detection")

    # Conditional branch: detect → (rca_synthesis | END)
    builder.add_conditional_edges(
        "anomaly_detection",
        _route_after_detection,
        {
            "rca_synthesis": "rca_synthesis",
            "__end__": END,
        },
    )

    # Terminal: rca_synthesis always exits to END
    builder.add_edge("rca_synthesis", END)

    return builder.compile()


# ── Module-level singleton ────────────────────────────────────────────────────
# Compiled once at import time. The FastAPI app imports this instance directly.
# Tests call build_graph() directly to get isolated instances.
graph = build_graph()
