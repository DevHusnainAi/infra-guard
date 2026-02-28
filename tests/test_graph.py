"""
Pytest test suite for Infra-Guard.

Test philosophy:
- Stability first (FR success metric): 100% of graph runs must reach END state
  regardless of LLM output quality or transient errors. This is the primary assertion
  in every integration test.
- Logic validation: Router, validator, and node error-handling are tested without
  any LLM calls — they are deterministic Python logic and should be tested as such.
- LLM calls are mocked in integration tests so CI runs without a GROQ_API_KEY
  and without network access.
- One live smoke test is included but unconditionally skipped unless GROQ_API_KEY
  is set in the environment. Run it explicitly for pre-deployment validation.

Fixtures:
- HEALTHY_LOGS: scores should produce a low anomaly_score (< 7) in real usage.
- CRITICAL_LOGS: scores should produce a high anomaly_score (>= 7) in real usage.
- MOCK_CONFIG: minimal RunnableConfig-compatible dict for unit tests.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from infra_guard.graph import _route_after_detection, build_graph
from infra_guard.nodes import validate_logs_node
from infra_guard.state import OverallState

# ── Shared fixtures ───────────────────────────────────────────────────────────

HEALTHY_LOGS: list[dict] = [
    {"service": "auth", "level": "INFO", "message": "User login successful", "latency_ms": 45},
    {"service": "api", "level": "INFO", "message": "GET /users 200", "latency_ms": 80},
    {"service": "db", "level": "INFO", "message": "Query executed in 12ms", "latency_ms": 12},
]

CRITICAL_LOGS: list[dict] = [
    {"service": "payment", "level": "ERROR", "message": "DB connection refused", "count": 42},
    {"service": "auth", "level": "ERROR", "message": "Downstream timeout from payment", "count": 38},
    {"service": "api", "level": "CRITICAL", "message": "Cascading 503s — circuit breaker open", "count": 105},
    {"service": "queue", "level": "ERROR", "message": "Message backlog critical: 50k unprocessed", "count": 1},
]

MOCK_CONFIG: dict = {
    "configurable": {
        "model": "llama-3.3-70b-versatile",
        "temperature": 0.1,
    },
    "metadata": {
        "langgraph_step": 1,
        "langgraph_node": "test_node",
        "langgraph_triggers": [],
    },
}

INVOKE_CONFIG: dict = {
    "configurable": {"thread_id": "test-thread"},
    "recursion_limit": 10,
}


def _base_state(**overrides) -> OverallState:
    """Return a minimal valid OverallState for unit tests."""
    base: dict = {
        "raw_logs": HEALTHY_LOGS,
        "anomaly_score": 0,
        "reasoning_path": [],
        "final_report": None,
        "error_context": None,
        "remaining_steps": 10,
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


def _mock_llm_response(content: str) -> MagicMock:
    """Create a mock ChatGroq response with the given content string."""
    mock = MagicMock()
    mock.content = content
    return mock


# ── Unit tests: validate_logs_node ───────────────────────────────────────────


class TestValidateLogsNode:
    def test_empty_list_returns_error_context(self) -> None:
        state = _base_state(raw_logs=[])
        result = validate_logs_node(state, MOCK_CONFIG)

        assert result["error_context"] is not None
        assert result["anomaly_score"] == 0
        assert any("REJECTED" in entry for entry in result["reasoning_path"])

    def test_valid_logs_pass_through_unchanged_count(self) -> None:
        state = _base_state(raw_logs=HEALTHY_LOGS)
        result = validate_logs_node(state, MOCK_CONFIG)

        assert result.get("error_context") is None
        assert len(result["raw_logs"]) == len(HEALTHY_LOGS)

    def test_entries_missing_timestamp_get_stamped(self) -> None:
        logs = [{"service": "auth", "level": "INFO", "message": "ok"}]
        state = _base_state(raw_logs=logs)
        result = validate_logs_node(state, MOCK_CONFIG)

        assert all("timestamp" in entry for entry in result["raw_logs"])

    def test_entries_with_existing_timestamp_are_unchanged(self) -> None:
        ts = "2024-01-01T00:00:00+00:00"
        logs = [{"service": "auth", "timestamp": ts, "message": "ok"}]
        state = _base_state(raw_logs=logs)
        result = validate_logs_node(state, MOCK_CONFIG)

        assert result["raw_logs"][0]["timestamp"] == ts

    def test_non_dict_entries_are_silently_filtered(self) -> None:
        logs = [{"service": "auth"}, "not a dict", 42, None]
        state = _base_state(raw_logs=logs)
        result = validate_logs_node(state, MOCK_CONFIG)

        assert len(result["raw_logs"]) == 1

    def test_all_non_dict_entries_returns_error(self) -> None:
        logs = ["string", 42, None]
        state = _base_state(raw_logs=logs)
        result = validate_logs_node(state, MOCK_CONFIG)

        assert result["error_context"] is not None
        assert result["anomaly_score"] == 0

    def test_reasoning_path_always_has_one_entry(self) -> None:
        for logs in [[], HEALTHY_LOGS, ["not a dict"]]:
            state = _base_state(raw_logs=logs)
            result = validate_logs_node(state, MOCK_CONFIG)
            assert len(result["reasoning_path"]) == 1


# ── Unit tests: _route_after_detection ───────────────────────────────────────


class TestRouter:
    @pytest.mark.parametrize("score", [0, 1, 2, 3, 4, 5, 6])
    def test_score_below_threshold_routes_to_end(self, score: int) -> None:
        state = _base_state(anomaly_score=score)
        assert _route_after_detection(state) == "__end__"

    @pytest.mark.parametrize("score", [7, 8, 9, 10])
    def test_score_at_or_above_threshold_routes_to_rca(self, score: int) -> None:
        state = _base_state(anomaly_score=score)
        assert _route_after_detection(state) == "rca_synthesis"

    def test_error_with_zero_score_routes_to_end(self) -> None:
        state = _base_state(anomaly_score=0, error_context="Detection node crashed")
        assert _route_after_detection(state) == "__end__"

    def test_error_with_high_score_routes_to_end_for_safety(self) -> None:
        # For safety, even a partial error should terminate rather than
        # sending potentially corrupt state into the RCA node.
        state = _base_state(anomaly_score=8, error_context="Partial parse warning")
        assert _route_after_detection(state) == "__end__"


# ── Integration tests: graph stability ───────────────────────────────────────


class TestGraphStability:
    """
    Primary stability assertion: 100% of graph.invoke() calls must return a result
    dict (i.e., reach END state) regardless of LLM output or simulated errors.

    All LLM calls are mocked so these tests run in CI with no API key or network.
    build_graph() is called per test for clean patch isolation.
    """

    @patch("infra_guard.nodes.ChatGroq")
    def test_healthy_logs_reach_end_with_no_rca(self, mock_groq_cls: MagicMock) -> None:
        mock_groq_cls.return_value.invoke.return_value = _mock_llm_response(
            json.dumps({
                "anomaly_score": 3,
                "detected_patterns": ["normal_traffic"],
                "summary": "All systems operating within normal parameters.",
            })
        )
        g = build_graph()
        result = g.invoke({"raw_logs": HEALTHY_LOGS}, config=INVOKE_CONFIG)

        assert result is not None
        assert result["anomaly_score"] == 3
        assert result.get("final_report") is None  # Router took END path
        assert len(result["reasoning_path"]) >= 2  # validate + detect entries

    @patch("infra_guard.nodes.ChatGroq")
    def test_critical_logs_trigger_rca_report(self, mock_groq_cls: MagicMock) -> None:
        mock_groq_cls.return_value.invoke.side_effect = [
            # First call: anomaly detection
            _mock_llm_response(json.dumps({
                "anomaly_score": 9,
                "detected_patterns": ["cascading_failures", "db_connection_refused"],
                "summary": "Critical cascading failures across payment and auth services.",
            })),
            # Second call: RCA synthesis
            _mock_llm_response(
                "## Root Cause Analysis Report\n\n"
                "### Impact Level\nCritical — payment and auth services down\n\n"
                "### Root Cause\nDB connection pool exhausted.\n\n"
                "### Affected Components\n- **payment**: cannot process transactions\n\n"
                "### Remediation Steps\n"
                "1. **Immediate (0–15 min):** Restart DB connection pool\n"
                "2. **Short-term (15–60 min):** Scale DB replicas\n"
                "3. **Long-term (post-incident):** Implement connection pool monitoring\n\n"
                "### Evidence\n```\nDB connection refused x42\n```"
            ),
        ]
        g = build_graph()
        result = g.invoke({"raw_logs": CRITICAL_LOGS}, config=INVOKE_CONFIG)

        assert result is not None
        assert result["anomaly_score"] == 9
        assert result["final_report"] is not None
        assert "Root Cause" in result["final_report"]
        assert "Remediation Steps" in result["final_report"]

    @patch("infra_guard.nodes.ChatGroq")
    def test_graph_reaches_end_when_llm_raises_exception(
        self, mock_groq_cls: MagicMock
    ) -> None:
        """FR-302: Graph must reach END even when the LLM throws an exception."""
        mock_groq_cls.return_value.invoke.side_effect = RuntimeError("Groq API unavailable")
        g = build_graph()
        result = g.invoke({"raw_logs": HEALTHY_LOGS}, config=INVOKE_CONFIG)

        assert result is not None
        assert result.get("error_context") is not None

    @patch("infra_guard.nodes.ChatGroq")
    def test_graph_reaches_end_on_invalid_json_response(
        self, mock_groq_cls: MagicMock
    ) -> None:
        """Parser error in anomaly detection should not crash the graph."""
        mock_groq_cls.return_value.invoke.return_value = _mock_llm_response(
            "I'm sorry, I cannot analyze logs in JSON format today."
        )
        g = build_graph()
        result = g.invoke({"raw_logs": HEALTHY_LOGS}, config=INVOKE_CONFIG)

        assert result is not None
        assert result.get("error_context") is not None

    def test_empty_logs_reach_end_without_llm_call(self) -> None:
        """Validation failure should short-circuit before any LLM call."""
        g = build_graph()
        result = g.invoke({"raw_logs": []}, config=INVOKE_CONFIG)

        assert result is not None
        assert result["anomaly_score"] == 0
        assert result.get("error_context") is not None
        assert result.get("final_report") is None

    @patch("infra_guard.nodes.ChatGroq")
    def test_reasoning_path_captures_all_node_traces(
        self, mock_groq_cls: MagicMock
    ) -> None:
        """reasoning_path must contain one entry per executed node."""
        mock_groq_cls.return_value.invoke.side_effect = [
            _mock_llm_response(json.dumps({
                "anomaly_score": 9,
                "detected_patterns": ["cascade"],
                "summary": "Critical.",
            })),
            _mock_llm_response("## Root Cause Analysis Report\n\nCritical."),
        ]
        g = build_graph()
        result = g.invoke({"raw_logs": CRITICAL_LOGS}, config=INVOKE_CONFIG)

        # validate_logs + anomaly_detection + rca_synthesis = 3 trace entries
        assert len(result["reasoning_path"]) == 3

    @patch("infra_guard.nodes.ChatGroq")
    def test_score_boundary_6_does_not_trigger_rca(
        self, mock_groq_cls: MagicMock
    ) -> None:
        mock_groq_cls.return_value.invoke.return_value = _mock_llm_response(
            json.dumps({"anomaly_score": 6, "detected_patterns": [], "summary": "Degraded."})
        )
        g = build_graph()
        result = g.invoke({"raw_logs": HEALTHY_LOGS}, config=INVOKE_CONFIG)

        assert result.get("final_report") is None

    @patch("infra_guard.nodes.ChatGroq")
    def test_score_boundary_7_triggers_rca(self, mock_groq_cls: MagicMock) -> None:
        mock_groq_cls.return_value.invoke.side_effect = [
            _mock_llm_response(
                json.dumps({"anomaly_score": 7, "detected_patterns": [], "summary": "Incident."})
            ),
            _mock_llm_response("## Root Cause Analysis Report\n\nIncident confirmed."),
        ]
        g = build_graph()
        result = g.invoke({"raw_logs": CRITICAL_LOGS}, config=INVOKE_CONFIG)

        assert result["final_report"] is not None


# ── Live smoke test ───────────────────────────────────────────────────────────


@pytest.mark.skipif(
    not os.getenv("GROQ_API_KEY"),
    reason="GROQ_API_KEY not set — skipping live Groq integration test",
)
class TestLiveGroq:
    def test_live_healthy_logs(self) -> None:
        """End-to-end smoke test against the real Groq API."""
        g = build_graph()
        result = g.invoke(
            {"raw_logs": HEALTHY_LOGS},
            config={"configurable": {"thread_id": "live-smoke-test"}, "recursion_limit": 10},
        )
        assert result is not None
        assert isinstance(result["anomaly_score"], int)
        assert 0 <= result["anomaly_score"] <= 10
        assert isinstance(result["reasoning_path"], list)
        assert len(result["reasoning_path"]) >= 2
