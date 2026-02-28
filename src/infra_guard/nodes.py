"""
LangGraph nodes for the Infra-Guard observability agent.

Node design contract (enforced throughout this module):
- Nodes are pure state transformers: (OverallState, RunnableConfig) → dict.
  They do NOT return Command objects — routing is the graph's responsibility.
- Every node appends exactly one entry to reasoning_path. Because reasoning_path
  uses operator.add as its reducer, each node's trace is preserved — none overwrites.
- Exceptions are always caught and written to error_context. The graph never
  crashes due to a node error (FR-302).
- Nodes check remaining_steps before initiating expensive LLM calls and degrade
  gracefully rather than hitting the hard recursion limit.
- The LLM is instantiated inside the node (not at module level) so that model and
  temperature can be overridden per-request via RunnableConfig["configurable"].
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from langchain_core.runnables import RunnableConfig
from langchain_groq import ChatGroq

from .prompts import ANOMALY_DETECTION_PROMPT, RCA_SYNTHESIS_PROMPT
from .state import OverallState

logger = logging.getLogger(__name__)

# ── Configuration & Limits ────────────────────────────────────────────────────

MAX_LOG_ENTRIES = 50  # Prevent context window overflow and excessive costs


# ── Internal helpers ──────────────────────────────────────────────────────────


def _escape_xml(text: str) -> str:
    """
    Sanitize text for safe inclusion within XML tags in LLM prompts.
    Prevents prompt injection via log content (e.g., </logs><task>...).
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _now() -> str:
    """ISO-8601 UTC timestamp for trace entries."""
    return datetime.now(timezone.utc).isoformat()


def _llm_from_config(config: RunnableConfig) -> ChatGroq:
    """
    Instantiate a ChatGroq client from runtime config.

    Model and temperature are not hardcoded — they can be overridden per-request
    via config["configurable"]. This keeps node logic decoupled from deployment
    concerns (e.g., swapping models for cost vs. quality trade-offs without
    touching node code).
    """
    cfg = config.get("configurable", {})
    return ChatGroq(
        model=cfg.get("model", "llama-3.3-70b-versatile"),
        temperature=cfg.get("temperature", 0.1),
    )


def _step(config: RunnableConfig) -> int:
    """Extract the current LangGraph super-step number for trace labelling."""
    return config.get("metadata", {}).get("langgraph_step", "?")


def _strip_code_fences(text: str) -> str:
    """
    Remove markdown code fences that some LLMs wrap around JSON responses.

    Groq with Llama reliably omits fences when instructed to, but this guard
    prevents a parse failure if the instruction is occasionally ignored.
    """
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop opening fence (```json or ```)
        lines = lines[1:]
        # Drop closing fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


# ── Nodes ─────────────────────────────────────────────────────────────────────


def validate_logs_node(state: OverallState, config: RunnableConfig) -> dict:
    """
    Validate and timestamp incoming log entries.

    FR-102: Every log stream must be timestamped and validated before being
    passed to analysis nodes.

    Responsibilities:
    - Reject empty or fully malformed log streams.
    - Stamp any entry missing a timestamp field.
    - Filter out non-dict entries silently (they carry no analysable data).

    On rejection, anomaly_score is set to 0 and error_context is populated.
    The graph will route to END, returning the error to the caller cleanly.
    """
    ts = _now()
    s = _step(config)
    trace_prefix = f"[step={s}][{ts}] validate_logs"

    raw_logs: list = state.get("raw_logs") or []

    if not raw_logs:
        trace = trace_prefix + " → REJECTED: empty log stream"
        return {
            "reasoning_path": [trace],
            "error_context": "Validation failed: no log entries provided.",
            "anomaly_score": 0,
        }

    # Safety: Truncate large log streams to prevent context overflow
    if len(raw_logs) > MAX_LOG_ENTRIES:
        logger.warning("Truncating log stream from %d to %d entries", len(raw_logs), MAX_LOG_ENTRIES)
        raw_logs = raw_logs[:MAX_LOG_ENTRIES]

    stamped: list[dict] = []
    for entry in raw_logs:
        if not isinstance(entry, dict):
            continue
        if "timestamp" not in entry:
            entry = {**entry, "timestamp": ts}
        # Security: Escape string values to prevent prompt injection
        sanitized_entry = {
            k: (_escape_xml(str(v)) if isinstance(v, str) else v)
            for k, v in entry.items()
        }
        stamped.append(sanitized_entry)

    if not stamped:
        trace = trace_prefix + " → REJECTED: no valid dict entries found"
        return {
            "reasoning_path": [trace],
            "error_context": "Validation failed: all entries were malformed (non-dict).",
            "anomaly_score": 0,
        }

    trace = trace_prefix + f" → OK: {len(stamped)} entries passed (sanitized)"
    return {
        "raw_logs": stamped,
        "reasoning_path": [trace],
    }


def anomaly_detection_node(state: OverallState, config: RunnableConfig) -> dict:
    """
    Scan logs for anomalies using Groq and assign a severity score (1–10).

    FR-201: Detect non-obvious patterns such as cascading microservice failures.
    FR-301: Append a human-readable trace entry to reasoning_path.
    FR-302: Catch all exceptions; write to error_context; never crash.

    Graceful degradation: if remaining_steps <= 2, skip the LLM call entirely
    and return score=0. This is preferable to a hard RecursionError.
    """
    ts = _now()
    s = _step(config)
    trace_prefix = f"[step={s}][{ts}] anomaly_detection"

    # Guard: if a prior node already recorded an error, skip LLM call.
    # Attempting detection on a failed/empty log stream produces meaningless output.
    if state.get("error_context"):
        trace = trace_prefix + " → SKIPPED: upstream error, no logs to analyze"
        logger.warning(trace)
        return {"reasoning_path": [trace]}

    # Guard: gracefully degrade near step limit
    remaining = int(state.get("remaining_steps", 10))
    if remaining <= 2:
        trace = trace_prefix + " → SKIPPED: insufficient remaining steps"
        logger.warning(trace)
        return {"reasoning_path": [trace], "anomaly_score": 0}

    try:
        llm = _llm_from_config(config)
        logs_text = json.dumps(state["raw_logs"], indent=2)
        prompt = ANOMALY_DETECTION_PROMPT.format(logs=logs_text)

        response = llm.invoke(prompt)
        content = _strip_code_fences(response.content)
        parsed: dict = json.loads(content)

        score: int = max(0, min(10, int(parsed.get("anomaly_score", 5))))
        patterns: list[str] = parsed.get("detected_patterns", [])
        summary: str = parsed.get("summary", "")

        trace = (
            trace_prefix
            + f" → score={score}/10"
            + f" | patterns={patterns}"
            + f" | {summary[:100]}{'...' if len(summary) > 100 else ''}"
        )
        logger.info(trace)
        return {
            "anomaly_score": score,
            "reasoning_path": [trace],
        }

    except json.JSONDecodeError as exc:
        # LLM returned non-JSON despite instructions — default to neutral score
        trace = trace_prefix + f" → PARSE_ERROR: {exc}"
        logger.warning(trace)
        return {
            "reasoning_path": [trace],
            "anomaly_score": 0,  # Standardized: score=0 on fatal logic failures
            "error_context": f"Anomaly detection parse error: {exc}",
        }

    except Exception as exc:
        trace = trace_prefix + f" → ERROR: {type(exc).__name__}: {exc}"
        logger.exception("anomaly_detection_node failed unexpectedly")
        return {
            "reasoning_path": [trace],
            "anomaly_score": 0,  # Standardized: score=0 on fatal logic failures
            "error_context": f"Anomaly detection failed: {type(exc).__name__}: {exc}",
        }


def rca_synthesis_node(state: OverallState, config: RunnableConfig) -> dict:
    """
    Synthesize a structured Markdown RCA report from logs and prior analysis.

    FR-203: Report must include Impact Level and Remediation Steps.
    FR-301: Append trace entry to reasoning_path.
    FR-302: Catch all exceptions; never crash.

    This node is only reached when anomaly_score >= 7 (enforced by the router
    in graph.py). It does not re-check the score — that is the router's concern.

    The most recent reasoning_path entry is passed to the LLM as the "initial
    analysis" context, giving it the anomaly detection summary without re-sending
    the full trace (context budget management).
    """
    ts = _now()
    s = _step(config)
    trace_prefix = f"[step={s}][{ts}] rca_synthesis"

    # Guard: gracefully degrade near step limit
    remaining = int(state.get("remaining_steps", 10))
    if remaining <= 1:
        trace = trace_prefix + " → SKIPPED: insufficient remaining steps"
        logger.warning(trace)
        return {"reasoning_path": [trace], "final_report": None}

    try:
        llm = _llm_from_config(config)
        logs_text = json.dumps(state["raw_logs"], indent=2)

        # Use the most recent trace entry as prior context (avoids sending the
        # full reasoning_path and bloating the prompt with redundant history)
        reasoning_path: list[str] = state.get("reasoning_path") or []
        prior_summary = reasoning_path[-1] if reasoning_path else "(no prior analysis)"

        prompt = RCA_SYNTHESIS_PROMPT.format(
            anomaly_score=state.get("anomaly_score", "unknown"),
            anomaly_summary=prior_summary,
            logs=logs_text,
        )

        response = llm.invoke(prompt)
        report: str = response.content.strip()

        trace = trace_prefix + f" → report generated ({len(report)} chars)"
        logger.info(trace)
        return {
            "final_report": report,
            "reasoning_path": [trace],
        }

    except Exception as exc:
        trace = trace_prefix + f" → ERROR: {type(exc).__name__}: {exc}"
        logger.exception("rca_synthesis_node failed unexpectedly")
        return {
            "reasoning_path": [trace],
            "final_report": None,
            "error_context": f"RCA synthesis failed: {type(exc).__name__}: {exc}",
        }
