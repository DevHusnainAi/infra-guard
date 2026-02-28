"""
FastAPI application layer for Infra-Guard.

Design decisions:
- This layer is a thin adapter. Zero business logic lives here. The API translates
  HTTP requests into graph invocations and graph results into HTTP responses.
- Input validation happens at the API boundary via Pydantic request models before
  the graph ever sees data. The graph trusts what it receives.
- Graph execution config (model, temperature) is injectable per-request. This
  allows callers to trade off cost vs. quality without a deployment change.
- A unique thread_id is generated per request. This makes each invocation
  independently traceable in logs and future checkpointer integrations.
- Graph errors are surfaced as structured JSON (never raw tracebacks). The
  /analyze endpoint returns 200 even for "system healthy" verdicts — the score
  and verdict fields carry the semantic result, not the HTTP status code.
- 500 is only returned on unexpected graph crashes (which should not happen per
  FR-302, but are guarded here as a belt-and-suspenders measure).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from .graph import graph

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Infra-Guard",
    description=(
        "Autonomous observability agent for cloud-native infrastructure. "
        "Ingests raw log streams, detects anomalies via Groq LPU inference, "
        "and synthesizes structured RCA reports for high-severity incidents."
    ),
    version="1.0.0",
)


# ── Request / Response models ─────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    """
    Inbound payload for the /analyze endpoint.

    raw_logs is the only required field. model and temperature allow per-request
    overrides for cost/quality trade-offs without touching deployment config.
    """

    raw_logs: list[dict[str, Any]] = Field(
        ...,
        min_length=1,
        description="List of log entry objects. Each entry must be a JSON object.",
        examples=[
            [
                {
                    "service": "payment",
                    "level": "ERROR",
                    "message": "DB connection refused",
                    "count": 42,
                }
            ]
        ],
    )
    model: str = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model ID to use for inference.",
    )
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="LLM sampling temperature. Lower = more deterministic.",
    )

    @field_validator("raw_logs")
    @classmethod
    def must_contain_at_least_one_dict(cls, v: list) -> list:
        if not any(isinstance(entry, dict) for entry in v):
            raise ValueError("At least one log entry must be a JSON object (dict).")
        return v


class AnalyzeResponse(BaseModel):
    """
    Outbound payload from the /analyze endpoint.

    Maps directly from OutputState plus a human-readable verdict string.
    """

    anomaly_score: int = Field(
        description="Detected severity score on a 1–10 scale. 0 means detection failed."
    )
    verdict: str = Field(
        description=(
            "'System Healthy' for score < 7. "
            "'Incident Detected (score=N/10)' for score >= 7."
        )
    )
    reasoning_path: list[str] = Field(
        description="Ordered trace of every state transition for auditability."
    )
    final_report: str | None = Field(
        default=None,
        description="Structured Markdown RCA report. Null when score < 7.",
    )
    error_context: str | None = Field(
        default=None,
        description="Error detail if any node failed. Null on successful runs.",
    )


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health", summary="Health check")
def health_check() -> dict[str, str]:
    """Returns 200 OK when the service is running."""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze log streams for anomalies and generate RCA",
    response_description=(
        "Analysis result including anomaly score, reasoning trace, "
        "and optional RCA report."
    ),
)
def analyze_logs(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Ingest raw log entries, detect anomalies, and optionally synthesize an RCA report.

    **Routing logic:**
    - Anomaly score **< 7** → returns `"System Healthy"` verdict. `final_report` is null.
    - Anomaly score **≥ 7** → triggers RCA synthesis. `final_report` contains a
      structured Markdown report with Impact Level and Remediation Steps.

    **Error handling:**
    - Node-level errors are captured in `error_context` and returned with a 200.
      The graph always reaches END (FR-302).
    - Only unexpected graph crashes (should not occur) return a 500.
    """
    thread_id = str(uuid.uuid4())

    config = {
        "configurable": {
            "thread_id": thread_id,
            "model": request.model,
            "temperature": request.temperature,
        },
        "recursion_limit": 10,
    }

    try:
        logger.info("[thread_id=%s] Starting analysis for %d logs", thread_id, len(request.raw_logs))
        result: dict = graph.invoke({"raw_logs": request.raw_logs}, config=config)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph execution failed: {type(exc).__name__}: {exc}",
        ) from exc

    score: int = result.get("anomaly_score", 0)
    verdict = (
        "System Healthy"
        if score < 7
        else f"Incident Detected (score={score}/10)"
    )

    return AnalyzeResponse(
        anomaly_score=score,
        verdict=verdict,
        reasoning_path=result.get("reasoning_path") or [],
        final_report=result.get("final_report"),
        error_context=result.get("error_context"),
    )
