"""
LLM prompt templates for Infra-Guard.

Separated from graph and node logic per the clean architecture requirement (FR-6.3).

Prompt design follows Anthropic's context engineering principles:
- Structured with XML tags to give the model clear reasoning anchors.
- Minimal — only instructions that address a specific, observed behavioral requirement.
- Output format uses JSON/Markdown that appears naturally in training data; no custom
  schemas requiring heavy escaping or token overhead.
- Score rubric embedded as inline examples rather than a rule list — models generalize
  from examples better than from enumerated rules.
- Docstrings on each constant explain the rationale for non-obvious choices.
"""

ANOMALY_DETECTION_PROMPT = """\
You are an expert SRE (Site Reliability Engineer) analyzing cloud-native infrastructure logs.

<task>
Examine the log entries below and identify anomalies, failure patterns, or early signs of
system degradation. Pay special attention to:
- Cascading microservice failures (one service's errors triggering others)
- Abnormal error rate spikes relative to baseline
- Latency degradation trends
- Repeated transient failures indicating systemic instability
- Cross-service correlation patterns that suggest a shared root cause
</task>

<output_format>
Return ONLY a valid JSON object — no markdown fences, no explanation outside the JSON:
{{
  "anomaly_score": <integer 1–10>,
  "detected_patterns": ["pattern_1", "pattern_2"],
  "summary": "<one concise paragraph summarizing findings>"
}}

Score rubric (use these as anchors, not hard rules):
  1–3 → Normal variation. No action needed.
  4–6 → Degraded performance. Worth monitoring.
  7–9 → Active incident. Immediate investigation required.
  10  → Critical failure. System-wide impact.
</output_format>

<logs>
{logs}
</logs>
"""

RCA_SYNTHESIS_PROMPT = """\
You are an expert SRE performing a formal root cause analysis (RCA) for an active incident.

<context>
Anomaly score: {anomaly_score}/10
Initial analysis: {anomaly_summary}
</context>

<task>
Using the log evidence below, identify the root cause, determine the blast radius,
and produce actionable remediation steps ordered by urgency.
</task>

<output_format>
Return a structured Markdown report using EXACTLY this template — no deviations:

## Root Cause Analysis Report

### Impact Level
[Critical | High | Medium] — <one-sentence description of scope>

### Root Cause
<2–3 sentences identifying the root cause with specific evidence from the logs.
Reference log fields (service names, error messages, timestamps) directly.>

### Affected Components
- **<component>**: <description of how it is affected>

### Remediation Steps
1. **Immediate (0–15 min):** <specific action>
2. **Short-term (15–60 min):** <specific action>
3. **Long-term (post-incident):** <specific action>

### Evidence
```
<paste the most relevant log snippets here>
```
</output_format>

<logs>
{logs}
</logs>
"""
