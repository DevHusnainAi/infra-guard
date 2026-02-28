# Infra-Guard: Autonomous Observability Agent

**Infra-Guard** is a production-grade autonomous agent designed to solve "alert fatigue" and fragmented logs in cloud-native environments. Powered by **LangGraph** and **Groq's LPU inference**, it performs near-instant root-cause analysis (RCA) on raw log streams.

---

## 🔥 Features

- **Autonomous RCA**: Automatically identifies failure patterns and synthesizes detailed Markdown reports.
- **Sub-Second Reasoning**: Leverages Groq (Llama 3.3 70B) for ultra-low latency analysis.
- **Stateful Workflow**: Uses LangGraph to manage multi-step reasoning traces and logical routing.
- **Security First**: Built-in protection against prompt injection and log volume overflows.
- **Production Ready**: FastAPI layer with Pydantic validation and detailed audit trails.

## 🏗️ Architecture

Infra-Guard follows a structured **Validation → Detection → Routing → Synthesis** flow:

1.  **Validate**: Ensures logs are well-formed and timestamped.
2.  **Detect**: LLM assigns an anomaly score (1-10) and identifies patterns.
3.  **Route**: Logic determines if the incident requires a full RCA synthesis (score ≥ 7).
4.  **Synthesize**: LLM generates a structured report with impact levels and remediation steps.

## 🛠️ Tech Stack

- **Orchestration**: [LangGraph](https://github.com/langchain-ai/langgraph)
- **Inference**: [Groq](https://groq.com/) (Llama 3.3 70B)
- **API Layer**: [FastAPI](https://fastapi.tiangolo.com/)
- **State/Validation**: [Pydantic](https://docs.pydantic.dev/)
- **Package Manager**: [uv](https://github.com/astral-sh/uv)

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.13+
- [uv](https://github.com/astral-sh/uv)
- A Groq API Key

### 2. Installation
```bash
git clone https://github.com/your-username/infra-guard.git
cd infra-guard
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### 3. Run the Server
```bash
uv run python src/infra_guard/main.py
```

## 🔌 API Usage

### `POST /analyze`
Analyzes a stream of logs for anomalies.

**Request:**
```bash
curl -X POST "http://localhost:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{
       "raw_logs": [
         {"service": "payment", "level": "ERROR", "message": "Connection refused"}
       ]
     }'
```

**Response:**
```json
{
  "anomaly_score": 9,
  "verdict": "Incident Detected (score=9/10)",
  "reasoning_path": ["...", "rca_synthesis generated report"],
  "final_report": "## Root Cause Analysis Report...",
  "error_context": null
}
```

---

## 🛡️ Security & Robustness

- **Sanitization**: All log inputs are XML-escaped to prevent prompt injection.
- **Rate Limiting**: Intelligent truncation of log streams to fit context windows.
- **Graceful Degradation**: Logic-based routing ensures the system remains stable even if LLM calls fail.

## 📜 License

This project is licensed under the [MIT License](LICENSE).
