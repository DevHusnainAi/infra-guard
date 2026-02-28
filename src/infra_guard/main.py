"""
Entry point for the Infra-Guard service.

Loads .env, configures logging, and starts Uvicorn.
HOST, PORT, and ENV are overridable via environment variables.
ENV=development enables hot-reload for local iteration.
"""

from __future__ import annotations

import logging
import os

import uvicorn
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


def _validate_env() -> None:
    """Ensure required environment variables are set."""
    if not os.getenv("GROQ_API_KEY"):
        raise RuntimeError("Missing required environment variable: GROQ_API_KEY")


def main() -> None:
    _validate_env()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    env = os.getenv("ENV", "production")

    uvicorn.run(
        "infra_guard.api:app",
        host=host,
        port=port,
        reload=(env == "development"),
        log_level="info",
    )


if __name__ == "__main__":
    main()
