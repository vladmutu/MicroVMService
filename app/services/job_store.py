"""
job_store.py — Helper utilities for building structured log entries.

The actual persistence is handled by PostgresPersistence.
This module provides the JobLogEntry builder used throughout the codebase.
"""

from datetime import UTC, datetime
from typing import Literal

from app.models.contracts import JobLogEntry


def build_log_entry(
    source: Literal["host", "guest", "control", "stderr", "stdout"],
    level: Literal["debug", "info", "warning", "error"],
    message: str,
) -> JobLogEntry:
    return JobLogEntry(
        timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        source=source,
        level=level,
        message=message,
    )