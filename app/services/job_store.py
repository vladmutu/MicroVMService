import asyncio
from datetime import UTC, datetime
from typing import Literal

from app.models.contracts import JobLogEntry, JobLogsResponse


def build_log_entry(source: Literal["host", "guest", "control", "stderr", "stdout"], level: Literal["debug", "info", "warning", "error"], message: str) -> JobLogEntry:
    return JobLogEntry(
        timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        source=source,
        level=level,
        message=message,
    )


class JobLogStore:
    def __init__(self, max_entries: int = 1000) -> None:
        self._max_entries = max_entries
        self._records: dict[str, list[JobLogEntry]] = {}
        self._truncated: set[str] = set()
        self._lock = asyncio.Lock()

    async def append(self, job_id: str, entries: list[JobLogEntry]) -> None:
        if not entries:
            return

        async with self._lock:
            record = self._records.setdefault(job_id, [])
            record.extend(entries)
            if len(record) > self._max_entries:
                self._records[job_id] = record[-self._max_entries :]
                self._truncated.add(job_id)

    async def get(self, job_id: str) -> JobLogsResponse | None:
        async with self._lock:
            entries = self._records.get(job_id)
            if entries is None:
                return None

            return JobLogsResponse(job_id=job_id, entries=list(entries), truncated=job_id in self._truncated)