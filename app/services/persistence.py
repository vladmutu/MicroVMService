"""
persistence.py — Mandatory PostgreSQL persistence layer.

Stores telemetry events, log lines, and analysis verdicts for every job.
The connection pool is initialized once at application startup and shared
across all analysis runs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings

logger = logging.getLogger(__name__)


class PostgresPersistence:
    """Mandatory PostgreSQL persistence for all analysis data."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool: Any | None = None
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        return self._pool is not None

    async def initialize(self) -> None:
        """Initialize the connection pool and ensure schema exists. Must be called at startup."""
        async with self._lock:
            if self._pool is not None:
                return

            try:
                import asyncpg
            except ImportError as exc:
                raise RuntimeError(
                    "asyncpg is required for PostgreSQL persistence. "
                    "Install it with: pip install asyncpg"
                ) from exc

            try:
                self._pool = await asyncpg.create_pool(
                    dsn=self._settings.postgres_dsn,
                    min_size=self._settings.postgres_pool_min_size,
                    max_size=self._settings.postgres_pool_max_size,
                    timeout=self._settings.postgres_connect_timeout_seconds,
                )
            except Exception as exc:
                raise RuntimeError(f"Failed to connect to PostgreSQL: {exc}") from exc

            await self._ensure_schema()
            logger.info("PostgreSQL persistence initialized")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL connection pool closed")

    # ── Write operations ──────────────────────────────────────────────

    async def create_job(
        self,
        job_id: str,
        ecosystem: str,
        package_name: str,
        package_version: str,
        status: str = "pending",
    ) -> None:
        if self._pool is None:
            return
        await self._pool.execute(
            """
            INSERT INTO analysis_jobs (job_id, ecosystem, package_name, package_version, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (job_id) DO NOTHING
            """,
            job_id, ecosystem, package_name, package_version, status, datetime.now(UTC),
        )

    async def update_job_status(
        self,
        job_id: str,
        status: str,
        verdict: str | None = None,
        risk_score: float | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        if self._pool is None:
            return
        await self._pool.execute(
            """
            UPDATE analysis_jobs
            SET status = $2, verdict = $3, risk_score = $4, evidence = $5::jsonb,
                finished_at = $6
            WHERE job_id = $1
            """,
            job_id, status, verdict, risk_score,
            json.dumps(evidence or {}, separators=(",", ":")),
            datetime.now(UTC),
        )

    async def write_telemetry(self, job_id: str, payload: str) -> None:
        """
        Store a raw telemetry line (plain text) observed from the guest.
        """
        if self._pool is None:
            return
        await self._pool.execute(
            """
            INSERT INTO analysis_telemetry_events (job_id, observed_at, payload)
            VALUES ($1, $2, $3)
            """,
            job_id, datetime.now(UTC), payload,
        )

    async def write_log(self, job_id: str, source: str, level: str, message: str) -> None:
        if self._pool is None:
            return
        await self._pool.execute(
            """
            INSERT INTO analysis_log_events (job_id, observed_at, source, level, message)
            VALUES ($1, $2, $3, $4, $5)
            """,
            job_id, datetime.now(UTC), source, level, message,
        )

    async def write_suspicious_line(self, job_id: str, line: str, category: str | None = None) -> None:
        """
        Store a single suspicious line observed by the IOC detector for later review.
        """
        if self._pool is None:
            return
        await self._pool.execute(
            """
            INSERT INTO analysis_suspicious_lines (job_id, observed_at, category, line)
            VALUES ($1, $2, $3, $4)
            """,
            job_id, datetime.now(UTC), category or "", line,
        )

    async def write_verdict(
        self,
        job_id: str,
        verdict: str,
        risk_score: float | None,
        evidence: dict[str, Any],
    ) -> None:
        if self._pool is None:
            return
        await self._pool.execute(
            """
            INSERT INTO analysis_verdicts (job_id, verdict, risk_score, evidence, created_at)
            VALUES ($1, $2, $3, $4::jsonb, $5)
            ON CONFLICT (job_id) DO UPDATE
            SET verdict = $2, risk_score = $3, evidence = $4::jsonb
            """,
            job_id, verdict, risk_score,
            json.dumps(evidence, separators=(",", ":")),
            datetime.now(UTC),
        )

    async def write_relevant_runtime_events(
        self,
        job_id: str,
        summary: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        """Store cleaned, malware-relevant runtime telemetry for later review."""
        if self._pool is None:
            return
        await self._pool.execute(
            """
            INSERT INTO analysis_relevant_runtime_events
                (job_id, created_at, event_count, syscall_count, process_count, network_count,
                 file_count, dns_count, artifact_count, summary, events)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb)
            ON CONFLICT (job_id) DO UPDATE
            SET created_at = EXCLUDED.created_at,
                event_count = EXCLUDED.event_count,
                syscall_count = EXCLUDED.syscall_count,
                process_count = EXCLUDED.process_count,
                network_count = EXCLUDED.network_count,
                file_count = EXCLUDED.file_count,
                dns_count = EXCLUDED.dns_count,
                artifact_count = EXCLUDED.artifact_count,
                summary = EXCLUDED.summary,
                events = EXCLUDED.events
            """,
            job_id,
            datetime.now(UTC),
            int(summary.get("event_count", len(events))),
            int(summary.get("syscall_count", 0)),
            int(summary.get("process_count", 0)),
            int(summary.get("network_count", 0)),
            int(summary.get("file_count", 0)),
            int(summary.get("dns_count", 0)),
            int(summary.get("artifact_count", 0)),
            json.dumps(summary, separators=(",", ":")),
            json.dumps(events, separators=(",", ":")),
        )

    # ── Read operations ───────────────────────────────────────────────

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        if self._pool is None:
            return None
        row = await self._pool.fetchrow(
            "SELECT * FROM analysis_jobs WHERE job_id = $1", job_id,
        )
        return dict(row) if row else None

    async def get_telemetry(self, job_id: str) -> list[str]:
        if self._pool is None:
            return []
        rows = await self._pool.fetch(
            "SELECT payload FROM analysis_telemetry_events WHERE job_id = $1 ORDER BY observed_at",
            job_id,
        )
        return [row["payload"] for row in rows]

    async def get_logs(self, job_id: str) -> list[dict[str, str]]:
        if self._pool is None:
            return []
        rows = await self._pool.fetch(
            "SELECT observed_at, source, level, message FROM analysis_log_events WHERE job_id = $1 ORDER BY observed_at",
            job_id,
        )
        return [dict(row) for row in rows]

    async def get_verdict(self, job_id: str) -> dict[str, Any] | None:
        if self._pool is None:
            return None
        row = await self._pool.fetchrow(
            "SELECT * FROM analysis_verdicts WHERE job_id = $1", job_id,
        )
        return dict(row) if row else None

    # ── Schema ────────────────────────────────────────────────────────

    async def _ensure_schema(self) -> None:
        if self._pool is None:
            return

        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                job_id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                verdict TEXT,
                risk_score DOUBLE PRECISION,
                evidence JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL,
                finished_at TIMESTAMPTZ
            )
        """)
        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS analysis_telemetry_events (
                id BIGSERIAL PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id),
                observed_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS analysis_log_events (
                id BIGSERIAL PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id),
                observed_at TIMESTAMPTZ NOT NULL,
                source TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS analysis_verdicts (
                job_id TEXT PRIMARY KEY REFERENCES analysis_jobs(job_id),
                verdict TEXT NOT NULL,
                risk_score DOUBLE PRECISION,
                evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL
            )
        """)
        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS analysis_relevant_runtime_events (
                job_id TEXT PRIMARY KEY REFERENCES analysis_jobs(job_id),
                created_at TIMESTAMPTZ NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                syscall_count INTEGER NOT NULL DEFAULT 0,
                process_count INTEGER NOT NULL DEFAULT 0,
                network_count INTEGER NOT NULL DEFAULT 0,
                file_count INTEGER NOT NULL DEFAULT 0,
                dns_count INTEGER NOT NULL DEFAULT 0,
                artifact_count INTEGER NOT NULL DEFAULT 0,
                summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                events JSONB NOT NULL DEFAULT '[]'::jsonb
            )
        """)

        # Indexes for common queries
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_telemetry_job_id ON analysis_telemetry_events(job_id)
        """)
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_log_events_job_id ON analysis_log_events(job_id)
        """)
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status)
        """)
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_relevant_runtime_events_job_id ON analysis_relevant_runtime_events(job_id)
        """)

        # Table for storing individual suspicious lines observed during analysis
        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS analysis_suspicious_lines (
                id BIGSERIAL PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id),
                observed_at TIMESTAMPTZ NOT NULL,
                category TEXT,
                line TEXT NOT NULL
            )
        """)

        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_suspicious_lines_job_id ON analysis_suspicious_lines(job_id)
        """)

        logger.info("PostgreSQL schema verified")