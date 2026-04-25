import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings


class PostgresPersistence:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        self._pool: Any | None = None
        self._enabled = bool(settings.postgres_dsn)
        self._lock = asyncio.Lock()
        self._create_pool = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def initialize(self) -> None:
        if not self._enabled:
            return

        async with self._lock:
            if self._pool is not None:
                return

            if self._create_pool is None:
                try:
                    import asyncpg  # type: ignore
                except ImportError:
                    self._logger.warning("PostgreSQL persistence disabled: asyncpg is not installed")
                    self._enabled = False
                    return
                self._create_pool = asyncpg.create_pool

            try:
                self._pool = await self._create_pool(
                    dsn=self._settings.postgres_dsn,
                    min_size=self._settings.postgres_pool_min_size,
                    max_size=self._settings.postgres_pool_max_size,
                    timeout=self._settings.postgres_connect_timeout_seconds,
                )
            except Exception:
                self._logger.exception("PostgreSQL persistence disabled: failed to connect to database")
                self._enabled = False
                self._pool = None
                return

            await self._ensure_schema()

    async def close(self) -> None:
        if self._pool is None:
            return
        await self._pool.close()
        self._pool = None

    async def write_telemetry(self, job_id: str, payload: dict[str, Any]) -> None:
        if not self._enabled or self._pool is None:
            return

        await self._pool.execute(
            """
            INSERT INTO analysis_telemetry_events (job_id, observed_at, payload)
            VALUES ($1, $2, $3::jsonb)
            """,
            job_id,
            datetime.now(UTC),
            json.dumps(payload, separators=(",", ":")),
        )

    async def write_log(self, job_id: str, source: str, level: str, message: str) -> None:
        if not self._enabled or self._pool is None:
            return

        await self._pool.execute(
            """
            INSERT INTO analysis_log_events (job_id, observed_at, source, level, message)
            VALUES ($1, $2, $3, $4, $5)
            """,
            job_id,
            datetime.now(UTC),
            source,
            level,
            message,
        )

    async def _ensure_schema(self) -> None:
        if self._pool is None:
            return

        await self._pool.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_telemetry_events (
                id BIGSERIAL PRIMARY KEY,
                job_id TEXT NOT NULL,
                observed_at TIMESTAMPTZ NOT NULL,
                payload JSONB NOT NULL
            )
            """
        )
        await self._pool.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_log_events (
                id BIGSERIAL PRIMARY KEY,
                job_id TEXT NOT NULL,
                observed_at TIMESTAMPTZ NOT NULL,
                source TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )