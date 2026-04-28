"""
main.py — FastAPI application with lifespan-managed resources.

Initializes PostgreSQL, VMLifecycleManager, and AnalysisEngine at startup.
Cleans up everything on shutdown.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.core.config import get_settings
from app.services.analysis_engine import AnalysisEngine
from app.services.persistence import PostgresPersistence
from app.services.sandbox.vm_lifecycle import VMLifecycleManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    # ── Startup ───────────────────────────────────────────────────
    logger.info("Starting %s (env=%s)", settings.service_name, settings.environment)

    # 1. PostgreSQL
    persistence = PostgresPersistence(settings)
    await persistence.initialize()
    app.state.persistence = persistence

    # 2. VM Lifecycle Manager
    lifecycle = VMLifecycleManager(settings, persistence=persistence)
    app.state.lifecycle = lifecycle

    # 3. Analysis Engine
    engine = AnalysisEngine(settings, persistence, lifecycle)
    app.state.engine = engine

    logger.info(
        "Ready — max_concurrent_vms=%d, cid_range=[%d..%d], tap=%s",
        settings.max_concurrent_vms,
        settings.cid_range_start,
        settings.cid_range_end,
        "enabled" if settings.tap_enabled else "disabled",
    )

    yield

    # ── Shutdown ──────────────────────────────────────────────────
    logger.info("Shutting down…")
    await persistence.close()
    logger.info("Shutdown complete")


settings = get_settings()
app = FastAPI(title=settings.service_name, version="0.1.0", lifespan=lifespan)
app.include_router(router)
