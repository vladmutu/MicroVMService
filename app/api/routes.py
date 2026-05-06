"""
routes.py — API endpoints.

POST /analyze — SentinelFlow-compatible synchronous analysis endpoint.
GET  /healthz, /readyz — health checks.
GET  /metrics — Prometheus metrics.
GET  /jobs/{job_id}/logs — per-job log retrieval.
"""

import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, File, Form, UploadFile

from app.core.auth import optional_bearer_auth
from app.core.config import get_settings
from app.models.contracts import (
    AnalyzeRequest,
    AnalyzeResponse,
    FilesystemChanges,
    IOCDetail,
    JobLogsResponse,
    NetworkActivity,
    SyscallTrace,
)
from app.services.analysis_engine import AnalysisEngine
from app.services.metrics import IN_FLIGHT, REQUEST_COUNTER, REQUEST_DURATION, metrics_payload

router = APIRouter()


def _get_engine(request: Request) -> AnalysisEngine:
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="Analysis engine not initialized")
    return engine


# ── Health ────────────────────────────────────────────────────────────

@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> dict[str, str]:
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="Not ready")
    return {"status": "ready"}


@router.get("/metrics")
async def metrics() -> Response:
    payload, content_type = metrics_payload()
    return Response(content=payload, media_type=content_type)


# ── Analysis ──────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(optional_bearer_auth)])
async def analyze(body: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    engine = _get_engine(request)
    settings = get_settings()

    started = time.perf_counter()
    IN_FLIGHT.inc()
    try:
        outcome = await engine.analyze(body)
        REQUEST_COUNTER.labels(body.ecosystem, body.sandbox_type, outcome.status).inc()

        telemetry = outcome.telemetry
        include_fc = body.sandbox_type == "firecracker" and outcome.coverage != "none"

        # Build IOC detail from evidence
        ioc_detail = None
        if include_fc and outcome.evidence:
            ioc_detail = IOCDetail(
                verdict=outcome.evidence.get("verdict", "benign"),
                dynamic_hit=outcome.evidence.get("dynamic_hit", False),
                network_iocs=outcome.evidence.get("network_iocs", []),
                process_iocs=outcome.evidence.get("process_iocs", []),
                file_iocs=outcome.evidence.get("file_iocs", []),
                dns_iocs=outcome.evidence.get("dns_iocs", []),
                crypto_iocs=outcome.evidence.get("crypto_iocs", []),
                raw_line_count=outcome.evidence.get("raw_line_count", 0),
                flagged_lines=outcome.evidence.get("flagged_lines", []),
            )

        return AnalyzeResponse(
            status=outcome.status,
            coverage=outcome.coverage,
            risk_score=outcome.risk_score,
            provider=settings.provider_name,
            job_id=outcome.job_id,
            timed_out=outcome.timed_out,
            vm_evasion_observed=outcome.vm_evasion_observed,
            syscall_trace=(
                SyscallTrace(
                    suspicious_count=telemetry.suspicious_syscalls,
                    categories=telemetry.syscall_categories or [],
                )
                if include_fc else None
            ),
            network_activity=(
                NetworkActivity(
                    outbound_connections=telemetry.outbound_connections,
                    destinations=telemetry.destinations or [],
                )
                if include_fc else None
            ),
            filesystem_changes=(
                FilesystemChanges(
                    sensitive_path_writes=telemetry.sensitive_writes,
                    paths=telemetry.write_paths or [],
                )
                if include_fc else None
            ),
            ioc_detail=ioc_detail,
        )
    finally:
        IN_FLIGHT.dec()
        REQUEST_DURATION.observe(time.perf_counter() - started)


@router.post("/analyze/upload", response_model=AnalyzeResponse, dependencies=[Depends(optional_bearer_auth)])
async def analyze_upload(
    request: Request,
    ecosystem: Literal["npm", "pypi"] = Form(...),
    package_name: str = Form(...),
    package_version: str = Form(default="unknown"),
    sandbox_type: Literal["generic", "firecracker"] = Form(...),
    file: UploadFile = File(...),
) -> AnalyzeResponse:
    """Analyze a locally uploaded package archive (supports .whl, .tar.gz, .zip, .tgz)."""
    engine = _get_engine(request)
    settings = get_settings()

    body = AnalyzeRequest(
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        sandbox_type=sandbox_type,
    )

    artifact_bytes = await file.read()
    artifact_filename = file.filename or None

    started = time.perf_counter()
    IN_FLIGHT.inc()
    try:
        outcome = await engine.analyze(body, artifact_bytes=artifact_bytes, artifact_filename=artifact_filename)
        REQUEST_COUNTER.labels(body.ecosystem, body.sandbox_type, outcome.status).inc()

        telemetry = outcome.telemetry
        include_fc = body.sandbox_type == "firecracker" and outcome.coverage != "none"

        ioc_detail = None
        if include_fc and outcome.evidence:
            ioc_detail = IOCDetail(
                verdict=outcome.evidence.get("verdict", "benign"),
                dynamic_hit=outcome.evidence.get("dynamic_hit", False),
                network_iocs=outcome.evidence.get("network_iocs", []),
                process_iocs=outcome.evidence.get("process_iocs", []),
                file_iocs=outcome.evidence.get("file_iocs", []),
                dns_iocs=outcome.evidence.get("dns_iocs", []),
                crypto_iocs=outcome.evidence.get("crypto_iocs", []),
                raw_line_count=outcome.evidence.get("raw_line_count", 0),
                flagged_lines=outcome.evidence.get("flagged_lines", []),
            )

        return AnalyzeResponse(
            status=outcome.status,
            coverage=outcome.coverage,
            risk_score=outcome.risk_score,
            provider=settings.provider_name,
            job_id=outcome.job_id,
            timed_out=outcome.timed_out,
            vm_evasion_observed=outcome.vm_evasion_observed,
            syscall_trace=(
                SyscallTrace(
                    suspicious_count=telemetry.suspicious_syscalls,
                    categories=telemetry.syscall_categories or [],
                )
                if include_fc else None
            ),
            network_activity=(
                NetworkActivity(
                    outbound_connections=telemetry.outbound_connections,
                    destinations=telemetry.destinations or [],
                )
                if include_fc else None
            ),
            filesystem_changes=(
                FilesystemChanges(
                    sensitive_path_writes=telemetry.sensitive_writes,
                    paths=telemetry.write_paths or [],
                )
                if include_fc else None
            ),
            ioc_detail=ioc_detail,
        )
    finally:
        IN_FLIGHT.dec()
        REQUEST_DURATION.observe(time.perf_counter() - started)


# ── Job logs ──────────────────────────────────────────────────────────

@router.get("/jobs/{job_id}/logs", response_model=JobLogsResponse, dependencies=[Depends(optional_bearer_auth)])
async def job_logs(job_id: str, request: Request) -> JobLogsResponse:
    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(status_code=503, detail="Persistence not initialized")

    rows = await persistence.get_logs(job_id)
    if not rows:
        raise HTTPException(status_code=404, detail="Job logs not found")

    from app.models.contracts import JobLogEntry
    entries = [
        JobLogEntry(
            timestamp=str(row["observed_at"]),
            source=row["source"],
            level=row["level"],
            message=row["message"],
        )
        for row in rows
    ]
    return JobLogsResponse(job_id=job_id, entries=entries)


@router.get("/analyze/{job_id}/logs", response_model=JobLogsResponse, dependencies=[Depends(optional_bearer_auth)])
async def analyze_job_logs(job_id: str, request: Request) -> JobLogsResponse:
    return await job_logs(job_id, request)


# ── Per-job pip output ────────────────────────────────────────────────

@router.get("/jobs/{job_id}/pip-output", dependencies=[Depends(optional_bearer_auth)])
async def job_pip_output(job_id: str, request: Request) -> dict:
    """Return pip/npm stdout lines captured during the analysis."""
    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(status_code=503, detail="Persistence not initialized")
    rows = await persistence.get_pip_output(job_id)
    if rows is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "lines": rows}


# ── Per-job IOC events ────────────────────────────────────────────────

@router.get("/jobs/{job_id}/ioc-events", dependencies=[Depends(optional_bearer_auth)])
async def job_ioc_events(job_id: str, request: Request) -> dict:
    """Return structured IOC events detected during analysis with score contributions."""
    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(status_code=503, detail="Persistence not initialized")
    rows = await persistence.get_ioc_events(job_id)
    total_score = sum(r.get("score_contribution", 0) for r in rows)
    return {"job_id": job_id, "total_score": total_score, "events": rows}


# ── Active VM slots ───────────────────────────────────────────────────

@router.get("/slots")
async def vm_slots(request: Request) -> dict:
    """Return live IP assignments for all currently running microVMs."""
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        return {"active": [], "available_slots": 0}
    lifecycle = getattr(engine, "_firecracker", None)
    lc = getattr(lifecycle, "_lifecycle", None)
    active = lc.active_vms if lc is not None else []
    available = lc.available_slots if lc is not None else 0
    return {"active": active, "available_slots": available}
