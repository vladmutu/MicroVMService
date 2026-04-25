import time

from fastapi import APIRouter, Depends, HTTPException, Response

from app.core.auth import optional_bearer_auth
from app.core.config import get_settings
from app.models.contracts import AnalyzeRequest, AnalyzeResponse, FilesystemChanges, JobLogsResponse, NetworkActivity, SyscallTrace
from app.services.analysis_engine import AnalysisEngine
from app.services.metrics import IN_FLIGHT, REQUEST_COUNTER, REQUEST_DURATION, metrics_payload

router = APIRouter()
engine = AnalysisEngine(get_settings())


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz() -> dict[str, str]:
    return {"status": "ready"}


@router.get("/metrics")
async def metrics() -> Response:
    payload, content_type = metrics_payload()
    return Response(content=payload, media_type=content_type)


@router.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(optional_bearer_auth)])
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    started = time.perf_counter()
    IN_FLIGHT.inc()
    try:
        outcome = await engine.analyze(request)
        REQUEST_COUNTER.labels(request.ecosystem, request.sandbox_type, outcome.status).inc()

        telemetry = outcome.telemetry
        include_fc_telemetry = request.sandbox_type == "firecracker" and outcome.coverage != "none"

        return AnalyzeResponse(
            status=outcome.status,
            coverage=outcome.coverage,
            risk_score=outcome.risk_score,
            provider=get_settings().provider_name,
            job_id=engine.build_job_id(request),
            timed_out=outcome.timed_out,
            vm_evasion_observed=outcome.vm_evasion_observed,
            syscall_trace=(
                SyscallTrace(
                    suspicious_count=telemetry.suspicious_syscalls,
                    categories=telemetry.syscall_categories or [],
                )
                if include_fc_telemetry
                else None
            ),
            network_activity=(
                NetworkActivity(
                    outbound_connections=telemetry.outbound_connections,
                    destinations=telemetry.destinations or [],
                )
                if include_fc_telemetry
                else None
            ),
            filesystem_changes=(
                FilesystemChanges(
                    sensitive_path_writes=telemetry.sensitive_writes,
                    paths=telemetry.write_paths or [],
                )
                if include_fc_telemetry
                else None
            ),
        )
    finally:
        IN_FLIGHT.dec()
        REQUEST_DURATION.observe(time.perf_counter() - started)


@router.get("/jobs/{job_id}/logs", response_model=JobLogsResponse, dependencies=[Depends(optional_bearer_auth)])
async def job_logs(job_id: str) -> JobLogsResponse:
    logs = await engine.get_job_logs(job_id)
    if logs is None:
        raise HTTPException(status_code=404, detail="Job logs not found")
    return logs


@router.get("/analyze/{job_id}/logs", response_model=JobLogsResponse, dependencies=[Depends(optional_bearer_auth)])
async def analyze_job_logs(job_id: str) -> JobLogsResponse:
    logs = await engine.get_job_logs(job_id)
    if logs is None:
        raise HTTPException(status_code=404, detail="Job logs not found")
    return logs
