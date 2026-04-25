from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from models.job import AnalysisJob
from orchestrator.queue import JobQueue
from storage.job_store import JobStore

router = APIRouter()

ALLOWED_ARTIFACT_SUFFIXES: dict[str, tuple[str, ...]] = {
    "pypi": (".whl", ".tar.gz", ".zip"),
    "npm": (".tgz", ".zip"),
}


def _artifact_suffix(filename: str) -> str:
    lowered = filename.lower()
    if lowered.endswith(".tar.gz"):
        return ".tar.gz"
    path = Path(lowered)
    return path.suffix


def _store_from_request(request: Request) -> JobStore:
    store = getattr(request.app.state, "job_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Job store not initialized")
    return store


def _queue_from_request(request: Request) -> JobQueue:
    queue = getattr(request.app.state, "job_queue", None)
    if queue is None:
        raise HTTPException(status_code=503, detail="Job queue not initialized")
    return queue


@router.post("/jobs")
async def submit_job(
    request: Request,
    package: str = Form(...),
    job_type: str = Form(...),
    artifact: UploadFile | None = File(default=None),
) -> JSONResponse:
    if job_type not in {"pypi", "npm"}:
        raise HTTPException(status_code=422, detail="job_type must be pypi or npm")

    store = _store_from_request(request)
    queue = _queue_from_request(request)

    artifact_path: Path | None = None
    if artifact is not None:
        filename = (artifact.filename or "artifact.bin").strip()
        suffix = _artifact_suffix(filename)
        allowed = ALLOWED_ARTIFACT_SUFFIXES[job_type]
        if suffix not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"Unsupported artifact extension '{suffix or 'none'}' for {job_type}. Allowed: {', '.join(allowed)}",
            )

        fd, temp_path = tempfile.mkstemp(prefix="job-artifact-", suffix=suffix or ".bin", dir="/tmp")
        artifact_path = Path(temp_path)
        try:
            with open(fd, "wb", closefd=True) as handle:
                while True:
                    chunk = await artifact.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
        finally:
            await artifact.close()

    job = AnalysisJob(
        job_id=str(uuid4()),
        job_type=job_type,
        package=package,
        artifact_path=artifact_path,
        submitted_at=datetime.now(UTC),
        status="pending",
        verdict=None,
        score=None,
        evidence={},
    )

    store.create(job)
    await queue.submit(job)
    return JSONResponse(status_code=202, content={"job_id": job.job_id, "status": job.status})


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> dict[str, Any]:
    store = _store_from_request(request)
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.to_dict()


@router.get("/jobs/{job_id}/telemetry")
async def get_job_telemetry(job_id: str, request: Request) -> dict[str, Any]:
    store = _store_from_request(request)
    if store.get(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"events": store.read_telemetry_events(job_id)}


@router.get("/jobs/{job_id}/logs")
async def get_job_logs(job_id: str, request: Request) -> dict[str, Any]:
    store = _store_from_request(request)
    if store.get(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"lines": store.read_logs(job_id)}


@router.get("/jobs/{job_id}/verdict")
async def get_job_verdict(job_id: str, request: Request) -> dict[str, Any]:
    store = _store_from_request(request)
    if store.get(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    verdict = store.read_verdict(job_id)
    if verdict is None:
        raise HTTPException(status_code=404, detail="Verdict not available")
    return verdict


@router.get("/jobs")
async def list_jobs(request: Request, limit: int = 20, offset: int = 0) -> dict[str, Any]:
    store = _store_from_request(request)
    safe_limit = max(1, min(limit, 200))
    safe_offset = max(0, offset)
    jobs = [job.to_dict() for job in store.list_jobs(limit=safe_limit, offset=safe_offset)]
    return {"jobs": jobs, "total": store.count_jobs()}
