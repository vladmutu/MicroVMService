from __future__ import annotations

import asyncio
from typing import Any

from config import AppConfig
from models.job import AnalysisJob
from orchestrator.vm_runner import JobResult, VMRunner
from storage.job_store import JobStore


class JobQueue:
    def __init__(self, config: AppConfig, store: JobStore, runner: VMRunner) -> None:
        self._config = config
        self._store = store
        self._runner = runner
        self._queue: asyncio.Queue[AnalysisJob] = asyncio.Queue()
        self._workers: list[asyncio.Task[Any]] = []

    async def start(self) -> None:
        await self.requeue_running_jobs()
        for worker_id in range(self._config.max_concurrent_jobs):
            self._workers.append(asyncio.create_task(self._worker_loop(worker_id)))

    async def stop(self) -> None:
        for task in self._workers:
            task.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def submit(self, job: AnalysisJob) -> None:
        await self._queue.put(job)

    async def requeue_running_jobs(self) -> None:
        for job in self._store.list_jobs(limit=10000, offset=0):
            if job.status == "running":
                self._store.update_status(job.job_id, "pending")
                await self._queue.put(job)

    async def _worker_loop(self, worker_id: int) -> None:
        _ = worker_id
        while True:
            job = await self._queue.get()
            try:
                self._store.update_status(job.job_id, "running")

                async def on_telemetry(event: dict) -> None:
                    self._store.append_telemetry(job.job_id, event)
                    if event.get("event") == "verdict":
                        self._store.write_verdict(job.job_id, event)

                async def on_log(line: str) -> None:
                    self._store.append_log(job.job_id, line)

                result: JobResult = await self._runner.run_job(job, on_telemetry=on_telemetry, on_log=on_log)
                if result.status == "done":
                    self._store.update_status(
                        job.job_id,
                        "done",
                        verdict=result.verdict,
                        score=result.score,
                        evidence=result.evidence,
                    )
                else:
                    self._store.append_log(job.job_id, f"[host-error] {result.error}")
                    self._store.update_status(job.job_id, "error")
            except Exception as exc:
                self._store.append_log(job.job_id, f"[worker-error] {exc}")
                self._store.update_status(job.job_id, "error")
            finally:
                self._queue.task_done()
