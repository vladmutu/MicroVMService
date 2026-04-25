from __future__ import annotations

from fastapi import FastAPI

from api.routes import router
from config import AppConfig, load_config
from orchestrator.queue import JobQueue
from orchestrator.vm_runner import VMRunner
from storage.job_store import JobStore

app = FastAPI(title="MicroVM Package Analyzer")


@app.on_event("startup")
async def startup() -> None:
    config: AppConfig = load_config()
    store = JobStore(config.vm.results_dir)
    runner = VMRunner(config.vm)
    queue = JobQueue(config, store, runner)

    app.state.config = config
    app.state.job_store = store
    app.state.job_queue = queue

    await queue.start()


@app.on_event("shutdown")
async def shutdown() -> None:
    queue: JobQueue | None = getattr(app.state, "job_queue", None)
    if queue is not None:
        await queue.stop()


app.include_router(router)
