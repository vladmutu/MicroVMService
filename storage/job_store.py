from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import UUID

from models.job import AnalysisJob


class JobStore:
    def __init__(self, results_dir: Path) -> None:
        self._results_dir = Path(results_dir)
        self._results_dir.mkdir(parents=True, exist_ok=True)

    def create(self, job: AnalysisJob) -> None:
        job_dir = self._job_dir(job.job_id)
        job_dir.mkdir(parents=True, exist_ok=False)
        (job_dir / "telemetry.jsonl").touch(exist_ok=True)
        (job_dir / "logs.txt").touch(exist_ok=True)
        self._write_job_json(job)

    def update_status(self, job_id: str, status: str, **fields: Any) -> None:
        current = self.get(job_id)
        if current is None:
            raise FileNotFoundError(f"Job not found: {job_id}")

        updated = replace(
            current,
            status=status,
            verdict=fields.get("verdict", current.verdict),
            score=fields.get("score", current.score),
            evidence=fields.get("evidence", current.evidence),
        )
        self._write_job_json(updated)

    def append_telemetry(self, job_id: str, event_dict: dict[str, Any]) -> None:
        path = self._job_dir(job_id) / "telemetry.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event_dict, separators=(",", ":")) + "\n")

    def append_log(self, job_id: str, line: str) -> None:
        path = self._job_dir(job_id) / "logs.txt"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line.rstrip("\n") + "\n")

    def write_verdict(self, job_id: str, verdict_event: dict[str, Any]) -> None:
        verdict_path = self._job_dir(job_id) / "verdict.json"
        if verdict_path.exists():
            return
        tmp_path = verdict_path.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(verdict_event, handle, separators=(",", ":"), ensure_ascii=True)
        tmp_path.replace(verdict_path)

    def get(self, job_id: str) -> AnalysisJob | None:
        job_path = self._job_dir(job_id) / "job.json"
        if not job_path.exists():
            return None
        with job_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return AnalysisJob.from_dict(payload)

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[AnalysisJob]:
        jobs: list[AnalysisJob] = []
        for job_path in sorted(self._results_dir.glob("*/job.json"), reverse=True):
            with job_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            jobs.append(AnalysisJob.from_dict(payload))

        return jobs[offset : offset + limit]

    def count_jobs(self) -> int:
        return len(list(self._results_dir.glob("*/job.json")))

    def read_telemetry_events(self, job_id: str) -> list[dict[str, Any]]:
        path = self._job_dir(job_id) / "telemetry.jsonl"
        if not path.exists():
            raise FileNotFoundError(f"Telemetry file not found for {job_id}")

        events: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
        return events

    def read_logs(self, job_id: str) -> list[str]:
        path = self._job_dir(job_id) / "logs.txt"
        if not path.exists():
            raise FileNotFoundError(f"Logs file not found for {job_id}")
        with path.open("r", encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def read_verdict(self, job_id: str) -> dict[str, Any] | None:
        path = self._job_dir(job_id) / "verdict.json"
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write_job_json(self, job: AnalysisJob) -> None:
        job_path = self._job_dir(job.job_id) / "job.json"
        tmp_path = job_path.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(job.to_dict(), handle, separators=(",", ":"), ensure_ascii=True)
        tmp_path.replace(job_path)

    def _job_dir(self, job_id: str) -> Path:
        self._validate_job_id(job_id)
        return self._results_dir / job_id

    @staticmethod
    def _validate_job_id(job_id: str) -> None:
        parsed = UUID(job_id)
        if parsed.version != 4:
            raise ValueError("job_id must be uuid4")
