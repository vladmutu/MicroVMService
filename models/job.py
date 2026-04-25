from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class AnalysisJob:
    job_id: str
    job_type: str
    package: str
    artifact_path: Path | None
    submitted_at: datetime
    status: str
    verdict: str | None
    score: int | None
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["artifact_path"] = str(self.artifact_path) if self.artifact_path else None
        data["submitted_at"] = self.submitted_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisJob":
        submitted = data.get("submitted_at")
        if isinstance(submitted, str):
            submitted_at = datetime.fromisoformat(submitted.replace("Z", "+00:00"))
        else:
            submitted_at = datetime.now(UTC)

        artifact_path_raw = data.get("artifact_path")
        artifact_path = Path(artifact_path_raw) if artifact_path_raw else None

        return cls(
            job_id=str(data["job_id"]),
            job_type=str(data["job_type"]),
            package=str(data["package"]),
            artifact_path=artifact_path,
            submitted_at=submitted_at,
            status=str(data.get("status", "pending")),
            verdict=data.get("verdict"),
            score=data.get("score"),
            evidence=dict(data.get("evidence") or {}),
        )
