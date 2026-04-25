from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FirecrackerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kernel_path: str
    rootfs_path: str


class ArtifactDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_name: str
    artifact_suffix: str
    artifact_size: int = Field(ge=0)
    artifact_sha256: str = Field(min_length=64, max_length=64)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: Literal["npm", "pypi"]
    package_name: str = Field(min_length=1, max_length=256)
    package_version: str = Field(min_length=1, max_length=128)
    sandbox_type: Literal["generic", "firecracker"]
    firecracker_config: FirecrackerConfig | None = None
    artifact: ArtifactDescriptor | None = None


class SyscallTrace(BaseModel):
    suspicious_count: int = Field(ge=0)
    categories: list[str]


class NetworkActivity(BaseModel):
    outbound_connections: int = Field(ge=0)
    destinations: list[str]


class FilesystemChanges(BaseModel):
    sensitive_path_writes: int = Field(ge=0)
    paths: list[str]


class JobLogEntry(BaseModel):
    timestamp: str
    source: Literal["host", "guest", "control", "stderr", "stdout"]
    level: Literal["debug", "info", "warning", "error"]
    message: str


class JobLogsResponse(BaseModel):
    job_id: str
    entries: list[JobLogEntry]
    truncated: bool = False


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["completed", "partial", "failed"]
    coverage: Literal["full", "partial", "none"]
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    provider: str
    job_id: str
    timed_out: bool
    vm_evasion_observed: bool

    syscall_trace: SyscallTrace | None = None
    network_activity: NetworkActivity | None = None
    filesystem_changes: FilesystemChanges | None = None
