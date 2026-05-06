"""
contracts.py — Pydantic v2 request/response models.

POST /analyze is the single API surface for SentinelFlow integration.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ── Request models ────────────────────────────────────────────────────

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


# ── Response models ───────────────────────────────────────────────────

class SyscallTrace(BaseModel):
    suspicious_count: int = Field(ge=0)
    categories: list[str]


class NetworkActivity(BaseModel):
    outbound_connections: int = Field(ge=0)
    destinations: list[str]


class FilesystemChanges(BaseModel):
    sensitive_path_writes: int = Field(ge=0)
    paths: list[str]


class IOCDetail(BaseModel):
    """Detailed IOC evidence from dynamic analysis."""
    verdict: str
    dynamic_hit: bool
    network_iocs: list[str] = Field(default_factory=list)
    process_iocs: list[str] = Field(default_factory=list)
    file_iocs: list[str] = Field(default_factory=list)
    dns_iocs: list[str] = Field(default_factory=list)
    crypto_iocs: list[str] = Field(default_factory=list)
    raw_line_count: int = 0
    flagged_lines: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["completed", "partial", "failed"]
    coverage: Literal["full", "partial", "none"]
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    provider: str
    job_id: str
    timed_out: bool
    vm_evasion_observed: bool

    # Firecracker telemetry (populated when sandbox_type=firecracker + coverage!=none)
    syscall_trace: SyscallTrace | None = None
    network_activity: NetworkActivity | None = None
    filesystem_changes: FilesystemChanges | None = None

    # Detailed IOC evidence (populated for firecracker runs)
    ioc_detail: IOCDetail | None = None


# ── Job log models ────────────────────────────────────────────────────

class JobLogEntry(BaseModel):
    timestamp: str
    source: Literal["host", "guest", "control", "stderr", "stdout"]
    level: Literal["debug", "info", "warning", "error"]
    message: str


class JobLogsResponse(BaseModel):
    job_id: str
    entries: list[JobLogEntry]
    truncated: bool = False
