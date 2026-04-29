"""
analysis_engine.py — Main orchestration layer.

Receives AnalyzeRequest, resolves the package, dispatches to the
appropriate sandbox runner, persists results to PostgreSQL,
and returns a structured AnalysisOutcome.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings
from app.models.contracts import AnalyzeRequest
from app.services.errors import AnalysisError, PackageResolutionError, SandboxInfraError, SandboxTimeoutError
from app.services.package_resolver import PackageResolver
from app.services.persistence import PostgresPersistence
from app.services.risk import normalize_risk_score
from app.services.sandbox.firecracker import FirecrackerSandboxRunner
from app.services.sandbox.generic import GenericSandboxRunner
from app.services.sandbox.vm_lifecycle import VMLifecycleManager
from app.services.telemetry import Telemetry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalysisOutcome:
    status: str           # "completed" | "partial" | "failed"
    coverage: str         # "full" | "partial" | "none"
    risk_score: float | None
    timed_out: bool
    vm_evasion_observed: bool
    telemetry: Telemetry
    evidence: dict[str, Any] = field(default_factory=dict)


class AnalysisEngine:
    """
    Orchestrates the full analysis workflow:
    1. Resolve package from PyPI/npm registry
    2. Dispatch to sandbox (Firecracker VM or generic fallback)
    3. Persist telemetry, logs, and verdict to PostgreSQL
    4. Return structured outcome for the API response
    """

    def __init__(
        self,
        settings: Settings,
        persistence: PostgresPersistence,
        lifecycle: VMLifecycleManager,
    ) -> None:
        self._settings = settings
        self._resolver = PackageResolver(settings)
        self._generic = GenericSandboxRunner()
        self._firecracker = FirecrackerSandboxRunner(settings, lifecycle)
        self._persistence = persistence

    @staticmethod
    def build_job_id(request: AnalyzeRequest) -> str:
        # Generate a unique job_id for each run using UUID
        # This ensures the same package analyzed multiple times gets different job_ids
        return str(uuid.uuid4())[:24]

    async def analyze(self, request: AnalyzeRequest, artifact_bytes: bytes | None = None) -> AnalysisOutcome:
        job_id = self.build_job_id(request)

        # Create job record in PostgreSQL
        await self._persistence.create_job(
            job_id=job_id,
            ecosystem=request.ecosystem,
            package_name=request.package_name,
            package_version=request.package_version,
            status="running",
        )

        try:
            outcome = await asyncio.wait_for(
                self._analyze_inner(request, job_id, artifact_bytes),
                timeout=self._settings.analysis_timeout_seconds,
            )
        except (asyncio.TimeoutError, TimeoutError):
            telemetry = Telemetry(timed_out=True).normalized()
            await self._persistence.write_log(job_id, "host", "warning", "analysis timed out")
            await self._persistence.update_job_status(job_id, "partial", risk_score=normalize_risk_score(telemetry, "partial"))
            outcome = AnalysisOutcome(
                status="partial",
                coverage="partial",
                risk_score=normalize_risk_score(telemetry, coverage="partial"),
                timed_out=True,
                vm_evasion_observed=False,
                telemetry=telemetry,
            )

        return outcome

    async def _analyze_inner(self, request: AnalyzeRequest, job_id: str, artifact_bytes: bytes | None = None) -> AnalysisOutcome:
        await self._persistence.write_log(
            job_id, "host", "info",
            f"analysis started for {request.ecosystem}:{request.package_name}:{request.package_version}",
        )

        try:
            # 1. Resolve package
            if artifact_bytes is not None:
                from app.services.package_resolver import ResolvedPackage
                package = ResolvedPackage(
                    ecosystem=request.ecosystem,
                    package_name=request.package_name,
                    package_version=request.package_version,
                    download_url="local-upload",
                    expected_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
                    artifact_bytes=artifact_bytes,
                )
            else:
                package = await self._resolver.resolve(
                    request.ecosystem, request.package_name, request.package_version,
                )
            self._validate_artifact_descriptor(request, package.artifact_bytes)
            await self._persistence.write_log(
                job_id, "host", "info", f"resolved artifact from {package.download_url}",
            )

            # 2. Run in sandbox
            if request.sandbox_type == "firecracker":
                telemetry = await self._firecracker.run(
                    request, package,
                    timeout_seconds=self._settings.vm_analysis_timeout_seconds,
                    job_id=job_id,
                )

                # Persist telemetry events and logs from VM run
                result = self._firecracker.last_run_result
                if result:
                    for event in result.telemetry_events:
                        await self._persistence.write_telemetry(job_id, event)
                    for line in result.log_lines:
                        await self._persistence.write_log(job_id, "guest", "info", line)
                    if result.relevant_runtime_events or result.relevant_runtime_summary:
                        await self._persistence.write_relevant_runtime_events(
                            job_id,
                            result.relevant_runtime_summary,
                            result.relevant_runtime_events,
                        )

                    # Build evidence dict for the API response
                    ev = result.evidence
                    evidence = {
                        "verdict": ev.verdict,
                        "dynamic_hit": ev.dynamic_hit,
                        "network_iocs": ev.network_iocs,
                        "process_iocs": ev.process_iocs,
                        "file_iocs": ev.file_iocs,
                        "dns_iocs": ev.dns_iocs,
                        "crypto_iocs": ev.crypto_iocs,
                        "raw_line_count": ev.raw_line_count,
                    }
                else:
                    evidence = {}
            else:
                telemetry = await self._generic.run(
                    request, package,
                    timeout_seconds=self._settings.analysis_timeout_seconds,
                    job_id=job_id,
                )
                evidence = {}
                await self._persistence.write_log(
                    job_id, "host", "info",
                    f"generic sandbox completed: suspicious_syscalls={telemetry.suspicious_syscalls}",
                )

            # 3. Finalize
            telemetry = telemetry.normalized()
            coverage = "partial" if telemetry.timed_out else "full"
            status = "partial" if telemetry.timed_out else "completed"
            risk_score = normalize_risk_score(telemetry, coverage=coverage)

            # Persist verdict
            verdict_str = evidence.get("verdict", "benign") if evidence else "benign"
            await self._persistence.write_verdict(job_id, verdict_str, risk_score, evidence)
            await self._persistence.update_job_status(
                job_id, status, verdict=verdict_str,
                risk_score=risk_score, evidence=evidence,
            )

            await self._persistence.write_log(
                job_id, "host", "info",
                f"analysis {status} — verdict={verdict_str} risk_score={risk_score}",
            )

            return AnalysisOutcome(
                status=status,
                coverage=coverage,
                risk_score=risk_score,
                timed_out=telemetry.timed_out,
                vm_evasion_observed=telemetry.vm_evasion_observed,
                telemetry=telemetry,
                evidence=evidence,
            )

        except SandboxTimeoutError:
            telemetry = Telemetry(timed_out=True).normalized()
            await self._persistence.write_log(job_id, "host", "warning", "sandbox timed out")
            await self._persistence.update_job_status(job_id, "partial")
            return AnalysisOutcome(
                status="partial", coverage="partial",
                risk_score=normalize_risk_score(telemetry, "partial"),
                timed_out=True, vm_evasion_observed=False, telemetry=telemetry,
            )

        except (PackageResolutionError, SandboxInfraError, AnalysisError) as exc:
            telemetry = Telemetry().normalized()
            await self._persistence.write_log(job_id, "host", "error", f"analysis failed: {exc}")
            await self._persistence.update_job_status(job_id, "failed")
            return AnalysisOutcome(
                status="failed", coverage="none",
                risk_score=None,
                timed_out=False, vm_evasion_observed=False, telemetry=telemetry,
            )

    @staticmethod
    def _validate_artifact_descriptor(request: AnalyzeRequest, artifact_bytes: bytes) -> None:
        if request.artifact is None:
            return
        if len(artifact_bytes) != request.artifact.artifact_size:
            raise PackageResolutionError("Artifact size mismatch")
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        if digest != request.artifact.artifact_sha256:
            raise PackageResolutionError("Artifact sha256 mismatch")
