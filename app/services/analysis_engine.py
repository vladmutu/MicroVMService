import asyncio
import hashlib
from dataclasses import dataclass

from app.core.config import Settings
from app.models.contracts import AnalyzeRequest
from app.services.errors import AnalysisError, PackageResolutionError, SandboxInfraError, SandboxTimeoutError
from app.services.job_store import JobLogStore, build_log_entry
from app.services.package_resolver import PackageResolver
from app.services.risk import normalize_risk_score
from app.services.sandbox.firecracker import FirecrackerSandboxRunner
from app.services.sandbox.generic import GenericSandboxRunner
from app.services.telemetry import Telemetry


@dataclass(slots=True)
class AnalysisOutcome:
    status: str
    coverage: str
    risk_score: float | None
    timed_out: bool
    vm_evasion_observed: bool
    telemetry: Telemetry


class AnalysisEngine:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._resolver = PackageResolver(settings)
        self._generic = GenericSandboxRunner()
        self._firecracker = FirecrackerSandboxRunner(settings)
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_analyses)
        self._job_logs = JobLogStore()

    @staticmethod
    def build_job_id(request: AnalyzeRequest) -> str:
        digest = hashlib.sha256(
            f"{request.ecosystem}:{request.package_name}:{request.package_version}:{request.sandbox_type}".encode("utf-8")
        ).hexdigest()
        return digest[:24]

    async def analyze(self, request: AnalyzeRequest) -> AnalysisOutcome:
        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    self._analyze_inner(request),
                    timeout=self._settings.analysis_timeout_seconds,
                )
            except (asyncio.TimeoutError, TimeoutError):
                job_id = self.build_job_id(request)
                telemetry = Telemetry(timed_out=True).normalized()
                await self._job_logs.append(job_id, [build_log_entry("host", "warning", "analysis timed out")])
                return AnalysisOutcome(
                    status="partial",
                    coverage="partial",
                    risk_score=normalize_risk_score(telemetry, coverage="partial"),
                    timed_out=True,
                    vm_evasion_observed=False,
                    telemetry=telemetry,
            )

    async def _analyze_inner(self, request: AnalyzeRequest) -> AnalysisOutcome:
        job_id = self.build_job_id(request)
        await self._job_logs.append(job_id, [build_log_entry("host", "info", f"analysis started for {request.ecosystem}:{request.package_name}:{request.package_version}")])
        try:
            package = await self._resolver.resolve(request.ecosystem, request.package_name, request.package_version)
            self._validate_artifact_descriptor(request, package.artifact_bytes)
            await self._job_logs.append(job_id, [build_log_entry("host", "info", f"resolved artifact from {package.download_url}")])

            if request.sandbox_type == "firecracker":
                try:
                    telemetry = await self._firecracker.run(
                        request,
                        package,
                        timeout_seconds=self._settings.analysis_timeout_seconds,
                        job_id=job_id,
                    )
                finally:
                    await self._job_logs.append(job_id, self._firecracker.last_run_logs)
            else:
                telemetry = await self._generic.run(request, package, timeout_seconds=self._settings.analysis_timeout_seconds, job_id=job_id)
                await self._job_logs.append(
                    job_id,
                    [
                        build_log_entry(
                            "host",
                            "info",
                            f"generic sandbox completed with suspicious_syscalls={telemetry.suspicious_syscalls}",
                        )
                    ],
                )

            telemetry = telemetry.normalized()
            await self._job_logs.append(job_id, [build_log_entry("host", "info", f"analysis completed with status completed and coverage full")])
            return AnalysisOutcome(
                status="completed",
                coverage="full",
                risk_score=normalize_risk_score(telemetry, coverage="full"),
                timed_out=False,
                vm_evasion_observed=telemetry.vm_evasion_observed,
                telemetry=telemetry,
            )
        except SandboxTimeoutError:
            telemetry = Telemetry(timed_out=True).normalized()
            await self._job_logs.append(job_id, [build_log_entry("host", "warning", "sandbox timed out")])
            return AnalysisOutcome(
                status="partial",
                coverage="partial",
                risk_score=normalize_risk_score(telemetry, coverage="partial"),
                timed_out=True,
                vm_evasion_observed=False,
                telemetry=telemetry,
            )
        except (PackageResolutionError, SandboxInfraError, AnalysisError):
            telemetry = Telemetry().normalized()
            await self._job_logs.append(job_id, [build_log_entry("host", "error", "analysis failed")])
            return AnalysisOutcome(
                status="failed",
                coverage="none",
                risk_score=None,
                timed_out=False,
                vm_evasion_observed=False,
                telemetry=telemetry,
            )
        except asyncio.TimeoutError:
            telemetry = Telemetry(timed_out=True).normalized()
            await self._job_logs.append(job_id, [build_log_entry("host", "warning", "analysis timeout raised by orchestrator")])
            return AnalysisOutcome(
                status="partial",
                coverage="partial",
                risk_score=normalize_risk_score(telemetry, coverage="partial"),
                timed_out=True,
                vm_evasion_observed=False,
                telemetry=telemetry,
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

    async def get_job_logs(self, job_id: str):
        return await self._job_logs.get(job_id)
