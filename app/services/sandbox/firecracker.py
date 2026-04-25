"""
firecracker.py — SandboxRunner implementation using the unified VMLifecycleManager.

Translates between the AnalysisEngine interface and the VM lifecycle.
Maps IOCEvidence → Telemetry for risk scoring.
"""

from __future__ import annotations

from app.core.config import Settings
from app.models.contracts import AnalyzeRequest
from app.services.package_resolver import ResolvedPackage
from app.services.sandbox.base import SandboxRunner
from app.services.sandbox.vm_lifecycle import VMLifecycleManager, VMRunResult
from app.services.telemetry import Telemetry


class FirecrackerSandboxRunner(SandboxRunner):
    def __init__(self, settings: Settings, lifecycle: VMLifecycleManager) -> None:
        self._settings = settings
        self._lifecycle = lifecycle
        self.last_run_result: VMRunResult | None = None

    async def run(
        self,
        request: AnalyzeRequest,
        package: ResolvedPackage,
        timeout_seconds: float,
        job_id: str | None = None,
    ) -> Telemetry:
        kernel = (
            request.firecracker_config.kernel_path
            if request.firecracker_config
            else self._settings.firecracker_default_kernel
        )
        rootfs = (
            request.firecracker_config.rootfs_path
            if request.firecracker_config
            else self._settings.firecracker_default_rootfs
        )

        result = await self._lifecycle.run_analysis(
            job_id=job_id or "unknown",
            job_type=request.ecosystem,
            package_name=request.package_name,
            artifact_bytes=package.artifact_bytes,
            kernel_path=kernel,
            rootfs_path=rootfs,
        )
        self.last_run_result = result

        # Map IOCEvidence → Telemetry for risk scoring
        ev = result.evidence
        syscall_categories: list[str] = []
        if ev.process_iocs:
            syscall_categories.append("suspicious_exec")
        if ev.crypto_iocs:
            syscall_categories.append("crypto_mining")
        if ev.file_iocs:
            syscall_categories.append("sensitive_file_access")

        destinations: list[str] = []
        for ioc in ev.network_iocs:
            # Extract IP/port from "public_ip:1.2.3.4" or "suspicious_port:4444"
            if ioc.startswith("public_ip:"):
                destinations.append(ioc.removeprefix("public_ip:"))
            elif ioc.startswith("suspicious_port:"):
                destinations.append(f"*:{ioc.removeprefix('suspicious_port:')}")

        write_paths = [
            ioc.removeprefix("sensitive_file:")
            for ioc in ev.file_iocs
            if ioc.startswith("sensitive_file:")
        ]

        return Telemetry(
            suspicious_syscalls=ev.suspicious_syscalls,
            syscall_categories=syscall_categories,
            outbound_connections=ev.outbound_connections,
            destinations=destinations,
            sensitive_writes=ev.sensitive_writes,
            write_paths=write_paths,
            vm_evasion_observed=False,
            timed_out=result.error == "analysis timed out",
        )
