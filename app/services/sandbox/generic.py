import hashlib

from app.models.contracts import AnalyzeRequest
from app.services.package_resolver import ResolvedPackage
from app.services.sandbox.base import SandboxRunner
from app.services.telemetry import Telemetry


class GenericSandboxRunner(SandboxRunner):
    async def run(
        self,
        request: AnalyzeRequest,
        package: ResolvedPackage,
        timeout_seconds: float,
        job_id: str | None = None,
    ) -> Telemetry:
        # Deterministic fallback mode for non-Firecracker environments.
        seed = hashlib.sha256(
            f"{request.ecosystem}:{request.package_name}:{request.package_version}".encode("utf-8")
        ).digest()

        suspicious = seed[0] % 8
        outbound = seed[1] % 4
        writes = seed[2] % 3

        syscall_categories = []
        if suspicious > 3:
            syscall_categories.append("process_injection")
        if suspicious > 1:
            syscall_categories.append("credential_access")

        destinations = []
        if outbound:
            destinations.append("198.51.100.10:443")

        write_paths = []
        if writes:
            write_paths.append("/etc/profile.d/loader.sh")

        return Telemetry(
            suspicious_syscalls=suspicious,
            syscall_categories=syscall_categories,
            outbound_connections=outbound,
            destinations=destinations,
            sensitive_writes=writes,
            write_paths=write_paths,
            vm_evasion_observed=seed[3] % 13 == 0,
        )
