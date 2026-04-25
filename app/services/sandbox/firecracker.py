import json
import inspect

from app.core.config import Settings
from app.models.contracts import AnalyzeRequest
from app.services.errors import SandboxInfraError
from app.services.job_store import build_log_entry
from app.services.package_resolver import ResolvedPackage
from app.services.sandbox.base import SandboxRunner
from app.services.sandbox.firecracker_manager import FirecrackerManager
from app.services.telemetry import Telemetry


class FirecrackerSandboxRunner(SandboxRunner):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._manager = FirecrackerManager(settings)
        self.last_run_logs = []

    async def run(
        self,
        request: AnalyzeRequest,
        package: ResolvedPackage,
        timeout_seconds: float,
        job_id: str | None = None,
    ) -> Telemetry:
        kernel = request.firecracker_config.kernel_path if request.firecracker_config else self._settings.firecracker_default_kernel
        rootfs = request.firecracker_config.rootfs_path if request.firecracker_config else self._settings.firecracker_default_rootfs

        try:
            result = await self._manager.run_vm(
                kernel,
                rootfs,
                request.ecosystem,
                request.package_name,
                package.artifact_bytes,
                timeout_seconds,
                job_id=job_id,
            )
        except Exception as exc:
            self.last_run_logs = list(self._manager.last_run_logs)
            self.last_run_logs.append(build_log_entry("host", "error", f"firecracker manager error: {exc}"))
            raise
        guest_logs = getattr(result, "guest_logs", [])
        self.last_run_logs = list(guest_logs) if isinstance(guest_logs, list) else []

        stdout_text = getattr(result, "stdout", "")
        stderr_text = getattr(result, "stderr", "")
        if not isinstance(stdout_text, str) or inspect.isawaitable(stdout_text):
            stdout_text = ""
        if not isinstance(stderr_text, str) or inspect.isawaitable(stderr_text):
            stderr_text = ""

        if isinstance(stdout_text, str) and stdout_text.strip():
            self.last_run_logs.append(build_log_entry("stdout", "info", stdout_text.strip()))
        if isinstance(stderr_text, str) and stderr_text.strip():
            self.last_run_logs.append(build_log_entry("stderr", "warning", stderr_text.strip()))

        try:
            telemetry_payload = getattr(result, "telemetry_payload", None)
            if not isinstance(telemetry_payload, dict) or inspect.isawaitable(telemetry_payload):
                telemetry_payload = None
            if telemetry_payload is not None:
                payload = telemetry_payload
            else:
                payload = json.loads(stdout_text) if isinstance(stdout_text, str) and stdout_text.strip() else {}
        except json.JSONDecodeError as exc:
            raise SandboxInfraError("Invalid telemetry format from guest VM") from exc

        return Telemetry(
            suspicious_syscalls=int(payload.get("suspicious_syscalls", 0)),
            syscall_categories=list(payload.get("syscall_categories", [])),
            outbound_connections=int(payload.get("outbound_connections", 0)),
            destinations=list(payload.get("destinations", [])),
            sensitive_writes=int(payload.get("sensitive_writes", 0)),
            write_paths=list(payload.get("write_paths", [])),
            vm_evasion_observed=bool(payload.get("vm_evasion_observed", False)),
        )
