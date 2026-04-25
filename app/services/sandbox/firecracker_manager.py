import asyncio
import json
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.core.config import Settings
from app.models.contracts import JobLogEntry
from app.services.errors import SandboxInfraError, SandboxTimeoutError
from app.services.job_store import build_log_entry
from app.services.persistence import PostgresPersistence


@dataclass(slots=True)
class MicroVMWorkspace:
    job_id: str
    workspace_dir: Path
    rootfs_path: Path
    api_socket_path: Path
    vsock_socket_path: Path
    telemetry_socket_path: Path
    log_socket_path: Path
    artifact_path: Path


@dataclass(slots=True)
class FirecrackerRunResult:
    stdout: str
    stderr: str
    guest_logs: list[JobLogEntry]
    telemetry_payload: dict[str, object] | None = None


class MicroVMManager:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.last_run_logs: list[JobLogEntry] = []

    def create_workspace(self, job_id: str | None, rootfs_path: str) -> MicroVMWorkspace:
        resolved_job_id = job_id or f"job-{next(tempfile._get_candidate_names())}"
        jobs_root = Path(self._settings.firecracker_workdir) / "jobs"
        jobs_root.mkdir(parents=True, exist_ok=True)

        workspace_dir = Path(tempfile.mkdtemp(prefix=f"{resolved_job_id}-", dir=jobs_root))
        rootfs_copy = workspace_dir / "rootfs.ext4"
        shutil.copy2(rootfs_path, rootfs_copy)

        return MicroVMWorkspace(
            job_id=resolved_job_id,
            workspace_dir=workspace_dir,
            rootfs_path=rootfs_copy,
            api_socket_path=workspace_dir / "api.socket",
            vsock_socket_path=workspace_dir / "v.sock",
            telemetry_socket_path=workspace_dir / "v.sock_7001",
            log_socket_path=workspace_dir / "v.sock_7002",
            artifact_path=workspace_dir / "artifact.bin",
        )

    def build_launch_command(self, workspace: MicroVMWorkspace) -> list[str]:
        return [
            self._settings.firecracker_binary,
            "--api-sock",
            str(workspace.api_socket_path),
        ]

    def launch_firecracker(self, workspace: MicroVMWorkspace) -> subprocess.Popen[bytes]:
        command = self.build_launch_command(workspace)
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError as exc:
            raise SandboxInfraError("Firecracker binary missing") from exc
        return proc

    async def launch_firecracker_async(self, workspace: MicroVMWorkspace) -> subprocess.Popen[bytes]:
        proc = self.launch_firecracker(workspace)
        await self._wait_for_socket_file(workspace.api_socket_path)
        return proc

    async def configure_vm(self, workspace: MicroVMWorkspace, kernel_path: str) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(workspace.api_socket_path))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=httpx.Timeout(10.0)) as client:
            await self._put(client, "/boot-source", {
                "kernel_image_path": kernel_path,
                "boot_args": self._settings.firecracker_boot_args,
            })
            await self._put(client, "/drives/rootfs", {
                "drive_id": "rootfs",
                "path_on_host": str(workspace.rootfs_path),
                "is_root_device": True,
                "is_read_only": False,
            })
            await self._put(client, "/vsock", {
                "guest_cid": self._settings.firecracker_guest_cid,
                "uds_path": str(workspace.vsock_socket_path),
            })
            await self._put(client, "/actions", {"action_type": "InstanceStart"})

    async def stream_job_to_guest(
        self,
        workspace: MicroVMWorkspace,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        guest_logs: list[JobLogEntry],
    ) -> None:
        payload = {"job_type": job_type, "package": package_name}
        attempts = 6
        delay_seconds = 0.5
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                await asyncio.to_thread(self._stream_job_once, workspace, payload, artifact_bytes)
                guest_logs.append(build_log_entry("control", "info", f"delivered job payload to guest on attempt {attempt}"))
                return
            except (TimeoutError, socket.timeout, OSError, SandboxInfraError) as exc:
                last_error = exc
                guest_logs.append(build_log_entry("control", "warning", f"guest control attempt {attempt}/{attempts} failed: {exc}"))
                if attempt < attempts:
                    await asyncio.sleep(delay_seconds)
                    delay_seconds = min(delay_seconds * 2.0, 2.0)

        raise SandboxTimeoutError(f"guest control channel failed after {attempts} attempts: {last_error}")

    def _stream_job_once(self, workspace: MicroVMWorkspace, payload: dict[str, object], artifact_bytes: bytes) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(self._settings.firecracker_guest_stream_timeout_seconds)

            try:
                client_socket.connect(str(workspace.vsock_socket_path))
            except (socket.timeout, OSError) as exc:
                raise SandboxInfraError(f"unable to connect to vsock UDS {workspace.vsock_socket_path}") from exc

            try:
                client_socket.sendall(b"CONNECT 7000\n")
                acknowledgement = self._recv_line(client_socket)
            except (socket.timeout, OSError) as exc:
                raise SandboxInfraError("timed out waiting for CONNECT 7000 acknowledgement") from exc

            if not acknowledgement.startswith(b"OK"):
                raise SandboxInfraError(f"guest control channel rejected connection: {acknowledgement!r}")

            try:
                client_socket.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
                if artifact_bytes:
                    client_socket.sendall(artifact_bytes)
                with suppress(OSError):
                    client_socket.shutdown(socket.SHUT_WR)

                # Keep the control socket open briefly so a guest that emits an immediate
                # status/log line over the same stream does not hit EPIPE on startup.
                if self._settings.firecracker_ingress_grace_seconds > 0:
                    grace_deadline = time.monotonic() + self._settings.firecracker_ingress_grace_seconds
                    while time.monotonic() < grace_deadline:
                        remaining = max(0.0, grace_deadline - time.monotonic())
                        client_socket.settimeout(min(0.25, remaining))
                        try:
                            _ = client_socket.recv(4096)
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        else:
                            # Ignore any optional status bytes from the guest.
                            continue
            except (socket.timeout, OSError) as exc:
                raise SandboxInfraError("timed out sending payload/artifact to guest") from exc

    async def run_vm(
        self,
        kernel_path: str,
        rootfs_path: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        timeout_seconds: float,
        job_id: str | None = None,
    ) -> FirecrackerRunResult:
        workspace = self.create_workspace(job_id, rootfs_path)
        proc: subprocess.Popen[bytes] | None = None
        stdout_text = ""
        stderr_text = ""
        telemetry_payload: dict[str, object] | None = None
        persistence = PostgresPersistence(self._settings)
        telemetry_server: asyncio.AbstractServer | None = None
        log_server: asyncio.AbstractServer | None = None
        listeners_ready = asyncio.Event()
        guest_logs: list[JobLogEntry] = [build_log_entry("host", "info", f"workspace created at {workspace.workspace_dir}")]
        self.last_run_logs = guest_logs

        try:
            await persistence.initialize()
            workspace.artifact_path.write_bytes(artifact_bytes)

            telemetry_server, log_server = await self._start_guest_stream_listeners(
                workspace,
                workspace.job_id,
                persistence,
                guest_logs,
                listeners_ready,
            )
            listeners_ready.set()

            proc = await self.launch_firecracker_async(workspace)
            await self.configure_vm(workspace, kernel_path)
            await self._wait_for_socket_file(workspace.vsock_socket_path)

            # The guest image is expected to have a Python agent listening on port 7000.
            await self.stream_job_to_guest(workspace, job_type, package_name, artifact_bytes, guest_logs)

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(self._communicate(proc), timeout=timeout_seconds)
            except asyncio.TimeoutError as exc:
                raise SandboxTimeoutError("Firecracker execution timed out") from exc

            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")
            if stdout_text.strip():
                guest_logs.append(build_log_entry("stdout", "info", stdout_text.strip()))
                await persistence.write_log(workspace.job_id, "stdout", "info", stdout_text.strip())
            if stderr_text.strip():
                guest_logs.append(build_log_entry("stderr", "warning", stderr_text.strip()))
                await persistence.write_log(workspace.job_id, "stderr", "warning", stderr_text.strip())

            telemetry_payload = self._last_telemetry_payload

            return FirecrackerRunResult(
                stdout=stdout_text,
                stderr=stderr_text,
                guest_logs=guest_logs,
                telemetry_payload=telemetry_payload,
            )
        finally:
            self.last_run_logs = list(guest_logs)
            if telemetry_server is not None:
                telemetry_server.close()
                with suppress(Exception):
                    await telemetry_server.wait_closed()
            if log_server is not None:
                log_server.close()
                with suppress(Exception):
                    await log_server.wait_closed()

            self._terminate_process(proc)
            await persistence.close()
            self._teardown_workspace(workspace)

    async def _start_guest_stream_listeners(
        self,
        workspace: MicroVMWorkspace,
        job_id: str,
        persistence: PostgresPersistence,
        guest_logs: list[JobLogEntry],
        listeners_ready: asyncio.Event,
    ) -> tuple[asyncio.AbstractServer, asyncio.AbstractServer]:
        self._last_telemetry_payload: dict[str, object] | None = None

        async def telemetry_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await listeners_ready.wait()
            try:
                while line := await reader.readline():
                    raw = line.decode("utf-8", errors="replace").strip()
                    if not raw:
                        continue
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        payload = {"raw": raw}

                    if not isinstance(payload, dict):
                        payload = {"raw": payload}

                    self._last_telemetry_payload = payload
                    guest_logs.append(build_log_entry("guest", "info", f"telemetry: {raw}"))
                    await persistence.write_telemetry(job_id, payload)
            finally:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

        async def log_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await listeners_ready.wait()
            try:
                while line := await reader.readline():
                    message = line.decode("utf-8", errors="replace").rstrip("\n")
                    if not message:
                        continue
                    guest_logs.append(build_log_entry("guest", "info", message))
                    await persistence.write_log(job_id, "guest", "info", message)
            finally:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

        with suppress(FileNotFoundError):
            workspace.telemetry_socket_path.unlink()
        with suppress(FileNotFoundError):
            workspace.log_socket_path.unlink()

        telemetry_server = await asyncio.start_unix_server(telemetry_handler, path=str(workspace.telemetry_socket_path))
        log_server = await asyncio.start_unix_server(log_handler, path=str(workspace.log_socket_path))
        guest_logs.append(build_log_entry("host", "info", "telemetry/log listeners ready on ports 7001/7002"))
        return telemetry_server, log_server

    async def _put(self, client: httpx.AsyncClient, path: str, payload: dict[str, Any]) -> None:
        response = await client.put(path, json=payload)
        response.raise_for_status()

    async def _communicate(self, proc: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, proc.communicate)

    async def _wait_for_socket_file(self, socket_path: Path, timeout_seconds: float = 10.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if socket_path.exists():
                return
            await asyncio.sleep(0.05)
        raise SandboxInfraError(f"Timed out waiting for socket: {socket_path}")

    @staticmethod
    def _recv_line(client_socket: socket.socket) -> bytes:
        buffer = bytearray()
        while True:
            chunk = client_socket.recv(1)
            if not chunk:
                break
            buffer.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(buffer)

    def _terminate_process(self, proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None:
            return

        if proc.poll() is None:
            with suppress(Exception):
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                with suppress(Exception):
                    proc.kill()
                with suppress(Exception):
                    proc.wait(timeout=5)

        with suppress(Exception):
            if proc.stdout is not None:
                proc.stdout.close()
        with suppress(Exception):
            if proc.stderr is not None:
                proc.stderr.close()

    def _teardown_workspace(self, workspace: MicroVMWorkspace) -> None:
        for path in (workspace.api_socket_path, workspace.vsock_socket_path, workspace.telemetry_socket_path, workspace.log_socket_path):
            with suppress(FileNotFoundError):
                path.unlink()
        with suppress(Exception):
            shutil.rmtree(workspace.workspace_dir, ignore_errors=True)


class FirecrackerManager(MicroVMManager):
    pass