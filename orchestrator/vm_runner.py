from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, BinaryIO, Callable

import httpx

from config import VMConfig
from models.job import AnalysisJob

TelemetryCallback = Callable[[dict[str, Any]], Awaitable[None]]
LogCallback = Callable[[str], Awaitable[None]]


@dataclass
class JobResult:
    status: str
    verdict: str | None
    score: int | None
    evidence: dict[str, Any]
    error: str | None


class VMRunner:
    def __init__(self, config: VMConfig) -> None:
        self._config = config

    async def run_job(
        self,
        job: AnalysisJob,
        on_telemetry: TelemetryCallback | None = None,
        on_log: LogCallback | None = None,
    ) -> JobResult:
        workdir = Path(tempfile.mkdtemp(prefix=f"vm-{job.job_id}-", dir="/tmp"))
        api_sock = workdir / "api.socket"
        vsock_path = workdir / "v.sock"
        telemetry_sock = workdir / "v.sock_7001"
        log_sock = workdir / "v.sock_7002"
        rootfs_copy = workdir / "rootfs.ext4"
        shutil.copy2(self._config.rootfs_path, rootfs_copy)

        proc: subprocess.Popen[bytes] | None = None
        telemetry_server: asyncio.AbstractServer | None = None
        log_server: asyncio.AbstractServer | None = None
        stdout_task: asyncio.Task[None] | None = None
        stderr_task: asyncio.Task[None] | None = None

        verdict_event: dict[str, Any] | None = None
        verdict_signal = asyncio.Event()

        async def telemetry_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal verdict_event
            try:
                while line := await reader.readline():
                    raw = line.decode("utf-8", errors="replace").strip()
                    if not raw:
                        continue
                    try:
                        event = json.loads(raw)
                    except json.JSONDecodeError:
                        event = {"event": "invalid_json", "raw": raw, "job_id": job.job_id}
                    if on_telemetry is not None:
                        await on_telemetry(event)
                    if event.get("event") == "verdict":
                        verdict_event = event
                        verdict_signal.set()
            finally:
                writer.close()
                await writer.wait_closed()

        async def log_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while line := await reader.readline():
                    text = line.decode("utf-8", errors="replace").rstrip("\n")
                    if on_log is not None and text:
                        await on_log(text)
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            telemetry_server = await asyncio.start_unix_server(telemetry_handler, path=str(telemetry_sock))
            log_server = await asyncio.start_unix_server(log_handler, path=str(log_sock))

            proc = subprocess.Popen(
                [str(self._config.firecracker_bin), "--api-sock", str(api_sock)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if proc.stdout is not None:
                stdout_task = asyncio.create_task(self._pump_pipe(proc.stdout, "firecracker-stdout", on_log))
            if proc.stderr is not None:
                stderr_task = asyncio.create_task(self._pump_pipe(proc.stderr, "firecracker-stderr", on_log))

            await self._wait_for_path(api_sock, self._config.boot_timeout_sec)

            await self._configure_vm(api_sock, rootfs_copy, vsock_path)
            await self._wait_for_path(vsock_path, self._config.boot_timeout_sec)

            await asyncio.wait_for(
                asyncio.to_thread(self._deliver_job, job, vsock_path),
                timeout=self._config.ingress_timeout_sec,
            )

            await asyncio.wait_for(verdict_signal.wait(), timeout=self._config.analysis_timeout_sec)

            verdict = verdict_event.get("verdict") if verdict_event else None
            score = verdict_event.get("score") if verdict_event else None
            evidence = dict(verdict_event.get("evidence") or {}) if verdict_event else {}
            return JobResult(status="done", verdict=verdict, score=score, evidence=evidence, error=None)
        except Exception as exc:
            return JobResult(status="error", verdict=None, score=None, evidence={}, error=str(exc))
        finally:
            if telemetry_server is not None:
                telemetry_server.close()
                await telemetry_server.wait_closed()
            if log_server is not None:
                log_server.close()
                await log_server.wait_closed()

            await self._teardown_process(proc)

            for task in (stdout_task, stderr_task):
                if task is None:
                    continue
                try:
                    await asyncio.wait_for(task, timeout=1.0)
                except Exception:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

            shutil.rmtree(workdir, ignore_errors=True)

    async def _pump_pipe(self, pipe: BinaryIO, label: str, on_log: LogCallback | None) -> None:
        while True:
            line = await asyncio.to_thread(pipe.readline)
            if not line:
                break

            text = line.decode("utf-8", errors="replace").rstrip("\n")
            if not text:
                continue

            print(f"[{label}] {text}", flush=True)
            if on_log is not None:
                await on_log(f"[{label}] {text}")

    async def _configure_vm(self, api_sock: Path, rootfs_copy: Path, vsock_path: Path) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(api_sock))
        timeout = httpx.Timeout(10.0)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=timeout) as client:
            await self._put(
                client,
                "/boot-source",
                {
                    "kernel_image_path": str(self._config.kernel_path),
                    "boot_args": self._config.boot_args,
                },
            )
            await self._put(
                client,
                "/drives/rootfs",
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(rootfs_copy),
                    "is_root_device": True,
                    "is_read_only": False,
                },
            )
            await self._put(
                client,
                "/vsock",
                {
                    "guest_cid": self._config.guest_cid,
                    "uds_path": str(vsock_path),
                },
            )
            await self._put(client, "/actions", {"action_type": "InstanceStart"})

    async def _put(self, client: httpx.AsyncClient, endpoint: str, payload: dict[str, Any]) -> None:
        response = await client.put(endpoint, json=payload)
        response.raise_for_status()

    def _deliver_job(self, job: AnalysisJob, vsock_path: Path) -> None:
        artifact_bytes = b""
        artifact_sha = ""
        if job.artifact_path is not None and job.artifact_path.exists():
            artifact_bytes = job.artifact_path.read_bytes()
            artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
        payload = {
            "job_id": job.job_id,
            "job_type": job.job_type,
            "package": job.package,
            "artifact_size": len(artifact_bytes),
            "artifact_sha256": artifact_sha,
        }
        deadline = time.monotonic() + float(self._config.ingress_timeout_sec)
        attempt = 0
        last_err: Exception | None = None

        # Give the agent a moment to start listening before first attempt
        time.sleep(1.0)

        while time.monotonic() < deadline:
            attempt += 1
            try:
                self._deliver_job_once(vsock_path, payload, artifact_bytes)
                return
            except Exception as exc:
                last_err = exc
                time.sleep(min(0.5 * attempt, 2.0))
        raise TimeoutError(f"ingress delivery failed after {attempt} attempts: {last_err}")

    def _deliver_job_once(self, vsock_path: Path, payload: dict[str, Any], artifact_bytes: bytes) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(self._config.ingress_timeout_sec))
            sock.connect(str(vsock_path))
            sock.sendall(b"CONNECT 7000\n")

            # This is the vsock proxy ack — not the agent ack
            proxy_ack = self._recv_line(sock)
            if not proxy_ack.startswith(b"OK"):
                raise RuntimeError(f"vsock proxy rejected CONNECT 7000: {proxy_ack!r}")

            # Send framed payload
            sock.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
            if artifact_bytes:
                sock.sendall(artifact_bytes)

            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

            # Now read the agent's ack (OK 7000\n) — wait up to ingress_timeout_sec
            agent_ack = self._recv_line(sock)
            if not agent_ack.startswith(b"OK"):
                raise RuntimeError(f"agent did not ack on port 7000: {agent_ack!r}")

    async def _wait_for_path(self, path: Path, timeout_sec: int) -> None:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            if path.exists():
                return
            await asyncio.sleep(0.05)
        raise TimeoutError(f"Timed out waiting for path: {path}")

    async def _teardown_process(self, proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None:
            return

        if proc.poll() is None:
            proc.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(proc.wait), timeout=self._config.teardown_timeout_sec)
            except Exception:
                proc.kill()
                await asyncio.to_thread(proc.wait)

    @staticmethod
    def _recv_line(sock: socket.socket) -> bytes:
        out = bytearray()
        while True:
            chunk = sock.recv(1)
            if not chunk:
                break
            out.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(out)
