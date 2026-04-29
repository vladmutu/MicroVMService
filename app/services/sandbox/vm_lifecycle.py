"""
vm_lifecycle.py — Unified Firecracker microVM lifecycle manager.

Handles: CID allocation, TAP networking, Firecracker process,
vsock UDS listeners (telemetry + logs), job delivery, IOC harvesting,
and guaranteed teardown.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from app.core.config import Settings
from app.services.ioc_detector import DynamicIOCDetector, IOCEvidence
from app.services.persistence import PostgresPersistence

logger = logging.getLogger(__name__)


# ─── CID Allocator ───────────────────────────────────────────────────

class CIDAllocator:
    """Thread-safe pool of unique guest CIDs for parallel VMs."""

    def __init__(self, start: int = 3, end: int = 100) -> None:
        self._available: set[int] = set(range(start, end + 1))
        self._lock = asyncio.Lock()

    async def acquire(self) -> int:
        async with self._lock:
            if not self._available:
                raise RuntimeError("No available CIDs — all VM slots are in use")
            return self._available.pop()

    async def release(self, cid: int) -> None:
        async with self._lock:
            self._available.add(cid)

    @property
    def available_count(self) -> int:
        return len(self._available)


# ─── Data classes ─────────────────────────────────────────────────────

@dataclass(slots=True)
class VMWorkspace:
    """All paths and identifiers for a single VM run."""
    job_id: str
    cid: int
    slot: int  # index for TAP naming / subnet
    workspace_dir: Path
    rootfs_path: Path
    api_socket: Path
    vsock_socket: Path
    telemetry_socket: Path
    log_socket: Path
    tap_device: str | None = None  # e.g. "vmtap3"


@dataclass(slots=True)
class VMRunResult:
    """Outcome of a single VM analysis run."""
    evidence: IOCEvidence
    telemetry_events: list[dict[str, Any]] = field(default_factory=list)
    relevant_runtime_events: list[dict[str, Any]] = field(default_factory=list)
    relevant_runtime_summary: dict[str, Any] = field(default_factory=dict)
    log_lines: list[str] = field(default_factory=list)
    error: str | None = None


# ─── TAP Networking ──────────────────────────────────────────────────

class TAPManager:
    """Creates and tears down per-VM TAP devices with NAT + security rules."""

    def __init__(self, settings: Settings) -> None:
        self._prefix = settings.tap_prefix
        self._subnet_prefix = settings.tap_subnet_prefix
        self._wan_iface = settings.tap_host_interface
        self._dns = settings.tap_dns_server

    def host_ip(self, slot: int) -> str:
        return f"{self._subnet_prefix}.{slot}.1"

    def guest_ip(self, slot: int) -> str:
        return f"{self._subnet_prefix}.{slot}.2"

    def tap_name(self, slot: int) -> str:
        return f"{self._prefix}{slot}"

    async def setup(self, slot: int) -> str:
        """Create TAP device, assign IP, add iptables rules. Returns tap name."""
        tap = self.tap_name(slot)
        host_ip = self.host_ip(slot)

        cmds = [
            ["ip", "tuntap", "add", "dev", tap, "mode", "tap"],
            ["ip", "addr", "add", f"{host_ip}/30", "dev", tap],
            ["ip", "link", "set", tap, "up"],
            # NAT so VM can reach internet
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", self._wan_iface, "-j", "MASQUERADE"],
            ["iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-i", tap, "-o", self._wan_iface, "-j", "ACCEPT"],
            # Block VM from scanning private networks
            ["iptables", "-I", "FORWARD", "-i", tap, "-d", "192.168.0.0/16", "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-i", tap, "-d", "10.0.0.0/8", "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-i", tap, "-d", "172.16.0.0/12", "-j", "DROP"],
            # But allow the host-guest link itself
            ["iptables", "-I", "FORWARD", "-i", tap, "-d", f"{host_ip}/30", "-j", "ACCEPT"],
        ]

        # Enable IP forwarding
        await self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"], ignore_errors=False)

        for cmd in cmds:
            await self._run(cmd, ignore_errors=True)

        logger.info("TAP %s created with host=%s/30", tap, host_ip)
        return tap

    async def teardown(self, slot: int) -> None:
        """Remove TAP device and associated iptables rules."""
        tap = self.tap_name(slot)
        host_ip = self.host_ip(slot)

        # Remove iptables rules (best-effort, ignore errors)
        cleanup_cmds = [
            ["iptables", "-D", "FORWARD", "-i", tap, "-d", f"{host_ip}/30", "-j", "ACCEPT"],
            ["iptables", "-D", "FORWARD", "-i", tap, "-d", "172.16.0.0/12", "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-i", tap, "-d", "10.0.0.0/8", "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-i", tap, "-d", "192.168.0.0/16", "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-i", tap, "-o", self._wan_iface, "-j", "ACCEPT"],
            ["ip", "link", "set", tap, "down"],
            ["ip", "tuntap", "del", "dev", tap, "mode", "tap"],
        ]
        for cmd in cleanup_cmds:
            await self._run(cmd, ignore_errors=True)

        logger.info("TAP %s torn down", tap)

    @staticmethod
    async def _run(cmd: list[str], ignore_errors: bool = False) -> None:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0 and not ignore_errors:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}: {stderr.decode()}")


# ─── VM Lifecycle Manager ────────────────────────────────────────────

class VMLifecycleManager:
    """
    Manages the complete lifecycle of a Firecracker microVM:

    1. Acquire CID + create workspace
    2. Copy rootfs (sparse)
    3. Setup TAP networking
    4. Launch Firecracker process
    5. Configure VM via API (kernel, rootfs, vsock, network)
    6. Start UDS listeners for telemetry (7001) + logs (7002)
    7. Deliver job payload via vsock port 7000
    8. Wait for agent_finished signal
    9. Harvest IOC evidence
    10. Teardown everything (kill FC, remove TAP, release CID, rm workspace)
    """

    def __init__(self, settings: Settings, persistence: PostgresPersistence | None = None) -> None:
        self._settings = settings
        self._cid_pool = CIDAllocator(settings.cid_range_start, settings.cid_range_end)
        self._tap_mgr = TAPManager(settings) if settings.tap_enabled else None
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_vms)
        self._persistence = persistence

    @property
    def available_slots(self) -> int:
        return self._cid_pool.available_count

    async def run_analysis(
        self,
        job_id: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        kernel_path: str | None = None,
        rootfs_path: str | None = None,
    ) -> VMRunResult:
        """Run a complete VM analysis cycle. Blocks until the VM finishes or times out."""
        async with self._semaphore:
            return await self._run_analysis_inner(
                job_id, job_type, package_name, artifact_bytes,
                kernel_path or self._settings.firecracker_default_kernel,
                rootfs_path or self._settings.firecracker_default_rootfs,
            )

    async def _run_analysis_inner(
        self,
        job_id: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        kernel_path: str,
        rootfs_path: str,
    ) -> VMRunResult:
        cid = await self._cid_pool.acquire()
        slot = cid  # use CID as slot for TAP naming
        workspace: VMWorkspace | None = None
        proc: subprocess.Popen[bytes] | None = None
        telemetry_server: asyncio.AbstractServer | None = None
        log_server: asyncio.AbstractServer | None = None
        serve_tasks: list[asyncio.Task[None]] = []
        pipe_tasks: list[asyncio.Task[None]] = []

        detector = DynamicIOCDetector()
        telemetry_events: list[dict[str, Any]] = []
        relevant_runtime_events: list[dict[str, Any]] = []
        relevant_runtime_summary: dict[str, Any] = {
            "event_count": 0,
            "syscall_count": 0,
            "process_count": 0,
            "network_count": 0,
            "file_count": 0,
            "dns_count": 0,
            "artifact_count": 0,
            "events": [],
        }
        log_lines: list[str] = []
        finished_signal = asyncio.Event()

        try:
            # 1. Create workspace + copy rootfs
            workspace = await self._create_workspace(job_id, cid, slot, rootfs_path)
            logger.info("[%s] Workspace created at %s (CID=%d)", job_id, workspace.workspace_dir, cid)

            # 2. Setup TAP networking
            if self._tap_mgr:
                workspace.tap_device = await self._tap_mgr.setup(slot)

            # 3. Launch Firecracker
            proc = self._launch_firecracker(workspace)
            await self._wait_for_path(workspace.api_socket, self._settings.vm_boot_timeout_seconds)
            logger.info("[%s] Firecracker process started (pid=%d)", job_id, proc.pid)

            # 4. Pump stdout/stderr
            if proc.stdout:
                pipe_tasks.append(asyncio.create_task(
                    self._pump_pipe(proc.stdout, f"fc-stdout-{job_id[:8]}", log_lines)
                ))
            if proc.stderr:
                pipe_tasks.append(asyncio.create_task(
                    self._pump_pipe(proc.stderr, f"fc-stderr-{job_id[:8]}", log_lines)
                ))

            # 5. Configure VM (kernel, rootfs, vsock, network, start)
            boot_args = self._build_boot_args(slot)
            await self._configure_vm(workspace, kernel_path, boot_args)
            await self._wait_for_path(workspace.vsock_socket, self._settings.vm_boot_timeout_seconds)
            logger.info("[%s] VM booted, vsock ready", job_id)

            # 6. Start UDS listeners for telemetry + logs
            telemetry_server, log_server, t_tasks = await self._start_listeners(
                workspace,
                detector,
                telemetry_events,
                relevant_runtime_events,
                relevant_runtime_summary,
                log_lines,
                finished_signal,
                job_id,
            )
            serve_tasks.extend(t_tasks)

            # 7. Deliver job payload
            await asyncio.wait_for(
                asyncio.to_thread(
                    self._deliver_job, workspace, job_id, job_type, package_name, artifact_bytes
                ),
                timeout=self._settings.vm_ingress_timeout_seconds,
            )
            logger.info("[%s] Job delivered to guest", job_id)

            # 8. Wait for agent_finished signal
            await finished_signal.wait()
            logger.info("[%s] Agent finished", job_id)

            # 9. Build evidence
            evidence = detector.build_evidence()
            return VMRunResult(
                evidence=evidence,
                telemetry_events=telemetry_events,
                relevant_runtime_events=relevant_runtime_events,
                relevant_runtime_summary=relevant_runtime_summary,
                log_lines=log_lines,
            )

        except asyncio.TimeoutError:
            logger.warning("[%s] VM analysis timed out", job_id)
            evidence = detector.build_evidence()
            return VMRunResult(
                evidence=evidence,
                telemetry_events=telemetry_events,
                relevant_runtime_events=relevant_runtime_events,
                relevant_runtime_summary=relevant_runtime_summary,
                log_lines=log_lines,
                error="analysis timed out",
            )
        except Exception as exc:
            logger.error("[%s] VM analysis failed: %s", job_id, exc, exc_info=True)
            evidence = detector.build_evidence()
            return VMRunResult(
                evidence=evidence,
                telemetry_events=telemetry_events,
                relevant_runtime_events=relevant_runtime_events,
                relevant_runtime_summary=relevant_runtime_summary,
                log_lines=log_lines,
                error=str(exc),
            )
        finally:
            # 10. Guaranteed teardown
            await self._teardown(
                workspace, proc, cid, slot,
                telemetry_server, log_server, serve_tasks, pipe_tasks,
            )

    # ─── Workspace ────────────────────────────────────────────────────

    async def _create_workspace(
        self, job_id: str, cid: int, slot: int, rootfs_path: str,
    ) -> VMWorkspace:
        jobs_root = Path(self._settings.firecracker_workdir) / "jobs"
        jobs_root.mkdir(parents=True, exist_ok=True)

        workspace_dir = Path(tempfile.mkdtemp(prefix=f"vm-{job_id[:8]}-", dir=str(jobs_root)))
        rootfs_copy = workspace_dir / "rootfs.ext4"

        # Sparse copy — fast on Linux, falls back to normal copy on unsupported systems
        try:
            await asyncio.to_thread(
                subprocess.run,
                ["cp", "--sparse=always", str(rootfs_path), str(rootfs_copy)],
                check=True, capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            await asyncio.to_thread(shutil.copy2, rootfs_path, rootfs_copy)

        return VMWorkspace(
            job_id=job_id,
            cid=cid,
            slot=slot,
            workspace_dir=workspace_dir,
            rootfs_path=rootfs_copy,
            api_socket=workspace_dir / "api.socket",
            vsock_socket=workspace_dir / "v.sock",
            telemetry_socket=workspace_dir / "v.sock_7001",
            log_socket=workspace_dir / "v.sock_7002",
        )

    # ─── Boot args with dynamic guest IP ──────────────────────────────

    def _build_boot_args(self, slot: int) -> str:
        base = self._settings.firecracker_boot_args
        if self._tap_mgr:
            guest_ip = self._tap_mgr.guest_ip(slot)
            host_ip = self._tap_mgr.host_ip(slot)
            # Linux kernel ip= parameter: ip=client:server:gw:mask:hostname:device:autoconf
            ip_arg = f"ip={guest_ip}::{host_ip}:255.255.255.252::eth0:off"
            return f"{base} {ip_arg}"
        return base

    # ─── Firecracker process ──────────────────────────────────────────

    def _launch_firecracker(self, workspace: VMWorkspace) -> subprocess.Popen[bytes]:
        cmd = [self._settings.firecracker_binary, "--api-sock", str(workspace.api_socket)]
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Firecracker binary not found: {self._settings.firecracker_binary}") from exc

    async def _configure_vm(
        self, workspace: VMWorkspace, kernel_path: str, boot_args: str,
    ) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(workspace.api_socket))
        timeout = httpx.Timeout(10.0)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=timeout) as client:
            await self._put(client, "/boot-source", {
                "kernel_image_path": kernel_path,
                "boot_args": boot_args,
            })
            await self._put(client, "/machine-config", {
                "vcpu_count": self._settings.firecracker_vcpu_count,
                "mem_size_mib": self._settings.firecracker_mem_mib,
                "smt": False,
            })
            await self._put(client, "/drives/rootfs", {
                "drive_id": "rootfs",
                "path_on_host": str(workspace.rootfs_path),
                "is_root_device": True,
                "is_read_only": False,
            })
            await self._put(client, "/vsock", {
                "guest_cid": workspace.cid,
                "uds_path": str(workspace.vsock_socket),
            })

            # Attach TAP network interface if enabled
            if workspace.tap_device:
                mac = self._generate_mac(workspace.slot)
                await self._put(client, "/network-interfaces/eth0", {
                    "iface_id": "eth0",
                    "guest_mac": mac,
                    "host_dev_name": workspace.tap_device,
                })

            await self._put(client, "/actions", {"action_type": "InstanceStart"})

    @staticmethod
    def _generate_mac(slot: int) -> str:
        """Generate a deterministic MAC address for the given VM slot."""
        return f"AA:FC:00:00:{slot >> 8:02X}:{slot & 0xFF:02X}"

    # ─── UDS Listeners (telemetry + logs) ─────────────────────────────

    async def _start_listeners(
        self,
        workspace: VMWorkspace,
        detector: DynamicIOCDetector,
        telemetry_events: list[dict[str, Any]],
        relevant_runtime_events: list[dict[str, Any]],
        relevant_runtime_summary: dict[str, Any],
        log_lines: list[str],
        finished_signal: asyncio.Event,
        job_id: str,
    ) -> tuple[asyncio.AbstractServer, asyncio.AbstractServer, list[asyncio.Task[None]]]:

        async def _handle_channel(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            port: int,
            on_line: Any,
        ) -> None:
            try:
                # Vsock handshake: guest sends "CONNECT {port}\n", host replies "OK {port}\n"
                handshake = await asyncio.wait_for(reader.readline(), timeout=10.0)
                expected = f"CONNECT {port}".encode()
                if not handshake.startswith(expected):
                    logger.warning("[%s] Bad handshake on port %d: %r", job_id, port, handshake)
                    return
                writer.write(f"OK {port}\n".encode())
                await writer.drain()

                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    text = line.decode("utf-8", errors="replace").rstrip("\n")
                    if text:
                        await on_line(text)
            except asyncio.TimeoutError:
                logger.warning("[%s] Handshake timeout on port %d", job_id, port)
            except Exception as exc:
                logger.error("[%s] Channel %d error: %r", job_id, port, exc)
            finally:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

        async def on_telemetry_line(text: str) -> None:
            telemetry_events.append({"raw": text})
            logger.debug("[%s][telemetry] %s", job_id, text[:200])
            if " agent_finished " in text or " verdict " in text or text.endswith(" agent_finished") or text.endswith(" verdict"):
                # Give a short delay to allow log_lines from vsock port 7002 to flush
                # before setting finished_signal and tearing down the VM.
                async def _signal() -> None:
                    await asyncio.sleep(0.5)
                    finished_signal.set()
                asyncio.create_task(_signal())

        async def on_log_line(text: str) -> None:
            log_lines.append(text)

            async def _persist_ioc_delta(payload_text: str, before_counts: tuple[int, int, int, int, int], after_counts: tuple[int, int, int, int, int]) -> None:
                if not self._persistence or not any(a > b for a, b in zip(after_counts, before_counts)):
                    return
                categories = []
                if after_counts[0] > before_counts[0]:
                    categories.append("network")
                if after_counts[1] > before_counts[1]:
                    categories.append("process")
                if after_counts[2] > before_counts[2]:
                    categories.append("file")
                if after_counts[3] > before_counts[3]:
                    categories.append("dns")
                if after_counts[4] > before_counts[4]:
                    categories.append("crypto")
                category = ",".join(categories) if categories else None
                with suppress(Exception):
                    await self._persistence.write_suspicious_line(job_id, payload_text, category=category)

            before_counts = (
                len(detector.network_iocs),
                len(detector.process_iocs),
                len(detector.file_iocs),
                len(detector.dns_iocs),
                len(detector.crypto_iocs),
            )
            
            detector.observe_line(text)
            
            after_counts = (
                len(detector.network_iocs),
                len(detector.process_iocs),
                len(detector.file_iocs),
                len(detector.dns_iocs),
                len(detector.crypto_iocs),
            )
            await _persist_ioc_delta(text, before_counts, after_counts)

            logger.debug("[%s][log] %s", job_id, text[:200])

        # Remove stale sockets
        for sock_path in (workspace.telemetry_socket, workspace.log_socket):
            with suppress(FileNotFoundError):
                sock_path.unlink()

        tel_port = self._settings.vsock_telemetry_port
        log_port = self._settings.vsock_log_port

        telemetry_server = await asyncio.start_unix_server(
            lambda r, w: _handle_channel(r, w, tel_port, on_telemetry_line),
            path=str(workspace.telemetry_socket),
            limit=5 * 1024 * 1024,  # 5MB limit for large strace lines
        )
        log_server = await asyncio.start_unix_server(
            lambda r, w: _handle_channel(r, w, log_port, on_log_line),
            path=str(workspace.log_socket),
            limit=5 * 1024 * 1024,  # 5MB limit for large strace lines
        )

        tasks = [
            asyncio.create_task(telemetry_server.serve_forever()),
            asyncio.create_task(log_server.serve_forever()),
        ]

        return telemetry_server, log_server, tasks

    # ─── Job delivery (vsock port 7000) ───────────────────────────────

    def _deliver_job(
        self,
        workspace: VMWorkspace,
        job_id: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
    ) -> None:
        artifact_sha = hashlib.sha256(artifact_bytes).hexdigest() if artifact_bytes else ""
        payload = {
            "job_id": job_id,
            "job_type": job_type,
            "package": package_name,
            "artifact_size": len(artifact_bytes),
            "artifact_sha256": artifact_sha,
        }

        deadline = time.monotonic() + self._settings.vm_ingress_timeout_seconds
        # Give the agent a moment to start listening
        time.sleep(self._settings.vm_ingress_grace_seconds)

        attempt = 0
        last_err: Exception | None = None

        while time.monotonic() < deadline:
            attempt += 1
            try:
                self._deliver_job_once(workspace, payload, artifact_bytes)
                return
            except Exception as exc:
                last_err = exc
                time.sleep(min(0.5 * attempt, 2.0))

        raise TimeoutError(f"Ingress delivery failed after {attempt} attempts: {last_err}")

    def _deliver_job_once(
        self,
        workspace: VMWorkspace,
        payload: dict[str, Any],
        artifact_bytes: bytes,
    ) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._settings.vm_ingress_timeout_seconds)
            sock.connect(str(workspace.vsock_socket))

            # Vsock proxy handshake
            sock.sendall(b"CONNECT 7000\n")
            proxy_ack = self._recv_line(sock)
            if not proxy_ack.startswith(b"OK"):
                raise RuntimeError(f"Vsock proxy rejected CONNECT 7000: {proxy_ack!r}")

            # Send framed payload: JSON header + artifact bytes
            sock.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
            if artifact_bytes:
                sock.sendall(artifact_bytes)

            with suppress(OSError):
                sock.shutdown(socket.SHUT_WR)

            # Wait for agent ack
            agent_ack = self._recv_line(sock)
            if not agent_ack.startswith(b"OK"):
                raise RuntimeError(f"Agent did not ack on port 7000: {agent_ack!r}")

    # ─── Teardown ─────────────────────────────────────────────────────

    async def _teardown(
        self,
        workspace: VMWorkspace | None,
        proc: subprocess.Popen[bytes] | None,
        cid: int,
        slot: int,
        telemetry_server: asyncio.AbstractServer | None,
        log_server: asyncio.AbstractServer | None,
        serve_tasks: list[asyncio.Task[None]],
        pipe_tasks: list[asyncio.Task[None]],
    ) -> None:
        # 1. Close UDS servers (No awaiting)
        for server in (telemetry_server, log_server):
            if server:
                server.close()

        # 2. Cancel serve_forever tasks (No awaiting)
        for task in serve_tasks:
            task.cancel()

        # 3. Terminate Firecracker process
        if proc and proc.poll() is None:
            proc.kill()
            with suppress(Exception):
                await asyncio.to_thread(proc.wait)

        # 4. Close pipe readers (No awaiting)
        for task in pipe_tasks:
            task.cancel()

        # 5. Teardown TAP networking
        if self._tap_mgr:
            with suppress(Exception):
                await self._tap_mgr.teardown(slot)

        # 6. Release CID back to pool
        await self._cid_pool.release(cid)

        # 7. Remove workspace
        if workspace:
            with suppress(Exception):
                shutil.rmtree(workspace.workspace_dir, ignore_errors=True)

        logger.info("Teardown complete for CID=%d", cid)

    # ─── Utilities ────────────────────────────────────────────────────

    @staticmethod
    async def _wait_for_path(path: Path, timeout_sec: float) -> None:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            if path.exists():
                return
            await asyncio.sleep(0.05)
        raise TimeoutError(f"Timed out waiting for: {path}")

    @staticmethod
    async def _pump_pipe(pipe: Any, label: str, log_lines: list[str]) -> None:
        while True:
            line = await asyncio.to_thread(pipe.readline)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip("\n")
            if text:
                message = f"[{label}] {text}"
                log_lines.append(message)
                print(message, flush=True)

    @staticmethod
    async def _put(client: httpx.AsyncClient, endpoint: str, payload: dict[str, Any]) -> None:
        response = await client.put(endpoint, json=payload)

        if response.status_code >= 400:
            print(f"\n[FIRECRACKER API ERROR] {endpoint}: {response.text}\n", flush=True)

        response.raise_for_status()

    @staticmethod
    def _recv_line(sock: socket.socket) -> bytes:
        buf = bytearray()
        while True:
            chunk = sock.recv(1)
            if not chunk:
                break
            buf.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(buf)


def _clean_runtime_event(event: dict[str, Any]) -> dict[str, Any] | None:
    event_type = event.get("event")
    ts = event.get("ts")
    if event_type == "syscall_event":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "syscall": event.get("syscall"),
            "args": event.get("args", []),
            "return_value": event.get("return_value"),
        }
    if event_type == "process_start":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "binary": event.get("binary"),
            "args": event.get("args", []),
            "cwd": event.get("cwd"),
            "late_spawn": event.get("late_spawn", False),
        }
    if event_type == "process_exit":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "return_value": event.get("return_value"),
            "lifetime_seconds": event.get("lifetime_seconds"),
        }
    if event_type == "network_event":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "action": event.get("action"),
            "fd": event.get("fd"),
            "ip": event.get("ip"),
            "port": event.get("port"),
            "protocol": event.get("protocol"),
            "family": event.get("family"),
            "payload_size": event.get("payload_size"),
            "failed": event.get("failed", False),
        }
    if event_type == "file_event":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "operation": event.get("operation"),
            "access_type": event.get("access_type"),
            "path": event.get("path"),
            "target_path": event.get("target_path"),
            "fd": event.get("fd"),
            "size": event.get("size"),
            "return_value": event.get("return_value"),
        }
    if event_type == "dns_event":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "syscall": event.get("syscall"),
            "port": event.get("port"),
        }
    if event_type == "artifact_created":
        return {
            "ts": ts,
            "event": event_type,
            "phase": event.get("phase"),
            "pid": event.get("pid"),
            "kind": event.get("kind"),
            "path": event.get("path"),
            "size": event.get("size"),
            "age_seconds": event.get("age_seconds"),
        }
    return None


def _accumulate_runtime_summary(summary: dict[str, Any], event: dict[str, Any]) -> None:
    summary["event_count"] = int(summary.get("event_count", 0)) + 1
    event_type = event.get("event")
    if event_type == "syscall_event":
        summary["syscall_count"] = int(summary.get("syscall_count", 0)) + 1
    elif event_type in {"process_start", "process_exit"}:
        summary["process_count"] = int(summary.get("process_count", 0)) + 1
    elif event_type == "network_event":
        summary["network_count"] = int(summary.get("network_count", 0)) + 1
    elif event_type == "file_event":
        summary["file_count"] = int(summary.get("file_count", 0)) + 1
    elif event_type == "dns_event":
        summary["dns_count"] = int(summary.get("dns_count", 0)) + 1
    elif event_type == "artifact_created":
        summary["artifact_count"] = int(summary.get("artifact_count", 0)) + 1

    events = summary.setdefault("events", [])
    if isinstance(events, list) and len(events) < 250:
        events.append(event)
