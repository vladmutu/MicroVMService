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
import threading
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


# ─── IP Registry ─────────────────────────────────────────────────────

class IPRegistry:
    """Thread-safe registry of active VM IP assignments.

    Provides a live view of which CID owns which TAP device and IP pair,
    so operators can inspect running VMs and detect stale leaks.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[int, dict[str, Any]] = {}  # cid → info

    def register(
        self,
        cid: int,
        job_id: str,
        tap: str,
        host_ip: str,
        guest_ip: str,
    ) -> None:
        with self._lock:
            self._active[cid] = {
                "job_id": job_id,
                "tap": tap,
                "host_ip": host_ip,
                "guest_ip": guest_ip,
                "started_at": time.time(),
            }

    def release(self, cid: int) -> None:
        with self._lock:
            self._active.pop(cid, None)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a sorted list of currently active VM assignments."""
        with self._lock:
            return [{"cid": k, **v} for k, v in sorted(self._active.items())]

    def is_ip_in_use(self, guest_ip: str) -> bool:
        with self._lock:
            return any(v["guest_ip"] == guest_ip for v in self._active.values())

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)


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
    telemetry_events: list[str] = field(default_factory=list)
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
        subnet = f"{self._subnet_prefix}.{slot}.0/30"

        # Pre-clean: remove any stale device left by a failed teardown so setup is idempotent.
        await self._run(["ip", "link", "set", tap, "down"], ignore_errors=True)
        await self._run(["ip", "tuntap", "del", "dev", tap, "mode", "tap"], ignore_errors=True)

        cmds = [
            ["ip", "tuntap", "add", "dev", tap, "mode", "tap"],
            ["ip", "addr", "add", f"{host_ip}/30", "dev", tap],
            # Lower MTU to reduce fragmentation risk in nested NAT setups.
            ["ip", "link", "set", tap, "mtu", "1420"],
            ["ip", "link", "set", tap, "up"],
            # Disable offloads to avoid checksum/offload issues on virtio-net.
            ["ethtool", "-K", tap, "sg", "off", "tso", "off", "gso", "off", "gro", "off", "tx", "off", "rx", "off"],
            ["ethtool", "-K", self._wan_iface, "tx", "off"],
        ]

        # Enable IP forwarding
        await self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"], ignore_errors=False)

        for cmd in cmds:
            await self._run(cmd, ignore_errors=True)

        # NAT so VM can reach internet; scope to this VM subnet for clean teardown.
        await self._iptables_ensure(
            ["-t", "nat"],
            ["POSTROUTING", "-s", subnet, "-o", self._wan_iface, "-j", "MASQUERADE"],
        )
        await self._iptables_ensure(
            [],
            ["FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        )
        await self._iptables_ensure(
            [],
            ["FORWARD", "-i", tap, "-o", self._wan_iface, "-j", "ACCEPT"],
        )
        # Block VM from scanning private networks.
        await self._iptables_ensure([], ["FORWARD", "-i", tap, "-d", "192.168.0.0/16", "-j", "DROP"])
        await self._iptables_ensure([], ["FORWARD", "-i", tap, "-d", "10.0.0.0/8", "-j", "DROP"])
        await self._iptables_ensure([], ["FORWARD", "-i", tap, "-d", "172.16.0.0/12", "-j", "DROP"])
        # But allow the host-guest /30 link itself.
        await self._iptables_ensure([], ["FORWARD", "-i", tap, "-d", f"{host_ip}/30", "-j", "ACCEPT"])

        # Clamp MSS and fill checksums for nested NAT reliability.
        await self._iptables_ensure(
            ["-t", "mangle"],
            [
                "FORWARD",
                "-p", "tcp",
                "--tcp-flags", "SYN,RST", "SYN",
                "-j", "TCPMSS",
                "--set-mss", "1200",
            ],
        )
        await self._iptables_ensure(
            ["-t", "mangle"],
            ["POSTROUTING", "-p", "tcp", "-j", "CHECKSUM", "--checksum-fill"],
        )
        await self._iptables_ensure(
            ["-t", "mangle"],
            ["POSTROUTING", "-p", "udp", "-j", "CHECKSUM", "--checksum-fill"],
        )

        logger.info("TAP %s created with host=%s/30", tap, host_ip)
        return tap

    async def teardown(self, slot: int) -> None:
        """Remove TAP device and associated iptables rules."""
        tap = self.tap_name(slot)
        host_ip = self.host_ip(slot)
        subnet = f"{self._subnet_prefix}.{slot}.0/30"

        # Remove iptables rules (best-effort, ignore errors)
        cleanup_cmds = [
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", self._wan_iface, "-j", "MASQUERADE"],
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

    async def _iptables_ensure(self, table_flag: list[str], rule: list[str]) -> None:
        """Add iptables rule only if it does not already exist."""
        check_cmd = ["iptables"] + table_flag + ["-C"] + rule
        add_cmd = ["iptables"] + table_flag + ["-A"] + rule
        result = await self._run_result(check_cmd)
        if result != 0:
            await self._run(add_cmd, ignore_errors=True)

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

    @staticmethod
    async def _run_result(cmd: list[str]) -> int:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        return proc.returncode


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
        pool_size = settings.cid_range_end - settings.cid_range_start + 1
        if settings.max_concurrent_vms > pool_size:
            raise RuntimeError(
                f"max_concurrent_vms={settings.max_concurrent_vms} exceeds CID pool size "
                f"({settings.cid_range_start}–{settings.cid_range_end}, {pool_size} slots). "
                "Increase cid_range_end or reduce max_concurrent_vms."
            )
        self._cid_pool = CIDAllocator(settings.cid_range_start, settings.cid_range_end)
        self._tap_mgr = TAPManager(settings) if settings.tap_enabled else None
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_vms)
        self._persistence = persistence
        self._ip_registry = IPRegistry()

    @property
    def available_slots(self) -> int:
        return self._cid_pool.available_count

    @property
    def active_vms(self) -> list[dict[str, Any]]:
        """Live snapshot of running VM IP assignments."""
        return self._ip_registry.snapshot()

    async def run_analysis(
        self,
        job_id: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        artifact_name: str | None = None,
        kernel_path: str | None = None,
        rootfs_path: str | None = None,
    ) -> VMRunResult:
        """Run a complete VM analysis cycle. Blocks until the VM finishes or times out."""
        async with self._semaphore:
            return await self._run_analysis_inner(
                job_id, job_type, package_name, artifact_bytes, artifact_name,
                kernel_path or self._settings.firecracker_default_kernel,
                rootfs_path or self._settings.firecracker_default_rootfs,
            )

    async def _run_analysis_inner(
        self,
        job_id: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        artifact_name: str | None,
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
        telemetry_events: list[str] = []
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
                self._ip_registry.register(
                    cid=cid,
                    job_id=job_id,
                    tap=workspace.tap_device,
                    host_ip=self._tap_mgr.host_ip(slot),
                    guest_ip=self._tap_mgr.guest_ip(slot),
                )

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
            logger.info("[%s] Telemetry and log listeners started, connector tasks running", job_id)

            # 7+8. Deliver job and wait for agent to finish — single combined timeout
            async def _deliver_then_wait() -> None:
                await asyncio.to_thread(
                    self._deliver_job, workspace, job_id, job_type, package_name, artifact_bytes, artifact_name
                )
                logger.info("[%s] Job delivered to guest", job_id)
                logger.info("[%s] Waiting for agent to finish (max %ds)...", job_id, self._settings.vm_analysis_timeout_seconds)
                await finished_signal.wait()

            try:
                await asyncio.wait_for(
                    _deliver_then_wait(),
                    timeout=self._settings.vm_analysis_timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("[%s] Timeout waiting for agent_finished; telemetry_events=%d, log_lines=%d", job_id, len(telemetry_events), len(log_lines))
                raise
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

        except asyncio.TimeoutError as exc:
            logger.warning("[%s] VM analysis timed out.", job_id)
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
            # Custom params parsed by /run_at_start/init from /proc/cmdline
            return f"{base} fc_ip={guest_ip} fc_gw={host_ip} fc_mask=30"
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
        telemetry_events: list[str],
        relevant_runtime_events: list[dict[str, Any]],
        relevant_runtime_summary: dict[str, Any],
        log_lines: list[str],
        finished_signal: asyncio.Event,
        job_id: str,
    ) -> tuple[asyncio.AbstractServer, asyncio.AbstractServer, list[asyncio.Task[None]]]:

        async def on_telemetry_line(text: str) -> None:
            telemetry_events.append(text)
            logger.debug("[%s][telemetry] %s", job_id, text[:200])
            # Agent sends telemetry as: <timestamp> <job_id> <event_name> [key=value ...]
            # Extract the event name (3rd space-delimited field)
            parts = text.split()
            if len(parts) >= 3 and parts[2] in ("agent_finished", "verdict"):
                # Give a short delay to allow log_lines from vsock port 7002 to flush
                # before setting finished_signal and tearing down the VM.
                async def _signal() -> None:
                    await asyncio.sleep(0.5)
                    finished_signal.set()
                asyncio.create_task(_signal())

        async def on_log_line(text: str) -> None:
            log_lines.append(text)
            logger.debug("[%s][log] %s", job_id, text[:200])

            if text.startswith("STDOUT:"):
                # pip/npm install output — store in dedicated table
                rest = text[len("STDOUT:"):]
                phase_part, content = rest.split("|", 1) if "|" in rest else (rest, rest)
                if self._persistence:
                    with suppress(Exception):
                        await self._persistence.write_pip_output(job_id, phase_part, content)

            elif text.startswith(("AGENT:", "MARKER:")):
                # Agent diagnostic messages and phase markers
                if self._persistence:
                    with suppress(Exception):
                        await self._persistence.write_log(job_id, "guest", "debug", text)

            else:
                # PHASE: strace lines (and any unprefixed fallback)
                before_ioc_count = len(detector.ioc_events)
                detector.observe_line(text)

                # Persist any newly triggered IOC events
                if self._persistence and len(detector.ioc_events) > before_ioc_count:
                    for ev in detector.ioc_events[before_ioc_count:]:
                        with suppress(Exception):
                            await self._persistence.write_ioc_event(
                                job_id,
                                ev.phase,
                                ev.category,
                                ev.subcategory,
                                ev.score_contribution,
                                ev.detail,
                                ev.raw_line,
                            )
                        with suppress(Exception):
                            await self._persistence.write_suspicious_line(
                                job_id, ev.raw_line, category=ev.category
                            )

        # Ensure old vsock UDS socket files are removed (Firecracker routes to these paths)
        with suppress(FileNotFoundError):
            workspace.telemetry_socket.unlink()
        with suppress(FileNotFoundError):
            workspace.log_socket.unlink()

        # Create Unix socket servers for telemetry (7001) and logs (7002)
        # Firecracker automatically routes guest vsock connections to these socket files
        async def _handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, on_line: Any) -> None:
            try:
                # Read handshake: guest sends "CONNECT <port>\n"
                handshake = await asyncio.wait_for(reader.readline(), timeout=5.0)
                expected = f"CONNECT {port}".encode()
                if not handshake.startswith(expected):
                    logger.warning("[%s] Bad handshake on port %d: %r", job_id, port, handshake)
                    writer.close()
                    with suppress(Exception):
                        await writer.wait_closed()
                    return
                
                # Send ack
                writer.write(f"OK {port}\n".encode())
                await writer.drain()
                logger.debug("[%s] Handshake OK on port %d", job_id, port)
                
                # Stream lines until connection closes
                while True:
                    line = await reader.readline()
                    if not line:
                        logger.debug("[%s] Connection closed on port %d", job_id, port)
                        break
                    text = line.decode("utf-8", errors="replace").rstrip("\n")
                    if text:
                        await on_line(text)
            except asyncio.TimeoutError:
                logger.warning("[%s] Handshake timeout on port %d", job_id, port)
            except Exception as exc:
                logger.error("[%s] Channel %d error: %s", job_id, port, exc, exc_info=True)
            finally:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

        # Start Unix socket servers for telemetry and logs
        tel_server = await asyncio.start_unix_server(
            lambda r, w: _handle_connection(r, w, self._settings.vsock_telemetry_port, on_telemetry_line),
            path=str(workspace.telemetry_socket),
        )
        log_server = await asyncio.start_unix_server(
            lambda r, w: _handle_connection(r, w, self._settings.vsock_log_port, on_log_line),
            path=str(workspace.log_socket),
        )
        logger.info("[%s] Telemetry and log Unix socket servers started", job_id)

        # Serve connections (these are background tasks that handle incoming connections)
        async def _serve_tel() -> None:
            async with tel_server:
                await tel_server.serve_forever()

        async def _serve_log() -> None:
            async with log_server:
                await log_server.serve_forever()

        serve_tasks = [
            asyncio.create_task(_serve_tel()),
            asyncio.create_task(_serve_log()),
        ]

        return tel_server, log_server, serve_tasks

    # ─── Job delivery (vsock port 7000) ───────────────────────────────

    def _deliver_job(
        self,
        workspace: VMWorkspace,
        job_id: str,
        job_type: str,
        package_name: str,
        artifact_bytes: bytes,
        artifact_name: str | None = None,
    ) -> None:
        artifact_sha = hashlib.sha256(artifact_bytes).hexdigest() if artifact_bytes else ""

        # Ensure a sensible artifact filename is provided to the guest agent.
        if not artifact_name:
            if job_type == "npm":
                ext = ".tgz"
            elif job_type == "pypi":
                ext = ".zip"
            else:
                ext = ".pkg"
            artifact_name = f"{package_name}{ext}"

        payload = {
            "job_id": job_id,
            "job_type": job_type,
            "package": package_name,
            "artifact_size": len(artifact_bytes),
            "artifact_sha256": artifact_sha,
            "artifact_name": artifact_name,
        }

        deadline = time.monotonic() + self._settings.vm_analysis_timeout_seconds + 30
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
            sock.settimeout(30.0)
            sock.connect(str(workspace.vsock_socket))

            # Vsock proxy handshake
            sock.sendall(b"CONNECT 7000\n")
            proxy_ack = self._recv_line(sock)
            if not proxy_ack.startswith(b"OK"):
                raise RuntimeError(f"Vsock proxy rejected CONNECT 7000: {proxy_ack!r}")

            # The forwarded guest stream still expects its own CONNECT line.
            sock.sendall(b"CONNECT 7000\n")
            guest_ack = self._recv_line(sock)
            if not guest_ack.startswith(b"OK"):
                raise RuntimeError(f"Guest agent rejected CONNECT 7000: {guest_ack!r}")

            # Send framed payload: JSON header + artifact bytes
            sock.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
            if artifact_bytes:
                sock.sendall(artifact_bytes)

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
        self._ip_registry.release(cid)

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
