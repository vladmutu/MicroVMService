#!/usr/bin/env python3
"""
agent.py — Dynamic analysis guest agent for Firecracker microVMs.

Collects raw behavioral evidence from PyPI and npm package installation/execution
and streams it to the host as newline-delimited raw text lines.

No verdict computation is performed here. All scoring, pattern matching,
and IOC detection is delegated entirely to the host service.

Architecture
------------
  Phase 0  Receive job (vsock 7000) + open outbound channels (7001, 7002)
  Phase 1  Artifact ingress: save, verify SHA-256, extract
  Phase 2  Install under strace
  Phase 3  Post-install execution probes under strace
  Phase 4  Extended ambient monitoring (strace -p 1)
  Phase 5  Graceful shutdown + channel flush

Host ← Guest protocol
---------------------
  Port 7001 — Telemetry (lifecycle events, one raw text line each)
               Format: <timestamp_unix_float> <job_id> <event_name> [key=value ...]
  Port 7002 — Raw strace lines (verbatim strace output, one line per write)
               Format: raw strace output line, optionally prefixed with phase tag
               Prefix: PHASE:<phase_name>|<raw_strace_line>

Guest ← Host protocol (port 7000)
----------------------------------
  Line 1  : CONNECT 7000\n (handshake from host)
  Line 2  : JSON header (newline-terminated)
    {
      "job_id":          "<uuid4>",
      "job_type":        "pypi" | "npm",
      "package":         "<name[==version]>",
      "artifact_size":   <int>,
      "artifact_sha256": "<hex | ''>"
    }
  Remainder: exactly artifact_size raw bytes.

Syscalls traced (comprehensive)
--------------------------------
  Process lifecycle  : execve execveat clone fork vfork exit exit_group
                       wait4 waitpid kill tkill tgkill
  Network            : socket bind connect accept accept4 listen
                       sendto recvfrom sendmsg recvmsg sendmmsg recvmmsg
                       getsockopt setsockopt shutdown
  File-system        : open openat creat read write pread64 pwrite64
                       readv writev mmap munmap mprotect
                       unlink unlinkat rename renameat renameat2
                       chmod fchmod fchmodat chown fchown fchownat
                       link linkat symlink symlinkat readlink readlinkat
                       mkdir mkdirat rmdir truncate ftruncate
                       stat fstat lstat statx newfstatat access faccessat
                       getcwd chdir fchdir
  Credentials        : getuid geteuid getgid getegid setuid seteuid
                       setgid setegid setresuid setresgid getresuid getresgid
                       capget capset prctl
  IPC / misc         : ptrace pipe pipe2 dup dup2 dup3 fcntl ioctl
                       syslog sched_setaffinity memfd_create
                       inotify_add_watch inotify_init inotify_init1
                       timerfd_create eventfd eventfd2
  Environment        : getenv (captured from traced output / LD_PRELOAD hooks)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOST_CID: int = 2
PORT_INGRESS: int = 7000
PORT_TELEMETRY: int = 7001
PORT_LOGS: int = 7002

WORK_DIR: Path = Path("/tmp/analysis")
EXTRACT_DIR: Path = WORK_DIR / "src"
ARTIFACT_PATH: Path = WORK_DIR / "artifact.pkg"

_TRACE_SYSCALLS: list[str] = [
    # --- process lifecycle ---
    "execve", "execveat", "clone", "fork", "vfork",
    "exit", "exit_group", "wait4", "waitpid",
    "kill", "tkill", "tgkill",
    # --- network ---
    "socket", "bind", "connect", "accept", "accept4", "listen",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    "getsockopt", "setsockopt", "shutdown",
    # --- filesystem ---
    "open", "openat", "creat",
    # REMOVED: "read", "write", "pread64", "pwrite64", "readv", "writev",
    "mmap", "munmap", "mprotect",
    "unlink", "unlinkat",
    "rename", "renameat", "renameat2",
    "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "fchownat",
    "link", "linkat", "symlink", "symlinkat",
    "readlink", "readlinkat",
    "mkdir", "mkdirat", "rmdir",
    "truncate", "ftruncate",
    "stat", "fstat", "lstat", "statx", "newfstatat",
    "access", "faccessat",
    "getcwd", "chdir", "fchdir",
    # --- credentials ---
    "getuid", "geteuid", "getgid", "getegid",
    "setresuid", "setresgid",
    "capget", "capset", "prctl",
    # --- ipc / misc ---
    "ptrace", "pipe", "pipe2", "dup", "dup2", "dup3", "fcntl", "ioctl",
    "syslog", "sched_setaffinity", "memfd_create",
    "inotify_add_watch", "inotify_init", "inotify_init1",
    "timerfd_create", "eventfd", "eventfd2",
]
TRACE_SYSCALLS_ARG: str = ",".join(_TRACE_SYSCALLS)

# Timeouts (seconds)
INSTALL_TIMEOUT: int = 90
PROBE_TIMEOUT: int = 60
MONITOR_DURATION: int = 45

_BIN = {
    "python": "/usr/bin/python3",
    "pip": "/usr/bin/pip3",
    "node": "/usr/bin/node",
    "npm": "/usr/bin/npm",
    "strace": "/usr/bin/strace",
}


# ---------------------------------------------------------------------------
# Vsock transport
# ---------------------------------------------------------------------------

class Channel:
    """
    Robust vsock channel with safe retry + handshake handling.
    Thread-safe.
    """

    def __init__(self, cid: int, port: int) -> None:
        self._cid = cid
        self._port = port
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()

    def connect(self, retries: int = 20, delay: float = 0.5) -> None:
        last_error = None

        for attempt in range(retries):
            s = None
            try:
                s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                s.settimeout(3.0)

                s.connect((self._cid, self._port))

                # handshake
                s.sendall(f"CONNECT {self._port}\n".encode())

                # read response safely (not byte-by-byte)
                s.settimeout(2.0)
                response = b""
                start = time.time()

                while b"\n" not in response:
                    if time.time() - start > 2.0:
                        raise TimeoutError("handshake timeout")

                    chunk = s.recv(1024)
                    if not chunk:
                        raise ConnectionError("empty handshake response")
                    response += chunk

                if response.startswith(f"OK {self._port}".encode()):
                    s.settimeout(None)
                    self._sock = s
                    return

                raise ConnectionError(f"bad handshake: {response!r}")

            except Exception as exc:
                last_error = exc
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
                time.sleep(delay)

        raise ConnectionRefusedError(
            f"failed to connect to port {self._port} after {retries} attempts: {last_error}"
        )

    def send_line(self, data: bytes) -> None:
        if not data.endswith(b"\n"):
            data += b"\n"

        with self._lock:
            if not self._sock:
                return
            try:
                self._sock.sendall(data)
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None


# ---------------------------------------------------------------------------
# Telemetry (port 7001) — lifecycle events as raw text lines
# ---------------------------------------------------------------------------

class Telemetry:
    """
    Lifecycle events → port 7001.

    Line format (space-delimited, always newline-terminated):
        <unix_timestamp_float> <job_id> <event_name> [key=value ...]

    key=value pairs are URL-encoded (no spaces in values; use %20 if needed).
    The host must parse these by splitting on the first two spaces for the
    fixed fields, then splitting remaining tokens on '=' for key/value pairs.

    Examples:
        1700000000.123456 abc-123 agent_started job_type=pypi package=requests artifact_size=0
        1700000001.000000 abc-123 install_started cmd=pip3,install,--no-cache-dir,requests
        1700000030.500000 abc-123 agent_finished install_exit_code=0 probes=2 status=ok
    """

    def __init__(self, job_id: str, channel: Channel) -> None:
        self._job_id = job_id
        self._ch = channel

    def emit(self, event: str, **fields: Any) -> None:
        ts = f"{time.time():.6f}"
        parts = [ts, self._job_id, event]
        for k, v in fields.items():
            # Flatten lists/dicts to comma-joined strings; escape spaces
            if isinstance(v, (list, tuple)):
                v_str = ",".join(str(x) for x in v)
            elif v is None:
                v_str = "null"
            else:
                v_str = str(v).replace(" ", "%20").replace("\n", "%0A")
            parts.append(f"{k}={v_str}")
        line = " ".join(parts)
        try:
            self._ch.send_line(line.encode("utf-8", errors="replace"))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Log stream (port 7002) — raw strace lines with phase prefix
# ---------------------------------------------------------------------------

class LogStream:
    """
    Raw strace output → port 7002.

    Each line written to this channel is either:

      1. A raw strace output line, prefixed with a phase tag:
            PHASE:<phase>|<verbatim strace line>
         Example:
            PHASE:install|1700000001.123456 execve("/usr/bin/python3", ...) = 0

      2. An agent diagnostic line (not from strace):
            AGENT:<level>|<message>
         Example:
            AGENT:debug|phase_install_started

      3. A phase boundary marker:
            MARKER:<phase>:<state>
         Example:
            MARKER:install:start
            MARKER:install:end

      4. A subprocess stdout/stderr line captured from the traced process:
            STDOUT:<phase>|<line>

    The host must NOT parse strace lines here into structured events.
    All parsing and pattern-matching is the host's responsibility.
    """

    def __init__(self, channel: Channel) -> None:
        self._ch = channel

    def raw_strace(self, line: str, phase: str) -> None:
        """Forward a verbatim strace output line with a phase prefix."""
        stripped = line.rstrip("\n")
        if not stripped:
            return
        out = f"PHASE:{phase}|{stripped}"
        self._ch.send_line(out.encode("utf-8", errors="replace"))

    def stdout_line(self, line: str, phase: str) -> None:
        """Forward a line captured from the traced process's stdout."""
        stripped = line.strip()
        if not stripped:
            return
        out = f"STDOUT:{phase}|{stripped}"
        self._ch.send_line(out.encode("utf-8", errors="replace"))

    def marker(self, phase: str, state: str) -> None:
        """Emit a phase boundary marker so the host can segment the stream."""
        out = f"MARKER:{phase}:{state}"
        self._ch.send_line(out.encode("utf-8", errors="replace"))

    def debug(self, message: str) -> None:
        print(f"[agent] {message}", flush=True)
        out = f"AGENT:debug|{message}"
        self._ch.send_line(out.encode("utf-8", errors="replace"))

    def warning(self, message: str) -> None:
        print(f"[agent] WARNING: {message}", flush=True)
        out = f"AGENT:warning|{message}"
        self._ch.send_line(out.encode("utf-8", errors="replace"))


class StdioRouter:
    """Redirects sys.stdout / sys.stderr into the log stream."""

    def __init__(self, log: LogStream, stream_name: str, phase: str = "agent") -> None:
        self._log = log
        self._name = stream_name
        self._phase = phase

    def write(self, text: str) -> None:
        stripped = text.strip()
        if stripped:
            self._log.stdout_line(f"[{self._name}] {stripped}", phase=self._phase)

    def flush(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Network readiness check
# ---------------------------------------------------------------------------

def _wait_for_network(log: "LogStream", tel: "Telemetry", timeout: int = 30) -> bool:
    """
    Poll outbound TCP connectivity to 1.1.1.1:443 (no DNS required).
    Returns True once reachable, False if timeout expires.
    On failure the agent continues in degraded mode — strace data is still valid.
    """
    import socket as _socket
    deadline = time.time() + timeout
    attempt = 0
    start = time.time()
    while time.time() < deadline:
        attempt += 1
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(("1.1.1.1", 443))
            elapsed = f"{time.time() - start:.2f}"
            tel.emit("network_ok", attempt=attempt, elapsed=elapsed)
            log.debug(f"network_ok attempt={attempt} elapsed={elapsed}s")
            return True
        except OSError:
            pass
        time.sleep(2)
    tel.emit("network_failed", attempts=attempt, timeout=timeout)
    log.warning(f"network_unavailable after {attempt} attempt(s) — pip/npm dependency downloads will fail")
    return False


# ---------------------------------------------------------------------------
# Ingress: receive framed job over vsock 7000
# ---------------------------------------------------------------------------

def receive_job() -> tuple[dict[str, Any], str, int]:
    """
    Listen on vsock port 7000, handle handshake, receive JSON header + artifact.
    Returns: (header_dict, actual_sha256, bytes_received)
    """
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to vsock port 7000
    for attempt in range(10):
        try:
            srv.bind((socket.VMADDR_CID_ANY, PORT_INGRESS))
            break
        except OSError as exc:
            print(f"[agent] vsock bind attempt {attempt}: {exc}", flush=True)
            time.sleep(0.5)
    else:
        raise RuntimeError("failed to bind vsock port 7000 after 10 retries")

    srv.listen(1)
    print("[agent] listening on vsock port 7000, waiting for connection...", flush=True)
    
    conn, _ = srv.accept()
    print("[agent] connection accepted on port 7000", flush=True)

    # ===== HANDSHAKE =====
    # Expect: "CONNECT 7000\n"
    buf = b""
    conn.settimeout(5.0)
    while b"\n" not in buf:
        chunk = conn.recv(1024)
        if not chunk:
            raise ConnectionError("connection closed before handshake")
        buf += chunk

    handshake_line, buf = buf.split(b"\n", 1)
    handshake = handshake_line.decode("utf-8", errors="replace").strip()
    
    if not handshake.startswith("CONNECT 7000"):
        raise RuntimeError(f"invalid handshake: {handshake!r}")
    
    # Send handshake response
    conn.sendall(b"OK 7000\n")
    print(f"[agent] handshake OK: {handshake!r}", flush=True)

    # ===== JSON HEADER =====
    # Next line is JSON header
    conn.settimeout(10.0)
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before JSON header")
        buf += chunk

    header_line, buf = buf.split(b"\n", 1)
    header: dict[str, Any] = json.loads(header_line.decode("utf-8"))
    print(f"[agent] received header: {header}", flush=True)

    artifact_size = int(header.get("artifact_size", 0))

    # ===== ARTIFACT BYTES (stream to disk) =====
    global ARTIFACT_PATH
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH = WORK_DIR / "artifact.pkg"
    
    hasher = hashlib.sha256()
    bytes_received = 0

    conn.settimeout(30.0)  # Allow time for large artifacts

    with ARTIFACT_PATH.open("wb") as f:
        # 1. Write leftover bytes from header split
        if buf and artifact_size > 0:
            initial_data = buf[:artifact_size]
            f.write(initial_data)
            hasher.update(initial_data)
            bytes_received += len(initial_data)

        # 2. Stream remaining bytes
        while bytes_received < artifact_size:
            remaining = artifact_size - bytes_received
            chunk = conn.recv(min(65536, remaining))
            if not chunk:
                break
            f.write(chunk)
            hasher.update(chunk)
            bytes_received += len(chunk)

    actual_sha256 = hasher.hexdigest()
    print(f"[agent] artifact received: {bytes_received} bytes, sha256={actual_sha256}", flush=True)

    # ===== CLEANUP =====
    # Drain any extra bytes
    conn.settimeout(0.3)
    try:
        while conn.recv(4096):
            pass
    except Exception:
        pass

    conn.close()
    srv.close()
    
    return header, actual_sha256, bytes_received


# ---------------------------------------------------------------------------
# Artifact handling
# ---------------------------------------------------------------------------

def detect_and_normalize_artifact(path: Path) -> Path | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)

        new_ext = None

        # ZIP / WHEEL
        if head.startswith(b"PK"):
            try:
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
                    if any(".dist-info/" in n for n in names):
                        new_ext = ".whl"
                    else:
                        new_ext = ".zip"
            except Exception:
                new_ext = ".zip"

        # GZIP (tar.gz / tgz)
        elif head.startswith(b"\x1f\x8b"):
            new_ext = ".tar.gz"

        # Optional fallback
        elif tarfile.is_tarfile(path):
            new_ext = ".tar"

        # FIXED: This is now unindented to run for all file types
        if new_ext:
            new_name = path.with_name(path.stem + new_ext)
            path.replace(new_name)
            return new_name

        return None

    except Exception:
        return None


# ---------------------------------------------------------------------------
# strace runner — streams raw lines directly to port 7002
# ---------------------------------------------------------------------------

def _tail_strace_log(
    log_path: Path,
    proc: subprocess.Popen,
    log: LogStream,
    phase: str,
) -> None:
    """Background thread: tail strace output file and forward raw lines to host."""
    sent = 0
    while proc.poll() is None:
        if log_path.exists():
            with log_path.open("r", errors="replace") as fh:
                fh.seek(sent)
                for line in fh:
                    log.raw_strace(line.rstrip("\n"), phase=phase)
                sent = fh.tell()
        time.sleep(0.15)
    # Final flush after process exits
    if log_path.exists():
        with log_path.open("r", errors="replace") as fh:
            fh.seek(sent)
            for line in fh:
                log.raw_strace(line.rstrip("\n"), phase=phase)


def _run_strace_once(strace_cmd):
    """Run strace command and return process handle."""
    return subprocess.Popen(
        strace_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def run_with_strace(
    cmd: list[str],
    log_path: Path,
    log: LogStream,
    tel: Telemetry,
    phase: str,
    timeout: int,
) -> tuple[int, bool, bool]:
    """
    Run command under strace, streaming strace output to host in real-time.
    Returns: (exit_code, timed_out, fallback_used)
    """
    cmd_text = " ".join(cmd)
    log.debug(f"strace_launch phase={phase} timeout={timeout}s cmd={cmd_text}")
    tel.emit("strace_launch", phase=phase, timeout=timeout, cmd=cmd_text)

    base_cmd = [
        _BIN["strace"],
        "-f",
        "-v",
        "-s", "65535",
        "-y",
        "-yy",
        "--timestamps=unix,us",
        "-e", f"trace={TRACE_SYSCALLS_ARG}",
        "-o", str(log_path),
    ] + cmd

    proc = _run_strace_once(base_cmd)
    tel.emit("strace_started", phase=phase, pid=proc.pid, log_path=str(log_path))
    output_buffer = []
    timed_out = False
    fallback_used = False

    def collect_output():
        if proc.stdout:
            for line in proc.stdout:
                output_buffer.append(line)
                stripped = line.strip()
                if stripped:
                    log.stdout_line(stripped, phase=phase)

    t = threading.Thread(target=collect_output, daemon=True)
    t.start()

    # Stream strace log to host in real-time while command runs
    tailer = threading.Thread(
        target=_tail_strace_log,
        args=(log_path, proc, log, phase),
        daemon=True,
    )
    tailer.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        log.warning(f"Process timed out after {timeout}s, terminating...")
        tel.emit("process_timeout", phase=phase)
        tel.emit("strace_timeout", phase=phase, timeout=timeout, fallback=False)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    t.join(timeout=2)
    tailer.join(timeout=3.0)

    combined_output = "".join(output_buffer)

    # Check if syscall filter failed
    if "invalid system call" in combined_output:
        fallback_used = True
        log.warning("strace syscall filter invalid — falling back to trace=all")
        tel.emit("strace_fallback_triggered", phase=phase, reason="invalid_system_call")

        fallback_cmd = [
            _BIN["strace"],
            "-f",
            "-v",
            "-s", "65535",
            "-y",
            "-yy",
            "--timestamps=unix,us",
            "-e", "trace=all",
            "-o", str(log_path),
        ] + cmd

        tel.emit("strace_fallback_started", phase=phase, reason="invalid_system_call")
        proc = _run_strace_once(fallback_cmd)

        def _drain_fallback():
            if proc.stdout:
                for line in proc.stdout:
                    output_buffer.append(line)
                    stripped = line.strip()
                    if stripped:
                        log.stdout_line(stripped, phase=phase)

        tf = threading.Thread(target=_drain_fallback, daemon=True)
        tf.start()

        fallback_tailer = threading.Thread(
            target=_tail_strace_log,
            args=(log_path, proc, log, phase),
            daemon=True,
        )
        fallback_tailer.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            log.warning(f"Fallback process timed out after {timeout}s, terminating...")
            tel.emit("process_timeout_fallback", phase=phase)
            tel.emit("strace_timeout", phase=phase, timeout=timeout, fallback=True)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        tf.join(timeout=2)
        fallback_tailer.join(timeout=3.0)
        tel.emit("strace_fallback_done", phase=phase, exit_code=proc.returncode or 0)

    exit_code = proc.returncode or 0
    tel.emit(
        "strace_exit",
        phase=phase,
        exit_code=exit_code,
        timed_out=timed_out,
        fallback=fallback_used,
    )
    if exit_code != 0:
        tel.emit("strace_nonzero_exit", phase=phase, exit_code=exit_code, fallback=fallback_used)

    return exit_code, timed_out, fallback_used


# ---------------------------------------------------------------------------
# Install command builder
# ---------------------------------------------------------------------------

def _find_npm_pkg_dir() -> Path:
    """Find package.json directory in extracted artifact.

    Extraction is no longer performed; this helper returns EXTRACT_DIR
    for compatibility, but callers should prefer installing the artifact
    file directly when present.
    """
    pkg_jsons = sorted(EXTRACT_DIR.rglob("package.json"), key=lambda p: len(p.parts))
    return pkg_jsons[0].parent if pkg_jsons else EXTRACT_DIR / "package"


def build_install_command(job_type: str, package: str, has_artifact: bool) -> list[str]:
    """Build the install command for pip or npm."""
    if job_type == "pypi":
        if has_artifact:
            target = str(ARTIFACT_PATH)
            if ARTIFACT_PATH.suffix == ".whl":
                # Removed --no-index so it fetches dependencies!
                return [_BIN["pip"], "install", "--no-cache-dir", target]
            return [_BIN["pip"], "install", "--no-cache-dir", target]
        return [_BIN["pip"], "install", "--no-cache-dir", package]

    target = str(ARTIFACT_PATH) if has_artifact else package
    return [_BIN["npm"], "install", "--no-fund", "--no-audit", target]


# ---------------------------------------------------------------------------
# Post-install execution probes
# ---------------------------------------------------------------------------

def find_entry_points(job_type: str, package: str) -> list[list[str]]:
    """Find entry points to execute after installation."""
    cmds: list[list[str]] = []

    if job_type == "pypi":
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", package.split("==")[0])
        cmds.append([_BIN["python"], "-c", f"import {safe}; print('import_ok')"])
        cmds.append([_BIN["python"], "-m", safe])

    elif job_type == "npm":
        # We no longer extract npm artifacts. Prefer simple runtime probes by
        # attempting to require the installed package by name (if provided).
        name = package.split("@")[0].split("==")[0]
        safe = re.sub(r"[^a-zA-Z0-9_\-@/\\.]", "_", name)
        if safe:
            # Try a lightweight require check
            cmds.append([_BIN["node"], "-e", f"require('{safe}'); console.log('require_ok')"]) 
            # Also try executing package as a module
            cmds.append([_BIN["node"], "-e", f"(async()=>{{try{{const m=require('{safe}'); if(m && m.main) console.log('has_main');}}catch(e){{}}}})();"])

    return cmds


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------

def phase_install(
    job_type: str,
    package: str,
    has_artifact: bool,
    log: LogStream,
    tel: Telemetry,
) -> int:
    """Phase 2: Install package under strace."""
    global ARTIFACT_PATH
    log.debug("phase_install_started")
    log.marker("install", "start")

    if has_artifact:
        # Artifact is already renamed using host metadata in main()
        log.debug(f"artifact path is {ARTIFACT_PATH}")

    # 1. Create a per-job virtual environment FIRST (if PyPI)
    venv_dir = WORK_DIR / "venv"
    if job_type == "pypi":
        try:
            WORK_DIR.mkdir(parents=True, exist_ok=True)
            # Create venv using system python
            subprocess.run([_BIN["python"], "-m", "venv", str(venv_dir)], check=True, timeout=20)
            tel.emit("venv_created", path=str(venv_dir))
            log.debug(f"venv created at {venv_dir}")
            
            # THE FIX: Override global binaries to point directly into the venv!
            # This ensures both the install AND the exec probes use the venv automatically.
            _BIN["python"] = str(venv_dir / "bin" / "python3")
            _BIN["pip"] = str(venv_dir / "bin" / "pip3")
            
        except Exception as exc:
            tel.emit("venv_creation_failed", error=str(exc).replace(" ", "%20"))
            log.warning(f"venv creation failed: {exc}")

    # 2. NOW build the install command (it will use the updated _BIN["pip"])
    install_cmd = build_install_command(job_type, package, has_artifact)
    log.debug(f"install_cmd={install_cmd}")
    tel.emit("install_started", cmd=install_cmd)

    # 3. Run directly (no need for `sh -c activate`!)
    install_log = WORK_DIR / "strace_install.log"
    exit_code, timed_out, fallback_used = run_with_strace(
        install_cmd, install_log, log, tel,
        phase="install", timeout=INSTALL_TIMEOUT,
    )

    tel.emit("install_done", exit_code=exit_code)
    tel.emit("install_outcome", exit_code=exit_code, timed_out=timed_out, fallback=fallback_used)
    if timed_out:
        tel.emit("install_timeout", exit_code=exit_code)
    elif exit_code != 0:
        tel.emit("install_failed", exit_code=exit_code)
    else:
        tel.emit("install_succeeded", exit_code=exit_code)
    log.marker("install", "end")
    log.debug(f"phase_install_done exit_code={exit_code}")
    return exit_code


def phase_execution_probes(
    job_type: str,
    package: str,
    log: LogStream,
    tel: Telemetry,
) -> int:
    """Phase 3: Execute entry points under strace."""
    log.debug("phase_exec_probes_started")
    log.marker("exec", "start")

    probes = find_entry_points(job_type, package)
    count = 0
    safe_name = re.sub(r"[^a-zA-Z0-9_]+", "_", package)

    for cmd in probes:
        tel.emit("exec_started", cmd=cmd)
        probe_log = WORK_DIR / f"strace_exec_{safe_name}_{count}.log"
        exit_code, timed_out, fallback_used = run_with_strace(
            cmd, probe_log, log, tel,
            phase="exec", timeout=PROBE_TIMEOUT,
        )
        tel.emit("exec_done", cmd=cmd, exit_code=exit_code)
        tel.emit("exec_outcome", exit_code=exit_code, timed_out=timed_out, fallback=fallback_used)
        count += 1

    log.marker("exec", "end")
    log.debug(f"phase_exec_probes_done count={count}")
    return count


def phase_ambient_monitor(
    log: LogStream,
    tel: Telemetry,
    duration: int = MONITOR_DURATION,
) -> None:
    """
    Phase 4: Attach strace to PID 1 for `duration` seconds to catch delayed
    malicious behaviour (persistence setup, C2 beacons, cron injection, etc.).
    """
    log.debug(f"phase_monitor_started duration={duration}s")
    tel.emit("monitor_started", duration=duration)
    log.marker("monitor", "start")

    monitor_log = WORK_DIR / "strace_monitor.log"
    strace_cmd = [
        _BIN["strace"],
        "-f", "-p", "1",
        "-v", "-s", "65535", "-y", "-yy",
        "--timestamps=unix,us",
        "-e", f"trace={TRACE_SYSCALLS_ARG}",
        "-o", str(monitor_log),
    ]

    try:
        proc = subprocess.Popen(
            strace_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        tailer = threading.Thread(
            target=_tail_strace_log,
            args=(monitor_log, proc, log, "monitor"),
            daemon=True,
        )
        tailer.start()

        deadline = time.time() + duration
        while time.time() < deadline and proc.poll() is None:
            time.sleep(0.5)

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        tailer.join(timeout=3.0)

    except Exception as exc:
        log.warning(f"monitor_error: {exc}")
        tel.emit("monitor_error", error=str(exc).replace(" ", "%20"))

    log.marker("monitor", "end")
    tel.emit("monitor_done")
    log.debug("phase_monitor_done")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("[agent] started, waiting for job on port 7000", flush=True)
    
    # Receive job header and artifact
    
    header, actual_sha256, bytes_received = receive_job()
    
    job_id: str = header.get("job_id", "unknown")
    job_type: str = header.get("job_type", "pypi")
    package: str = header.get("package", "")
    expected_sha256: str = header.get("artifact_sha256", "")
    artifact_size: int = int(header.get("artifact_size", 0))
    
    # NEW: Extract the real filename sent by the host
    artifact_name: str = header.get("artifact_name", "artifact.pkg")

    print(f"[agent] job received: id={job_id} type={job_type} pkg={package}", flush=True)

    # ===== Open outbound channels =====
    tel_ch = Channel(HOST_CID, PORT_TELEMETRY)
    log_ch = Channel(HOST_CID, PORT_LOGS)
    
    print("[agent] connecting outbound channels...", flush=True)

    # Connect telemetry (required)
    tel_ok = False
    for attempt in range(10):
        try:
            tel_ch.connect()
            tel_ok = True
            print("[agent] telemetry channel connected", flush=True)
            break
        except Exception as exc:
            print(f"[agent] telemetry connect attempt {attempt}: {exc}", flush=True)
            time.sleep(1)

    # Connect logs (optional, fallback to telemetry if failed)
    log_ok = False
    for attempt in range(10):
        try:
            log_ch.connect()
            log_ok = True
            print("[agent] logs channel connected", flush=True)
            break
        except Exception as exc:
            print(f"[agent] logs connect attempt {attempt}: {exc}", flush=True)
            time.sleep(1)

    if not tel_ok:
        print("[agent] WARNING: telemetry channel failed; continuing without telemetry", flush=True)

    if not log_ok:
        print("[agent] INFO: logs channel failed; using telemetry for logs", flush=True)
        log_ch = tel_ch

    tel = Telemetry(job_id, tel_ch)
    log = LogStream(log_ch)

    # Route stdout/stderr through vsock
    sys.stdout = StdioRouter(log, "stdout")  # type: ignore[assignment]
    sys.stderr = StdioRouter(log, "stderr")  # type: ignore[assignment]

    log.debug(f"started job_id={job_id} type={job_type} package={package} artifact_size={artifact_size}")
    tel.emit("agent_started", job_type=job_type, package=package, artifact_size=artifact_size)

    # ===== Network readiness check =====
    _wait_for_network(log, tel, timeout=30)

    install_exit_code = -1
    probe_count = 0

    try:
        # ===== Phase 1: Artifact verification =====
        log.debug("phase_artifact_ingress_started")
        
        has_artifact = artifact_size > 0 and bytes_received == artifact_size

        if has_artifact:
            hash_ok = (not expected_sha256) or (actual_sha256 == expected_sha256)
            
            if not hash_ok:
                log.warning(f"hash_mismatch expected={expected_sha256} actual={actual_sha256}")
                tel.emit("artifact_hash_mismatch", expected=expected_sha256, actual=actual_sha256)
            else:
                tel.emit("artifact_received", size=bytes_received, sha256=actual_sha256)
            
            # NEW: Just rename it directly to what the host told us it is
            global ARTIFACT_PATH
            new_path = ARTIFACT_PATH.with_name(artifact_name)
            ARTIFACT_PATH.replace(new_path)
            ARTIFACT_PATH = new_path
            
            tel.emit("artifact_normalized", ext=new_path.suffix, path=str(new_path))
            log.debug(f"artifact renamed using host metadata to path={new_path}")
        else:
            WORK_DIR.mkdir(parents=True, exist_ok=True)
            tel.emit("artifact_received", size=0, note="no_artifact_install_from_registry")
            log.debug("no_artifact_install_from_registry")

        # ===== Phase 2: Install =====
        install_exit_code = phase_install(job_type, package, has_artifact, log, tel)

        # ===== Phase 3: Execution probes =====
        probe_count = phase_execution_probes(job_type, package, log, tel)

        # ===== Phase 4: Ambient monitoring =====
        phase_ambient_monitor(log, tel)

        # ===== Completion =====
        tel.emit("agent_finished",
                 install_exit_code=install_exit_code,
                 probes=probe_count,
                 status="ok")
        log.debug(f"agent_finished exit_code={install_exit_code} probes={probe_count} status=ok")

    except Exception:
        import traceback
        tb = traceback.format_exc()
        log.warning(f"agent_crashed")
        for tb_line in tb.splitlines():
            log.debug(f"traceback| {tb_line}")
        tel.emit("agent_finished", status="crashed")

    finally:
        log.debug("closing_channels")
        tel_ch.close()
        log_ch.close()


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    print("[agent] script started", flush=True)
    try:
        main()
    except Exception as exc:
        print(f"[agent] FATAL: {exc}", flush=True)
        import traceback
        traceback.print_exc()