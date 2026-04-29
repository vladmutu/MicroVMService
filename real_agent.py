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
  Line 1  : JSON header (newline-terminated)
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
    "read", "write", "pread64", "pwrite64", "readv", "writev",
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
    "setuid", "seteuid", "setgid", "setegid",
    "setresuid", "setresgid", "getresuid", "getresgid",
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
    Lazy vsock connection with a simple handshake and line-oriented framing.
    Thread-safe: multiple threads may call send_line() concurrently.
    """

    def __init__(self, cid: int, port: int) -> None:
        self._cid = cid
        self._port = port
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()

    def connect(self, retries: int = 15, delay: float = 0.5) -> None:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(5.0)
        last_exc: Exception = RuntimeError("no attempts made")
        for _ in range(retries):
            try:
                s.connect((self._cid, self._port))
                s.sendall(f"CONNECT {self._port}\n".encode())
                buf = bytearray()
                while b"\n" not in buf:
                    chunk = s.recv(1)
                    if not chunk:
                        break
                    buf.extend(chunk)
                if not bytes(buf).startswith(f"OK {self._port}".encode()):
                    raise ConnectionRefusedError(
                        f"unexpected handshake on port {self._port}: {bytes(buf)!r}"
                    )
                self._sock = s
                return
            except (ConnectionRefusedError, OSError) as exc:
                last_exc = exc
                time.sleep(delay)
        raise ConnectionRefusedError(
            f"host not listening on port {self._port} after {retries} attempts: {last_exc}"
        )

    def send_line(self, data: bytes) -> None:
        if not data.endswith(b"\n"):
            data = data + b"\n"
        with self._lock:
            if self._sock is None:
                return
            try:
                self._sock.sendall(data)
            except BrokenPipeError:
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
# Ingress: receive framed job over vsock 7000
# ---------------------------------------------------------------------------

def receive_job() -> tuple[dict[str, Any], bytes]:
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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
    conn, _ = srv.accept()

    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk

    header_line, leftover = buf.split(b"\n", 1)
    header: dict[str, Any] = json.loads(header_line.decode())
    artifact_size = int(header.get("artifact_size", 0))

    artifact = leftover
    while len(artifact) < artifact_size:
        chunk = conn.recv(min(65536, artifact_size - len(artifact)))
        if not chunk:
            break
        artifact += chunk
    artifact = artifact[:artifact_size]

    conn.settimeout(0.3)
    try:
        while conn.recv(4096):
            pass
    except Exception:
        pass
    conn.settimeout(None)
    try:
        conn.sendall(b"OK 7000\n")
    except Exception:
        pass
    conn.close()
    srv.close()
    return header, artifact


# ---------------------------------------------------------------------------
# Artifact handling
# ---------------------------------------------------------------------------

def save_and_verify_artifact(data: bytes, expected_sha256: str, job_type: str) -> bool:
    global ARTIFACT_PATH
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    if data[:4] == b"PK\x03\x04":
        suffix = ".whl" if job_type == "pypi" else ".zip"
    elif data[:2] == b"\x1f\x8b":
        suffix = ".tar.gz" if job_type == "pypi" else ".tgz"
    else:
        suffix = ".tar.gz" if job_type == "pypi" else ".tgz"

    ARTIFACT_PATH = WORK_DIR / f"artifact{suffix}"
    ARTIFACT_PATH.write_bytes(data)

    if expected_sha256:
        return hashlib.sha256(data).hexdigest() == expected_sha256
    return True


def extract_artifact() -> None:
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        name = ARTIFACT_PATH.name.lower()
        if name.endswith(".whl") or name.endswith(".zip") or zipfile.is_zipfile(str(ARTIFACT_PATH)):
            with zipfile.ZipFile(str(ARTIFACT_PATH)) as zf:
                try:
                    zf.extractall(str(EXTRACT_DIR), pwd=b"infected")
                except RuntimeError:
                    zf.extractall(str(EXTRACT_DIR))
        elif tarfile.is_tarfile(str(ARTIFACT_PATH)):
            with tarfile.open(str(ARTIFACT_PATH)) as tf:
                tf.extractall(str(EXTRACT_DIR))
    except Exception:
        pass


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


def _pump_stdout(
    stream,
    log: LogStream,
    phase: str,
) -> None:
    """Background thread: drain subprocess stdout and forward to host."""
    for line in stream:
        log.stdout_line(line.rstrip("\n"), phase=phase)


def run_with_strace(
    cmd: list[str],
    log_path: Path,
    log: LogStream,
    tel: Telemetry,
    phase: str,
    timeout: int,
) -> int:
    strace_cmd = [
        _BIN["strace"],
        "-f",                          # follow forks
        "-v",                          # verbose struct decoding
        "-s", "65535",                 # full string capture
        "-y",                          # resolve fd → path
        "-yy",                         # also resolve socket addresses
        "--timestamps=unix,us",        # microsecond UNIX timestamps
        "-e", f"trace={TRACE_SYSCALLS_ARG}",
        "-o", str(log_path),
    ] + cmd

    try:
        proc = subprocess.Popen(
            strace_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except FileNotFoundError:
        log.warning("strace not found — running without tracing")
        tel.emit("warning", message="strace_not_found", cmd=" ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout,
            )
            for line in (result.stdout or "").splitlines():
                log.stdout_line(line, phase=phase)
            return result.returncode or 0
        except subprocess.TimeoutExpired:
            return -1

    tailer = threading.Thread(
        target=_tail_strace_log,
        args=(log_path, proc, log, phase),
        daemon=True,
    )
    pumper = threading.Thread(
        target=_pump_stdout,
        args=(proc.stdout, log, phase),
        daemon=True,
    )
    tailer.start()
    pumper.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        log.warning(f"strace_timeout phase={phase} timeout={timeout}s cmd={cmd}")
        tel.emit("strace_timeout", phase=phase, timeout_seconds=timeout)

    tailer.join(timeout=3.0)
    pumper.join(timeout=3.0)
    return proc.returncode or 0


# ---------------------------------------------------------------------------
# Install command builder
# ---------------------------------------------------------------------------

def _find_npm_pkg_dir() -> Path:
    pkg_jsons = sorted(EXTRACT_DIR.rglob("package.json"), key=lambda p: len(p.parts))
    return pkg_jsons[0].parent if pkg_jsons else EXTRACT_DIR / "package"


def build_install_command(job_type: str, package: str, has_artifact: bool) -> list[str]:
    if job_type == "pypi":
        if has_artifact:
            target = str(ARTIFACT_PATH)
            if ARTIFACT_PATH.suffix == ".whl":
                return [_BIN["pip"], "install", "--no-cache-dir", "--no-index", target]
            return [_BIN["pip"], "install", "--no-cache-dir", "--no-deps", target]
        return [_BIN["pip"], "install", "--no-cache-dir", "--no-deps", package]

    target = str(_find_npm_pkg_dir()) if has_artifact else package
    return [_BIN["npm"], "install", "--no-fund", "--no-audit", target]


# ---------------------------------------------------------------------------
# Post-install execution probes
# ---------------------------------------------------------------------------

def find_entry_points(job_type: str, package: str) -> list[list[str]]:
    cmds: list[list[str]] = []

    if job_type == "pypi":
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", package.split("==")[0])
        cmds.append([_BIN["python"], "-c", f"import {safe}; print('import_ok')"])
        cmds.append([_BIN["python"], "-m", safe])

    elif job_type == "npm":
        pkg_dir = _find_npm_pkg_dir()
        index = pkg_dir / "index.js"
        if index.exists():
            cmds.append([_BIN["node"], str(index)])
        pkg_json = pkg_dir / "package.json"
        if pkg_json.exists():
            try:
                meta = json.loads(pkg_json.read_text(errors="replace"))
                bins = meta.get("bin")
                if isinstance(bins, str):
                    cmds.append([_BIN["node"], str(pkg_dir / bins)])
                elif isinstance(bins, dict):
                    for script in bins.values():
                        cmds.append([_BIN["node"], str(pkg_dir / script)])
                main = meta.get("main")
                if main:
                    main_path = pkg_dir / main
                    if main_path.exists() and [_BIN["node"], str(main_path)] not in cmds:
                        cmds.append([_BIN["node"], str(main_path)])
                scripts = meta.get("scripts", {})
                postinstall = scripts.get("postinstall")
                if postinstall:
                    cmds.append(["/bin/sh", "-c", postinstall])
            except Exception:
                pass

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
    log.debug("phase_install_started")
    log.marker("install", "start")

    install_cmd = build_install_command(job_type, package, has_artifact)
    tel.emit("install_started", cmd=install_cmd)
    log.debug(f"install_cmd={install_cmd}")

    install_log = WORK_DIR / "strace_install.log"
    exit_code = run_with_strace(
        install_cmd, install_log, log, tel,
        phase="install", timeout=INSTALL_TIMEOUT,
    )

    tel.emit("install_done", exit_code=exit_code)
    log.marker("install", "end")
    log.debug(f"phase_install_done exit_code={exit_code}")
    return exit_code


def phase_execution_probes(
    job_type: str,
    package: str,
    log: LogStream,
    tel: Telemetry,
) -> int:
    log.debug("phase_exec_probes_started")
    log.marker("exec", "start")

    probes = find_entry_points(job_type, package)
    count = 0
    safe_name = re.sub(r"[^a-zA-Z0-9_]+", "_", package)

    for cmd in probes:
        tel.emit("exec_started", cmd=cmd)
        probe_log = WORK_DIR / f"strace_exec_{safe_name}_{count}.log"
        exit_code = run_with_strace(
            cmd, probe_log, log, tel,
            phase="exec", timeout=PROBE_TIMEOUT,
        )
        tel.emit("exec_done", cmd=cmd, exit_code=exit_code)
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
    Attach strace to PID 1 for `duration` seconds to catch delayed malicious
    behaviour (persistence setup, C2 beacons, cron injection, etc.).
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
    header, artifact_bytes = receive_job()
    print(f"[agent] job received: {header.get('job_id')}", flush=True)

    job_id: str = header.get("job_id", "unknown")
    job_type: str = header.get("job_type", "pypi")
    package: str = header.get("package", "")
    expected_sha256: str = header.get("artifact_sha256", "")
    artifact_size: int = int(header.get("artifact_size", 0))

    # Open outbound channels
    tel_ch = Channel(HOST_CID, PORT_TELEMETRY)
    log_ch = Channel(HOST_CID, PORT_LOGS)
    print("[agent] connecting outbound channels", flush=True)
    for attempt in range(10):
        try:
            tel_ch.connect()
            log_ch.connect()
            break
        except Exception as exc:
            print(f"[agent] channel connect attempt {attempt}: {exc}", flush=True)
            time.sleep(1)

    tel = Telemetry(job_id, tel_ch)
    log = LogStream(log_ch)

    # Route all stdout/stderr through vsock
    sys.stdout = StdioRouter(log, "stdout")  # type: ignore[assignment]
    sys.stderr = StdioRouter(log, "stderr")  # type: ignore[assignment]

    log.debug(f"started job_id={job_id} type={job_type} package={package} artifact_size={artifact_size}")
    tel.emit("agent_started", job_type=job_type, package=package, artifact_size=artifact_size)

    install_exit_code = -1
    probe_count = 0

    try:
        # ------------------------------------------------------------------
        # Phase 1 — Artifact ingress
        # ------------------------------------------------------------------
        log.debug("phase_artifact_ingress_started")
        has_artifact = artifact_size > 0 and len(artifact_bytes) == artifact_size

        if has_artifact:
            hash_ok = save_and_verify_artifact(artifact_bytes, expected_sha256, job_type)
            actual_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            if not hash_ok:
                log.warning(f"hash_mismatch expected={expected_sha256} actual={actual_sha256}")
                tel.emit("artifact_hash_mismatch", expected=expected_sha256, actual=actual_sha256)
            else:
                tel.emit("artifact_received", size=len(artifact_bytes), sha256=actual_sha256)
            extract_artifact()
            log.debug(f"artifact_extracted to={EXTRACT_DIR}")
        else:
            WORK_DIR.mkdir(parents=True, exist_ok=True)
            tel.emit("artifact_received", size=0, note="no_artifact_install_from_registry")
            log.debug("no_artifact_install_from_registry")

        # ------------------------------------------------------------------
        # Phase 2 — Install under strace
        # ------------------------------------------------------------------
        install_exit_code = phase_install(job_type, package, has_artifact, log, tel)

        # ------------------------------------------------------------------
        # Phase 3 — Execution probes under strace
        # ------------------------------------------------------------------
        probe_count = phase_execution_probes(job_type, package, log, tel)

        # ------------------------------------------------------------------
        # Phase 4 — Ambient monitor (strace -p 1)
        # ------------------------------------------------------------------
        phase_ambient_monitor(log, tel)

        # ------------------------------------------------------------------
        # Completion — emit raw summary line, NO verdict
        # ------------------------------------------------------------------
        tel.emit("agent_finished",
                 install_exit_code=install_exit_code,
                 probes=probe_count,
                 status="ok")
        log.debug(f"agent_finished exit_code={install_exit_code} probes={probe_count} status=ok")

    except Exception:
        import traceback
        tb = traceback.format_exc()
        log.warning(f"agent_crashed")
        # Emit traceback line by line so the host can ingest it
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