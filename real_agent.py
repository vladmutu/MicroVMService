#!/usr/bin/env python3
"""
agent.py — Dynamic analysis guest agent for Firecracker microVMs.

Collects raw behavioral evidence from PyPI and npm package installation/execution
and streams it to the host for verdict computation by DynamicIOCDetector.

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
  Port 7001 — Telemetry (lifecycle events, one JSON line each)
  Port 7002 — Log stream  (structured events: syscalls, file/net/process/dns)

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
from collections import defaultdict
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
ARTIFACT_PATH: Path = WORK_DIR / "artifact.pkg"   # overwritten after format detection

# All syscalls to trace — grouped by category for readability / maintenance.
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

# Absolute binary paths inside the microVM rootfs
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
# Telemetry + log-stream helpers
# ---------------------------------------------------------------------------

class Telemetry:
    """Lifecycle events → port 7001."""

    def __init__(self, job_id: str, channel: Channel) -> None:
        self._job_id = job_id
        self._ch = channel

    def emit(self, event: str, **fields: Any) -> None:
        payload: dict[str, Any] = {
            "ts": time.time(),
            "job_id": self._job_id,
            "event": event,
        }
        payload.update(fields)
        try:
            self._ch.send_line(json.dumps(payload, separators=(",", ":")).encode())
        except Exception:
            pass


class LogStream:
    """
    Structured evidence events → port 7002.
    All runtime/strace observations travel through here.
    """

    def __init__(self, channel: Channel) -> None:
        self._ch = channel
        self._lock = threading.Lock()
        self._seq = 0

    def emit(self, event: str, **fields: Any) -> None:
        with self._lock:
            self._seq += 1
            seq = self._seq
        payload: dict[str, Any] = {"ts": time.time(), "seq": seq, "event": event}
        payload.update(fields)
        try:
            line = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8", errors="replace")
        except Exception:
            line = json.dumps(
                {"ts": time.time(), "seq": seq, "event": "serialization_error",
                 "original_event": event},
                separators=(",", ":"),
            ).encode()
        self._ch.send_line(line)

    def debug(self, message: str) -> None:
        print(f"[agent] {message}", flush=True)
        self.emit("agent_debug", message=message)


class StdioRouter:
    """Redirects sys.stdout / sys.stderr into the log stream."""

    def __init__(self, log: LogStream, stream_name: str) -> None:
        self._log = log
        self._name = stream_name

    def write(self, text: str) -> None:
        stripped = text.strip()
        if stripped:
            self._log.emit("stdio_line", stream=self._name, message=stripped)

    def flush(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Ingress: receive framed job over vsock 7000
# ---------------------------------------------------------------------------

def receive_job() -> tuple[dict[str, Any], bytes]:
    """
    Binds vsock port 7000, accepts one connection, reads the framed job.
    Returns (header_dict, artifact_bytes).
    """
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

    # Read header line
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

    # Drain, then ack
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
    """
    Persists artifact bytes with the correct extension, updates ARTIFACT_PATH.
    Returns True if SHA-256 matches (or no hash was provided).
    """
    global ARTIFACT_PATH
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # Detect format from magic bytes
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
    """
    Extracts ARTIFACT_PATH into EXTRACT_DIR.
    Silently ignores extraction failures — the strace phases still run.
    """
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
# strace line parsing
# ---------------------------------------------------------------------------

_RE_PID_PREFIX   = re.compile(r"^\[pid\s+(?P<pid>\d+)\]\s+(?P<body>.*)$")
_RE_TIMESTAMP    = re.compile(r"^(?P<ts>\d+\.\d+)\s+(?P<body>.*)$")
_RE_EXIT_MARKER  = re.compile(r"^\+\+\+ exited with (?P<code>-?\d+) \+\+\+$")
_RE_KILLED       = re.compile(r"^\+\+\+ killed by (?P<sig>\w+) \+\+\+$")
_RE_SYSCALL      = re.compile(r"^(?P<name>[a-zA-Z_]\w*)\((?P<args>.*)\)\s+=\s+(?P<ret>.+)$")
_RE_UNFINISHED   = re.compile(r"^(?P<name>[a-zA-Z_]\w*)\((?P<args>.*)<unfinished \.\.\\.>$")
_RE_RESUMED      = re.compile(r"^<\.\.\.\s+(?P<name>[a-zA-Z_]\w*)\s+resumed>(?P<tail>.*)$")
_RE_INET_IP      = re.compile(
    r"(?:inet_addr\(\"(?P<a>[0-9.]+)\"\)|sin_addr=inet_addr\(\"(?P<b>[0-9.]+)\"\))"
)
_RE_PORT         = re.compile(r"sin_port=htons\((?P<p>\d+)\)")
_RE_FD_INT       = re.compile(r"^-?\d+")
_RE_QUOTED       = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


def _split_args(text: str) -> list[str]:
    """Split a syscall argument string at top-level commas (respects nesting + strings)."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
            buf.append(ch)
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            continue
        if ch == "," and depth == 0:
            p = "".join(buf).strip()
            if p:
                parts.append(p)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _safe_int(s: str | None) -> int | None:
    if not s:
        return None
    m = _RE_FD_INT.match(s.strip())
    if not m:
        return None
    try:
        return int(m.group(0))
    except ValueError:
        return None


def _extract_ip_port(raw: str) -> tuple[str | None, int | None]:
    ip = None
    m = _RE_INET_IP.search(raw)
    if m:
        ip = m.group("a") or m.group("b")
    port = None
    m2 = _RE_PORT.search(raw)
    if m2:
        try:
            port = int(m2.group("p"))
        except ValueError:
            pass
    return ip, port


def _extract_path(args: list[str]) -> str | None:
    for a in args:
        a = a.strip()
        if a.startswith('"') and a.endswith('"'):
            return _unquote(a)
    return None


def _extract_argv(raw: str) -> list[str]:
    b = raw.find("[")
    if b == -1:
        return []
    e = raw.find("]", b)
    if e == -1:
        return []
    parts = _split_args(raw[b + 1 : e])
    return [_unquote(p.strip()) for p in parts if p.strip() not in ("...", "")]


# ---------------------------------------------------------------------------
# Runtime data collector
# ---------------------------------------------------------------------------

class RuntimeDataCollector:
    """
    Parses strace output line-by-line and emits structured JSON events covering:

      syscall_event         — every traced syscall with parsed args/return
      process_start         — execve/execveat/clone/fork/vfork
      process_exit          — exit/exit_group/process_exit_marker/killed_by_signal
      signal_sent           — kill/tkill/tgkill
      network_event         — socket lifecycle + data transfer
      file_event            — open/read/write/unlink/chmod/chown/link/symlink/mmap/…
      credential_event      — getuid/setuid/capget/capset/prctl/…
      dns_event             — sendto/sendmsg/connect on port 53
      ipc_event             — ptrace/pipe/dup/memfd_create/inotify/…
      mmap_event            — mmap/mprotect with executable flags
      artifact_created      — interesting derived facts (exec from /tmp, write-then-exec, …)
      strace_unparsed       — lines that didn't parse (forwarded verbatim for host)
      agent_debug           — internal diagnostics
    """

    def __init__(
        self,
        job_id: str,
        ecosystem: str,
        package: str,
        log: LogStream,
    ) -> None:
        self._job_id = job_id
        self._ecosystem = ecosystem
        self._package = package
        self._log = log

        # Per-process state
        self._ppid: dict[int, int] = {}
        self._start_ts: dict[int, float] = {}
        self._cmd: dict[int, list[str]] = {}
        self._cwd: dict[int, str] = {}
        self._fd_table: dict[int, dict[int, dict[str, str]]] = defaultdict(dict)

        # File tracking
        self._file_write_ts: dict[str, float] = {}
        self._known_created: set[str] = set()

        # Unfinished syscall buffer
        self._pending: dict[tuple[int | None, str], str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mark_phase(self, phase: str, state: str) -> None:
        self._emit("phase_event", ts=time.time(), phase=phase, state=state)

    def observe_strace_line(self, line: str, phase: str) -> None:
        raw = line.rstrip("\n")
        if not raw:
            return
        parsed = self._parse(raw)
        if parsed is None:
            self._emit("strace_unparsed", ts=time.time(), phase=phase, line=raw)
            return
        self._dispatch(parsed, phase, raw)

    def observe_stdout_line(self, line: str, phase: str) -> None:
        """Captures process stdout (env references, DNS calls surfaced by libs, etc.)."""
        stripped = line.strip()
        if not stripped:
            return
        self._emit("stdout_line", ts=time.time(), phase=phase, line=stripped)
        # Surface getenv / getaddrinfo patterns that appear in user-space output
        if "getenv(" in stripped:
            self._emit("env_access", ts=time.time(), phase=phase, line=stripped)
        if "getaddrinfo(" in stripped:
            self._emit("dns_event", ts=time.time(), phase=phase, source="stdout", line=stripped)

    # ------------------------------------------------------------------
    # strace parsing
    # ------------------------------------------------------------------

    def _parse(self, raw: str) -> dict[str, Any] | None:
        body = raw
        pid: int | None = None

        m = _RE_PID_PREFIX.match(body)
        if m:
            pid = int(m.group("pid"))
            body = m.group("body")

        ts = time.time()
        m = _RE_TIMESTAMP.match(body)
        if m:
            try:
                ts = float(m.group("ts"))
            except ValueError:
                pass
            body = m.group("body")

        # +++ exited with N +++
        m = _RE_EXIT_MARKER.match(body)
        if m:
            return {"ts": ts, "pid": pid, "syscall": "_exit_marker",
                    "args_raw": "", "args": [], "ret": m.group("code")}

        # +++ killed by SIG +++
        m = _RE_KILLED.match(body)
        if m:
            return {"ts": ts, "pid": pid, "syscall": "_killed_by_signal",
                    "args_raw": m.group("sig"), "args": [m.group("sig")], "ret": ""}

        # unfinished
        m = _RE_UNFINISHED.match(body)
        if m:
            self._pending[(pid, m.group("name"))] = m.group("args")
            return None

        # resumed
        m = _RE_RESUMED.match(body)
        if m:
            name = m.group("name")
            prefix = self._pending.pop((pid, name), "")
            body = f"{name}({prefix}{m.group('tail')}"

        m = _RE_SYSCALL.match(body)
        if not m:
            return None

        name = m.group("name")
        args_raw = m.group("args")
        return {
            "ts": ts,
            "pid": pid,
            "syscall": name,
            "args_raw": args_raw,
            "args": _split_args(args_raw),
            "ret": m.group("ret").strip(),
        }

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, p: dict[str, Any], phase: str, raw: str) -> None:
        ts = p["ts"]
        pid = p["pid"]
        syscall = p["syscall"]
        args = p["args"]
        args_raw = p["args_raw"]
        ret = p["ret"]

        # Always emit the raw syscall event
        self._emit(
            "syscall_event",
            ts=ts, phase=phase,
            pid=pid,
            ppid=self._ppid.get(pid) if pid is not None else None,
            syscall=syscall,
            args=args,
            args_raw=args_raw,
            return_value=ret,
            raw=raw,
        )

        # Route to specialised trackers
        self._track_process(ts, phase, pid, syscall, args, args_raw, ret)
        self._track_network(ts, phase, pid, syscall, args, args_raw, ret)
        self._track_files(ts, phase, pid, syscall, args, args_raw, ret)
        self._track_credentials(ts, phase, pid, syscall, args, args_raw, ret)
        self._track_ipc(ts, phase, pid, syscall, args, args_raw, ret)
        self._track_memory(ts, phase, pid, syscall, args, args_raw, ret)

    # ------------------------------------------------------------------
    # Process tracking
    # ------------------------------------------------------------------

    def _track_process(
        self, ts: float, phase: str,
        pid: int | None, syscall: str,
        args: list[str], args_raw: str, ret: str,
    ) -> None:
        if pid is None:
            return

        if syscall in ("_exit_marker", "exit", "exit_group"):
            start = self._start_ts.get(pid, ts)
            self._emit(
                "process_exit",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                return_value=ret,
                lifetime_seconds=max(0.0, ts - start),
                cmd=self._cmd.get(pid),
            )
            return

        if syscall == "_killed_by_signal":
            self._emit(
                "process_exit",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                killed_by_signal=args_raw,
                lifetime_seconds=max(0.0, ts - self._start_ts.get(pid, ts)),
            )
            return

        if syscall in ("kill", "tkill", "tgkill"):
            target = _safe_int(args[0]) if args else None
            sig = args[1].strip() if len(args) > 1 else None
            self._emit(
                "signal_sent",
                ts=ts, phase=phase,
                sender_pid=pid, target_pid=target, signal=sig,
            )
            return

        if syscall in ("fork", "vfork", "clone"):
            child = _safe_int(ret)
            if child is not None and child > 0:
                self._ppid[child] = pid
                self._start_ts[child] = ts
                if pid in self._cwd:
                    self._cwd[child] = self._cwd[pid]
                self._emit(
                    "process_start",
                    ts=ts, phase=phase,
                    pid=child, ppid=pid, syscall=syscall,
                    cwd=self._cwd.get(child),
                    late_spawn=(phase == "monitor"),
                )
            return

        if syscall in ("execve", "execveat"):
            binary = _unquote(args[0]) if args else ""
            argv = _extract_argv(args_raw)
            self._start_ts.setdefault(pid, ts)
            self._cmd[pid] = [binary] + argv

            exec_from_tmp = binary.startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))
            recently_written = binary in self._file_write_ts
            shell_invocation = binary.endswith(("/sh", "/bash", "/dash", "/zsh", "/ksh"))
            inline_cmd = "-c" in argv

            self._emit(
                "process_start",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                binary=binary, args=argv,
                cwd=self._cwd.get(pid),
                exec_from_tmp=exec_from_tmp,
                recently_written_file=recently_written,
                shell_invocation=shell_invocation,
                inline_command=inline_cmd,
                # Detect interpreter abuse: python/node used with suspicious flags
                downloads_and_runs=(
                    shell_invocation and inline_cmd and
                    any(kw in " ".join(argv) for kw in ("curl", "wget", "http", "base64", "eval"))
                ),
                obfuscated_cmdline=(
                    any(len(a) > 256 for a in argv) or
                    any(kw in " ".join(argv) for kw in ("base64", "\\x", "\\u00", "eval(", "exec("))
                ),
            )

            if exec_from_tmp:
                self._emit("artifact_created", ts=ts, phase=phase, pid=pid,
                           kind="exec_from_tmp", path=binary)
            if recently_written:
                age = ts - self._file_write_ts[binary]
                self._emit("artifact_created", ts=ts, phase=phase, pid=pid,
                           kind="exec_recently_written", path=binary,
                           age_seconds=round(age, 3))
            return

        if syscall == "chdir" and args:
            self._cwd[pid] = _unquote(args[0])
        elif syscall == "fchdir":
            pass  # fd-based chdir — we lose the path without /proc
        elif syscall == "getcwd":
            qs = _RE_QUOTED.findall(ret)
            if qs:
                self._cwd[pid] = qs[0]

        # wait4 / waitpid
        if syscall in ("wait4", "waitpid"):
            waited_pid = _safe_int(args[0]) if args else None
            self._emit(
                "process_wait",
                ts=ts, phase=phase,
                pid=pid, waited_pid=waited_pid, return_value=ret,
            )

    # ------------------------------------------------------------------
    # Network tracking
    # ------------------------------------------------------------------

    def _track_network(
        self, ts: float, phase: str,
        pid: int | None, syscall: str,
        args: list[str], args_raw: str, ret: str,
    ) -> None:
        if pid is None:
            return

        if syscall == "socket":
            fd = _safe_int(ret)
            domain = args[0].strip() if args else ""
            sock_type = args[1].strip() if len(args) > 1 else ""
            proto = args[2].strip() if len(args) > 2 else ""
            if fd is not None:
                self._fd_table[pid][fd] = {
                    "kind": "socket", "domain": domain,
                    "type": sock_type, "protocol": proto,
                }
            self._emit(
                "network_event",
                ts=ts, phase=phase, pid=pid,
                action="socket_create", fd=fd,
                family=domain, socket_type=sock_type, protocol=proto,
            )
            return

        if syscall == "bind":
            fd = _safe_int(args[0]) if args else None
            ip, port = _extract_ip_port(args_raw)
            self._emit(
                "network_event",
                ts=ts, phase=phase, pid=pid,
                action="bind", fd=fd, ip=ip, port=port,
            )
            return

        if syscall == "listen":
            fd = _safe_int(args[0]) if args else None
            backlog = _safe_int(args[1]) if len(args) > 1 else None
            meta = self._fd_table[pid].get(fd or -1, {})
            self._emit(
                "network_event",
                ts=ts, phase=phase, pid=pid,
                action="listen", fd=fd, backlog=backlog,
                family=meta.get("domain"), socket_type=meta.get("type"),
            )
            return

        if syscall in (
            "connect", "accept", "accept4",
            "sendto", "recvfrom", "sendmsg", "recvmsg",
            "sendmmsg", "recvmmsg",
        ):
            fd = _safe_int(args[0]) if args else None
            ip, port = _extract_ip_port(args_raw)
            meta = self._fd_table[pid].get(fd or -1, {})
            size = _safe_int(ret)
            failed = size is not None and size < 0

            self._emit(
                "network_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                action=syscall, fd=fd,
                ip=ip, port=port,
                family=meta.get("domain"), protocol=meta.get("protocol"),
                payload_size=max(0, size) if size is not None and not failed else None,
                failed=failed, return_value=ret, args_raw=args_raw,
            )

            # DNS heuristic: outbound UDP/TCP on port 53
            if port == 53:
                self._emit(
                    "dns_event",
                    ts=ts, phase=phase, pid=pid,
                    ppid=self._ppid.get(pid),
                    syscall=syscall, port=53, ip=ip, args_raw=args_raw,
                )
            return

        if syscall in ("getsockopt", "setsockopt"):
            fd = _safe_int(args[0]) if args else None
            self._emit(
                "network_event",
                ts=ts, phase=phase, pid=pid,
                action=syscall, fd=fd, args_raw=args_raw,
            )
            return

        if syscall == "shutdown":
            fd = _safe_int(args[0]) if args else None
            how = args[1].strip() if len(args) > 1 else None
            self._emit(
                "network_event",
                ts=ts, phase=phase, pid=pid,
                action="shutdown", fd=fd, how=how,
            )

    # ------------------------------------------------------------------
    # File-system tracking
    # ------------------------------------------------------------------

    def _track_files(
        self, ts: float, phase: str,
        pid: int | None, syscall: str,
        args: list[str], args_raw: str, ret: str,
    ) -> None:
        if pid is None:
            return

        # ---- open / openat / creat ----
        if syscall in ("open", "openat", "creat"):
            path = _extract_path(args)
            fd = _safe_int(ret)
            flags = args_raw
            if fd is not None and path:
                self._fd_table[pid][fd] = {"kind": "file", "path": path}

            access = "read"
            if "O_WRONLY" in flags or "O_RDWR" in flags:
                access = "write"
            if "O_CREAT" in flags or syscall == "creat":
                access = "create"

            hidden = bool(path) and Path(path).name.startswith(".")

            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type=access,
                path=path, fd=fd, flags=flags,
                hidden_file=hidden, return_value=ret,
            )

            if path and access == "create" and path not in self._known_created:
                self._known_created.add(path)
                self._emit(
                    "artifact_created",
                    ts=ts, phase=phase, pid=pid, kind="new_file", path=path,
                    is_tmp=path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")),
                    hidden_file=hidden,
                )
            return

        # ---- read / write / pread64 / pwrite64 ----
        if syscall in ("read", "write", "pread64", "pwrite64", "readv", "writev"):
            fd = _safe_int(args[0]) if args else None
            size = _safe_int(ret)
            path = None
            if fd is not None:
                meta = self._fd_table[pid].get(fd)
                if meta and meta.get("kind") == "file":
                    path = meta.get("path")

            is_write = syscall in ("write", "pwrite64", "writev")
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall,
                access_type="write" if is_write else "read",
                path=path, fd=fd,
                size=max(0, size) if size is not None else None,
                return_value=ret,
            )
            if is_write and path and (size or 0) > 0:
                self._file_write_ts[path] = ts
            return

        # ---- unlink / rename ----
        if syscall in ("unlink", "unlinkat", "rename", "renameat", "renameat2"):
            qs = _RE_QUOTED.findall(args_raw)
            src = qs[0] if qs else None
            dst = qs[1] if len(qs) > 1 else None
            op = "delete" if syscall.startswith("unlink") else "rename"
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type=op,
                path=src, target_path=dst, return_value=ret,
            )
            # Write-then-delete within 2 s is classic dropper behaviour
            if op == "delete" and src and src in self._file_write_ts:
                age = ts - self._file_write_ts[src]
                if age <= 2.0:
                    self._emit(
                        "artifact_created",
                        ts=ts, phase=phase, pid=pid,
                        kind="write_delete_quick", path=src,
                        age_seconds=round(age, 3),
                    )
            return

        # ---- chmod / fchmod / fchmodat ----
        if syscall in ("chmod", "fchmod", "fchmodat"):
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            executable = "755" in args_raw or "111" in args_raw or "0111" in args_raw
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type="chmod",
                path=path, args_raw=args_raw,
                made_executable=executable, return_value=ret,
            )
            if executable and path:
                self._emit("artifact_created", ts=ts, phase=phase, pid=pid,
                           kind="file_made_executable", path=path)
            return

        # ---- chown ----
        if syscall in ("chown", "fchown", "fchownat"):
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type="chown",
                path=path, args_raw=args_raw, return_value=ret,
            )
            return

        # ---- link / symlink ----
        if syscall in ("link", "linkat", "symlink", "symlinkat"):
            qs = _RE_QUOTED.findall(args_raw)
            src = qs[0] if qs else None
            dst = qs[1] if len(qs) > 1 else None
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type="link",
                path=src, target_path=dst, return_value=ret,
            )
            return

        # ---- readlink ----
        if syscall in ("readlink", "readlinkat"):
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type="readlink",
                path=path, return_value=ret,
            )
            return

        # ---- mkdir / rmdir ----
        if syscall in ("mkdir", "mkdirat", "rmdir"):
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            op = "mkdir" if "mkdir" in syscall else "rmdir"
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type=op,
                path=path, return_value=ret,
            )
            return

        # ---- truncate ----
        if syscall in ("truncate", "ftruncate"):
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type="truncate",
                path=path, args_raw=args_raw, return_value=ret,
            )
            return

        # ---- stat / access ----
        if syscall in (
            "stat", "fstat", "lstat", "statx", "newfstatat",
            "access", "faccessat",
        ):
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            self._emit(
                "file_event",
                ts=ts, phase=phase,
                pid=pid, ppid=self._ppid.get(pid),
                operation=syscall, access_type="stat",
                path=path, return_value=ret,
            )

    # ------------------------------------------------------------------
    # Credential tracking
    # ------------------------------------------------------------------

    def _track_credentials(
        self, ts: float, phase: str,
        pid: int | None, syscall: str,
        args: list[str], args_raw: str, ret: str,
    ) -> None:
        if pid is None:
            return

        READ_CRED = {"getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid"}
        WRITE_CRED = {"setuid", "seteuid", "setgid", "setegid", "setresuid", "setresgid"}

        if syscall in READ_CRED:
            self._emit(
                "credential_event",
                ts=ts, phase=phase, pid=pid,
                action="read", syscall=syscall, return_value=ret,
            )
            return

        if syscall in WRITE_CRED:
            self._emit(
                "credential_event",
                ts=ts, phase=phase, pid=pid,
                action="set", syscall=syscall,
                args_raw=args_raw, return_value=ret,
            )
            return

        if syscall == "capget":
            self._emit(
                "credential_event",
                ts=ts, phase=phase, pid=pid,
                action="capget", args_raw=args_raw, return_value=ret,
            )
            return

        if syscall == "capset":
            self._emit(
                "credential_event",
                ts=ts, phase=phase, pid=pid,
                action="capset", args_raw=args_raw, return_value=ret,
            )
            return

        if syscall == "prctl":
            option = args[0].strip() if args else None
            self._emit(
                "credential_event",
                ts=ts, phase=phase, pid=pid,
                action="prctl", option=option, args_raw=args_raw, return_value=ret,
            )

    # ------------------------------------------------------------------
    # IPC / misc tracking
    # ------------------------------------------------------------------

    def _track_ipc(
        self, ts: float, phase: str,
        pid: int | None, syscall: str,
        args: list[str], args_raw: str, ret: str,
    ) -> None:
        if pid is None:
            return

        if syscall == "ptrace":
            request = args[0].strip() if args else None
            target = _safe_int(args[1]) if len(args) > 1 else None
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action="ptrace", request=request, target_pid=target,
                return_value=ret,
            )
            return

        if syscall in ("pipe", "pipe2"):
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action=syscall, args_raw=args_raw, return_value=ret,
            )
            return

        if syscall in ("dup", "dup2", "dup3"):
            old_fd = _safe_int(args[0]) if args else None
            new_fd = _safe_int(args[1]) if len(args) > 1 else None
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action=syscall, old_fd=old_fd, new_fd=new_fd, return_value=ret,
            )
            # Duplicate stdin/stdout/stderr to a socket → classic reverse shell
            if old_fd is not None and new_fd is not None and new_fd <= 2:
                meta = self._fd_table[pid].get(old_fd, {})
                if meta.get("kind") == "socket":
                    self._emit(
                        "artifact_created",
                        ts=ts, phase=phase, pid=pid,
                        kind="stdio_redirected_to_socket",
                        old_fd=old_fd, new_fd=new_fd,
                    )
            return

        if syscall == "memfd_create":
            qs = _RE_QUOTED.findall(args_raw)
            name = qs[0] if qs else None
            fd = _safe_int(ret)
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action="memfd_create", name=name, fd=fd, return_value=ret,
            )
            self._emit(
                "artifact_created",
                ts=ts, phase=phase, pid=pid,
                kind="memfd_create", name=name,
            )
            return

        if syscall in ("inotify_init", "inotify_init1"):
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action=syscall, return_value=ret,
            )
            return

        if syscall == "inotify_add_watch":
            qs = _RE_QUOTED.findall(args_raw)
            path = qs[0] if qs else None
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action="inotify_add_watch", path=path, args_raw=args_raw,
            )
            return

        if syscall in ("timerfd_create", "eventfd", "eventfd2"):
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action=syscall, args_raw=args_raw, return_value=ret,
            )
            return

        if syscall in ("fcntl", "ioctl"):
            fd = _safe_int(args[0]) if args else None
            cmd = args[1].strip() if len(args) > 1 else None
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action=syscall, fd=fd, cmd=cmd, return_value=ret,
            )
            return

        if syscall == "syslog":
            action = args[0].strip() if args else None
            self._emit(
                "ipc_event",
                ts=ts, phase=phase, pid=pid,
                action="syslog", syslog_action=action, return_value=ret,
            )

    # ------------------------------------------------------------------
    # Memory mapping tracking
    # ------------------------------------------------------------------

    def _track_memory(
        self, ts: float, phase: str,
        pid: int | None, syscall: str,
        args: list[str], args_raw: str, ret: str,
    ) -> None:
        if pid is None:
            return

        if syscall == "mmap":
            prot = args[2].strip() if len(args) > 2 else ""
            flags = args[3].strip() if len(args) > 3 else ""
            fd = _safe_int(args[4]) if len(args) > 4 else None
            executable = "PROT_EXEC" in prot
            anonymous = "MAP_ANONYMOUS" in flags or "MAP_ANON" in flags
            self._emit(
                "mmap_event",
                ts=ts, phase=phase, pid=pid,
                syscall="mmap", prot=prot, flags=flags,
                fd=fd, anonymous=anonymous,
                executable=executable, return_value=ret,
            )
            if executable and anonymous:
                self._emit(
                    "artifact_created",
                    ts=ts, phase=phase, pid=pid,
                    kind="anon_exec_mmap",
                )
            return

        if syscall == "mprotect":
            prot = args[1].strip() if len(args) > 1 else ""
            executable = "PROT_EXEC" in prot
            self._emit(
                "mmap_event",
                ts=ts, phase=phase, pid=pid,
                syscall="mprotect", prot=prot,
                executable=executable, return_value=ret,
            )
            if executable:
                self._emit(
                    "artifact_created",
                    ts=ts, phase=phase, pid=pid,
                    kind="mprotect_exec", prot=prot,
                )

    # ------------------------------------------------------------------
    # Internal emit
    # ------------------------------------------------------------------

    def _emit(self, event: str, **fields: Any) -> None:
        self._log.emit(
            event,
            job_id=self._job_id,
            ecosystem=self._ecosystem,
            package=self._package,
            **fields,
        )


# ---------------------------------------------------------------------------
# strace runner
# ---------------------------------------------------------------------------

def _tail_strace_log(
    log_path: Path,
    proc: subprocess.Popen,
    collector: RuntimeDataCollector,
    phase: str,
) -> None:
    """Background thread: tail strace output file and forward to collector."""
    sent = 0
    while proc.poll() is None:
        if log_path.exists():
            with log_path.open("r", errors="replace") as fh:
                fh.seek(sent)
                for line in fh:
                    collector.observe_strace_line(line.rstrip(), phase=phase)
                sent = fh.tell()
        time.sleep(0.15)
    # Final flush
    if log_path.exists():
        with log_path.open("r", errors="replace") as fh:
            fh.seek(sent)
            for line in fh:
                collector.observe_strace_line(line.rstrip(), phase=phase)


def _pump_stdout(
    stream,
    collector: RuntimeDataCollector,
    phase: str,
) -> None:
    """Background thread: drain subprocess stdout to prevent pipe-buffer deadlock."""
    for line in stream:
        collector.observe_stdout_line(line.rstrip(), phase=phase)


def run_with_strace(
    cmd: list[str],
    log_path: Path,
    log: LogStream,
    tel: Telemetry,
    collector: RuntimeDataCollector,
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
        tel.emit("warning", message="strace not found — running without tracing", cmd=cmd)
        # Fallback: run naked, capture stdout only
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout,
            )
            for line in (result.stdout or "").splitlines():
                collector.observe_stdout_line(line, phase=phase)
            return result.returncode or 0
        except subprocess.TimeoutExpired:
            return -1

    tailer = threading.Thread(
        target=_tail_strace_log,
        args=(log_path, proc, collector, phase),
        daemon=True,
    )
    pumper = threading.Thread(
        target=_pump_stdout,
        args=(proc.stdout, collector, phase),
        daemon=True,
    )
    tailer.start()
    pumper.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        log.emit("strace_timeout", phase=phase, timeout_seconds=timeout, command=cmd)

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

    # npm
    target = str(_find_npm_pkg_dir()) if has_artifact else package
    return [_BIN["npm"], "install", "--no-fund", "--no-audit", target]


# ---------------------------------------------------------------------------
# Post-install execution probes
# ---------------------------------------------------------------------------

def find_entry_points(job_type: str, package: str) -> list[list[str]]:
    """Return probe commands to execute after installation."""
    cmds: list[list[str]] = []

    if job_type == "pypi":
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", package.split("==")[0])
        cmds.append([_BIN["python"], "-c", f"import {safe}; print('import_ok')"])
        cmds.append([_BIN["python"], "-m", safe])

    elif job_type == "npm":
        pkg_dir = _find_npm_pkg_dir()
        # 1. index.js
        index = pkg_dir / "index.js"
        if index.exists():
            cmds.append([_BIN["node"], str(index)])
        # 2. bin scripts from package.json
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
                # 3. "main" entry
                main = meta.get("main")
                if main:
                    main_path = pkg_dir / main
                    if main_path.exists() and [_BIN["node"], str(main_path)] not in cmds:
                        cmds.append([_BIN["node"], str(main_path)])
                # 4. scripts.postinstall (already executed by npm, but probe explicitly)
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
    collector: RuntimeDataCollector,
) -> int:
    log.debug("phase_install_started")
    collector.mark_phase("install", "start")
    install_cmd = build_install_command(job_type, package, has_artifact)
    tel.emit("install_started", cmd=install_cmd)
    log.debug(f"install_cmd={install_cmd}")

    install_log = WORK_DIR / "strace_install.log"
    exit_code = run_with_strace(
        install_cmd, install_log, log, tel, collector,
        phase="install", timeout=INSTALL_TIMEOUT,
    )
    tel.emit("install_done", exit_code=exit_code)
    collector.mark_phase("install", "end")
    log.debug(f"phase_install_done exit_code={exit_code}")
    return exit_code


def phase_execution_probes(
    job_type: str,
    package: str,
    log: LogStream,
    tel: Telemetry,
    collector: RuntimeDataCollector,
) -> int:
    log.debug("phase_exec_probes_started")
    collector.mark_phase("exec", "start")
    probes = find_entry_points(job_type, package)
    count = 0
    safe_name = re.sub(r"[^a-zA-Z0-9_]+", "_", package)
    for cmd in probes:
        tel.emit("exec_started", cmd=cmd)
        probe_log = WORK_DIR / f"strace_exec_{safe_name}_{count}.log"
        exit_code = run_with_strace(
            cmd, probe_log, log, tel, collector,
            phase="exec", timeout=PROBE_TIMEOUT,
        )
        tel.emit("exec_done", cmd=cmd, exit_code=exit_code)
        count += 1
    collector.mark_phase("exec", "end")
    log.debug(f"phase_exec_probes_done count={count}")
    return count


def phase_ambient_monitor(
    log: LogStream,
    tel: Telemetry,
    collector: RuntimeDataCollector,
    duration: int = MONITOR_DURATION,
) -> None:
    """
    Attach strace to PID 1 for `duration` seconds to catch any delayed malicious
    behaviour (persistence setup, C2 beacons, cron injection, etc.).
    """
    log.debug(f"phase_monitor_started duration={duration}s")
    tel.emit("monitor_started", duration=duration)
    collector.mark_phase("monitor", "start")

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
            args=(monitor_log, proc, collector, "monitor"),
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
        log.debug(f"monitor_error: {exc}")
        tel.emit("monitor_error", error=str(exc))

    collector.mark_phase("monitor", "end")
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
    collector = RuntimeDataCollector(job_id, job_type, package, log)

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
                log.debug(f"hash_mismatch expected={expected_sha256} actual={actual_sha256}")
                tel.emit("artifact_hash_mismatch",
                         expected=expected_sha256, actual=actual_sha256)
            else:
                tel.emit("artifact_received",
                         size=len(artifact_bytes), sha256=actual_sha256)
                collector._emit(
                    "artifact_created",
                    ts=time.time(), phase="ingress",
                    kind="uploaded_artifact", path=str(ARTIFACT_PATH),
                    size=len(artifact_bytes), sha256=actual_sha256,
                )
            extract_artifact()
            log.debug(f"artifact_extracted to={EXTRACT_DIR}")
        else:
            WORK_DIR.mkdir(parents=True, exist_ok=True)
            tel.emit("artifact_received", size=0, note="no artifact — install from registry")
            log.debug("no_artifact_install_from_registry")

        # ------------------------------------------------------------------
        # Phase 2 — Install under strace
        # ------------------------------------------------------------------
        install_exit_code = phase_install(
            job_type, package, has_artifact, log, tel, collector,
        )

        # ------------------------------------------------------------------
        # Phase 3 — Execution probes under strace
        # ------------------------------------------------------------------
        probe_count = phase_execution_probes(
            job_type, package, log, tel, collector,
        )

        # ------------------------------------------------------------------
        # Phase 4 — Ambient monitor (strace -p 1)
        # ------------------------------------------------------------------
        phase_ambient_monitor(log, tel, collector)

        # ------------------------------------------------------------------
        # Completion
        # ------------------------------------------------------------------
        tel.emit("agent_finished",
                 install_exit_code=install_exit_code,
                 probes=probe_count,
                 status="ok")
        collector._emit(
            "agent_finished",
            ts=time.time(),
            install_exit_code=install_exit_code,
            probes=probe_count,
            status="ok",
        )
        log.debug(f"agent_finished exit_code={install_exit_code} probes={probe_count}")

    except Exception:
        import traceback
        tb = traceback.format_exc()
        log.debug(f"agent_crashed:\n{tb}")
        tel.emit("agent_finished", status="crashed", traceback=tb)
        collector._emit("agent_finished", ts=time.time(), status="crashed", traceback=tb)

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