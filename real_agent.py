#!/usr/bin/env python3
"""
agent.py — Pure data-collector guest agent running inside the Firecracker microVM.

The agent does NOT compute verdicts — it collects raw behavioral data and
streams it to the host.  The host's DynamicIOCDetector interprets the evidence.

Flow:
    1. Listen on vsock port 7000 for a framed job header + artifact bytes.
    2. Extract the artifact.
    3. Run install and post-install execution probes under verbose strace.
    4. Stream raw strace + stdout/stderr to the host on vsock port 7002.
    5. Emit lifecycle telemetry on vsock port 7001.
    6. Signal agent_finished and exit.

Protocol (host → guest, port 7000):
  Line 1: JSON header, newline-terminated.
    {
      "job_id":          "<uuid4>",
      "job_type":        "pypi" | "npm",
      "package":         "<package-name>",
      "artifact_size":   <int, bytes>,          # 0 = no artifact
      "artifact_sha256": "<hex string | ''>"
    }
  Remaining bytes: exactly artifact_size raw bytes of the package file.

Telemetry events (guest → host, port 7001):
  Each line is a JSON object:
    {"ts": <float>, "job_id": "...", "event": "<type>", ...fields}

  Event types:
    agent_started, artifact_received, artifact_hash_mismatch,
    install_started, install_done,
    exec_started, exec_done,
    agent_finished
"""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOST_CID = 2
PORT_INGRESS = 7000
PORT_TELEMETRY = 7001
PORT_LOGS = 7002

WORK_DIR = Path("/tmp/analysis")
ARTIFACT_PATH = WORK_DIR / "artifact.pkg"
EXTRACT_DIR = WORK_DIR / "src"


# ---------------------------------------------------------------------------
# Vsock channels
# ---------------------------------------------------------------------------

class Channel:
    """Lazy vsock connection with line-oriented send."""

    def __init__(self, cid: int, port: int, label: str):
        self.cid = cid
        self.port = port
        self.label = label
        self._sock: socket.socket | None = None

    def _connect(self) -> None:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(5.0)
        for attempt in range(15):
            try:
                s.connect((self.cid, self.port))
                # Handshake: send CONNECT, expect OK
                s.sendall(f"CONNECT {self.port}\n".encode())
                response = bytearray()
                while not response.endswith(b"\n"):
                    chunk = s.recv(1)
                    if not chunk:
                        break
                    response.extend(chunk)
                if not bytes(response).startswith(f"OK {self.port}".encode()):
                    raise ConnectionRefusedError(
                        f"host rejected port {self.port}: {bytes(response)!r}"
                    )
                self._sock = s
                return
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)

        print(f"[agent] Failed to connect to host port {self.port}", flush=True)
        raise ConnectionRefusedError(f"Host not listening on port {self.port}")

    def send_line(self, data: bytes) -> None:
        if self._sock is None:
            self._connect()
        if not data.endswith(b"\n"):
            data += b"\n"
        try:
            self._sock.sendall(data)
        except BrokenPipeError:
            pass

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


class Telemetry:
    def __init__(self, job_id: str, channel: Channel):
        self.job_id = job_id
        self.ch = channel

    def emit(self, event: str, **fields) -> None:
        payload = {"ts": time.time(), "job_id": self.job_id, "event": event}
        payload.update(fields)
        self.ch.send_line(json.dumps(payload, separators=(",", ":")).encode())


class LogStream:
    def __init__(self, channel: Channel):
        self.ch = channel

    def write(self, text: str) -> None:
        self.ch.send_line(text.encode("utf-8", errors="replace"))


def stream_file_lines(path: Path, log_stream: LogStream) -> None:
    """Stream a file's contents line by line to the host."""
    if not path.exists():
        return
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.rstrip("\n")
                if stripped:
                    log_stream.write(stripped)
    except Exception as exc:
        log_stream.write(f"[agent] failed to stream {path.name}: {exc}")


# ---------------------------------------------------------------------------
# Ingress: read framed job from vsock port 7000
# ---------------------------------------------------------------------------

def read_job() -> tuple[dict, bytes]:
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    for attempt in range(10):
        try:
            srv.bind((socket.VMADDR_CID_ANY, PORT_INGRESS))
            break
        except OSError as e:
            print(f"[agent] Vsock bind attempt {attempt} failed: {e}", flush=True)
            time.sleep(0.5)
    else:
        raise RuntimeError("Failed to bind to vsock port 7000 after retries")

    srv.listen(1)
    conn, _ = srv.accept()

    # Read header line
    header_buf = b""
    while b"\n" not in header_buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        header_buf += chunk

    header_line, leftover = header_buf.split(b"\n", 1)
    header = json.loads(header_line.decode("utf-8"))

    artifact_size = int(header.get("artifact_size", 0))
    artifact_bytes = leftover

    # Read remaining artifact bytes
    while len(artifact_bytes) < artifact_size:
        needed = artifact_size - len(artifact_bytes)
        chunk = conn.recv(min(65536, needed))
        if not chunk:
            break
        artifact_bytes += chunk

    artifact_bytes = artifact_bytes[:artifact_size]

    # Drain extras, then ack
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

    return header, artifact_bytes


# ---------------------------------------------------------------------------
# Artifact handling
# ---------------------------------------------------------------------------

def save_and_verify_artifact(
    artifact_bytes: bytes, expected_sha256: str, job_type: str,
) -> bool:
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # Rename artifact to proper extension for install tools to recognize it
    suffix_map = {
        "pypi": ".tar.gz",  # default; .whl handled below
        "npm": ".tgz",
    }
    suffix = suffix_map.get(job_type, ".pkg")

    # Detect actual format from magic bytes
    if artifact_bytes[:4] == b"PK\x03\x04":
        suffix = ".zip"  # could be .whl
    elif artifact_bytes[:2] == b"\x1f\x8b":
        suffix = ".tar.gz" if job_type == "pypi" else ".tgz"

    actual_path = WORK_DIR / f"artifact{suffix}"
    actual_path.write_bytes(artifact_bytes)

    # Update the global so install commands use the right file
    global ARTIFACT_PATH
    ARTIFACT_PATH = actual_path

    if expected_sha256:
        actual = hashlib.sha256(artifact_bytes).hexdigest()
        return actual == expected_sha256
    return True


def extract_artifact(job_type: str) -> None:
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        suffix = ARTIFACT_PATH.suffix.lower()
        name = ARTIFACT_PATH.name.lower()

        if suffix in (".whl", ".zip") or name.endswith(".whl"):
            with zipfile.ZipFile(str(ARTIFACT_PATH)) as zf:
                zf.extractall(str(EXTRACT_DIR))
        elif tarfile.is_tarfile(str(ARTIFACT_PATH)):
            with tarfile.open(str(ARTIFACT_PATH)) as tf:
                tf.extractall(str(EXTRACT_DIR))
        elif zipfile.is_zipfile(str(ARTIFACT_PATH)):
            with zipfile.ZipFile(str(ARTIFACT_PATH)) as zf:
                zf.extractall(str(EXTRACT_DIR))
    except Exception:
        pass  # extraction failure is non-fatal


# ---------------------------------------------------------------------------
# Dynamic analysis helpers
# ---------------------------------------------------------------------------

def build_install_command(
    job_type: str, package_name: str, has_artifact: bool,
) -> list[str]:
    if job_type == "pypi":
        if has_artifact:
            target = str(ARTIFACT_PATH)
            suffix = ARTIFACT_PATH.suffix.lower()
            if suffix == ".whl":
                return ["pip3", "install", "--no-cache-dir", "--no-index", target]
            else:
                return ["pip3", "install", "--no-cache-dir", "--no-deps", target]
        else:
            return ["pip3", "install", "--no-cache-dir", "--no-deps", package_name]
    else:  # npm
        target = str(ARTIFACT_PATH) if has_artifact else package_name
        return ["npm", "install", "--no-fund", "--no-audit", target]


def _run_command_with_timeout(
    cmd: list[str], log_stream: LogStream, timeout: int,
) -> int:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout)
        if stdout:
            for line in stdout.splitlines():
                if line:
                    log_stream.write(line)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        log_stream.write(f"[agent] command timed out after {timeout}s: {' '.join(cmd)}")
    return proc.returncode or 0


def run_with_strace(
    cmd: list[str],
    log_path: Path,
    log_stream: LogStream,
    tel: Telemetry,
    timeout: int = 60,
) -> int:
    """Run cmd under verbose strace and stream the raw trace to the host."""
    strace_cmd = [
        "strace",
        "-f",              # follow forks
        "-v",              # verbose output
        "-s", "2048",      # max string size
        "-y",              # resolve file descriptors
        "-yy",             # resolve socket addresses
        "-e", "trace=network,process,file,desc",
        "-o", str(log_path),
        "--timestamps=unix,us",
    ] + cmd

    try:
        exit_code = _run_command_with_timeout(strace_cmd, log_stream, timeout)
        # Stream the strace output file to the host for IOC analysis
        stream_file_lines(log_path, log_stream)
        return exit_code
    except FileNotFoundError:
        tel.emit("warning", message="strace not found; running without tracing", cmd=cmd)
        return _run_command_with_timeout(cmd, log_stream, timeout)


def find_entry_points(job_type: str, package_name: str) -> list[list[str]]:
    """Return a list of post-install probe commands."""
    cmds: list[list[str]] = []
    if job_type == "pypi":
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", package_name.split("==")[0])
        cmds.append(["python3", "-c", f"import {safe_name}; print('import OK')"])
        cmds.append(["python3", "-m", safe_name])
    elif job_type == "npm":
        # Check for index.js or main entry
        main_js = EXTRACT_DIR / "package" / "index.js"
        if main_js.exists():
            cmds.append(["node", str(main_js)])
        # Also try running via npx if a bin is defined
        pkg_json = EXTRACT_DIR / "package" / "package.json"
        if pkg_json.exists():
            try:
                meta = json.loads(pkg_json.read_text())
                if "bin" in meta:
                    bins = meta["bin"]
                    if isinstance(bins, str):
                        cmds.append(["node", str(EXTRACT_DIR / "package" / bins)])
                    elif isinstance(bins, dict):
                        for _, script in bins.items():
                            cmds.append(["node", str(EXTRACT_DIR / "package" / script)])
            except Exception:
                pass
    return cmds


def run_execution_probes(
    job_type: str,
    package_name: str,
    log_stream: LogStream,
    tel: Telemetry,
) -> list[list[str]]:
    """Run entry points under strace and stream results."""
    executed: list[list[str]] = []
    for cmd in find_entry_points(job_type, package_name):
        tel.emit("exec_started", cmd=cmd)
        safe = re.sub(r"[^a-zA-Z0-9_]+", "_", package_name)
        probe_log = WORK_DIR / f"strace_exec_{safe}_{len(executed)}.log"
        exit_code = run_with_strace(cmd, probe_log, log_stream, tel, timeout=30)
        tel.emit("exec_done", cmd=cmd, exit_code=exit_code)
        executed.append(cmd)
    return executed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # --- Receive job ---
    print("[agent] Waiting for job on port 7000...", flush=True)
    header, artifact_bytes = read_job()
    print(f"[agent] Job received: {header.get('job_id')}", flush=True)

    job_id = header.get("job_id", "unknown")
    job_type = header.get("job_type", "pypi")
    package_name = header.get("package", "")
    expected_sha256 = header.get("artifact_sha256", "")
    artifact_size = int(header.get("artifact_size", 0))

    # Open outbound channels
    tel_ch = Channel(HOST_CID, PORT_TELEMETRY, "telemetry")
    log_ch = Channel(HOST_CID, PORT_LOGS, "logs")

    print("[agent] Connecting to telemetry/logs channels...", flush=True)
    for attempt in range(10):
        try:
            tel_ch._connect()
            log_ch._connect()
            break
        except Exception as e:
            print(f"[agent] Outbound connect attempt {attempt}: {e}", flush=True)
            time.sleep(1)

    tel = Telemetry(job_id, tel_ch)
    log = LogStream(log_ch)

    tel.emit("agent_started", job_type=job_type, package=package_name,
             artifact_size=artifact_size)

    # --- Phase 1: Artifact handling ---
    has_artifact = artifact_size > 0 and len(artifact_bytes) == artifact_size

    if has_artifact:
        hash_ok = save_and_verify_artifact(artifact_bytes, expected_sha256, job_type)
        if not hash_ok:
            tel.emit("artifact_hash_mismatch",
                     expected=expected_sha256,
                     actual=hashlib.sha256(artifact_bytes).hexdigest())
        else:
            tel.emit("artifact_received",
                     size=len(artifact_bytes),
                     sha256=hashlib.sha256(artifact_bytes).hexdigest())
        extract_artifact(job_type)
    else:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        tel.emit("artifact_received", size=0, note="no artifact — install from index")

    # --- Phase 2: Install under strace ---
    install_cmd = build_install_command(job_type, package_name, has_artifact)
    tel.emit("install_started", cmd=install_cmd)
    log.write(f"[agent] running: {' '.join(install_cmd)}")

    install_strace = WORK_DIR / "strace_install.log"
    exit_code = run_with_strace(install_cmd, install_strace, log, tel, timeout=60)
    tel.emit("install_done", exit_code=exit_code)

    # --- Phase 3: Post-install execution probes ---
    executed = run_execution_probes(job_type, package_name, log, tel)

    # --- Signal completion (host does verdict, not us) ---
    tel.emit("agent_finished",
             install_exit_code=exit_code,
             probes=len(executed))
    log.write(f"[agent] finished install_exit_code={exit_code} probes={len(executed)}")

    # Flush and close channels
    tel_ch.close()
    log_ch.close()


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)

    print("[agent] Script started", flush=True)
    try:
        main()
    except Exception as e:
        print(f"[agent] FATAL ERROR: {e}", flush=True)
        import traceback
        traceback.print_exc()
