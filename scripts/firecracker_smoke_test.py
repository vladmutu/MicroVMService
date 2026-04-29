#!/usr/bin/env python3
"""
Standalone Firecracker vsock smoke test with real package download.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class PhaseResult:
    ok: bool
    detail: str


class Listener:
    """Unix socket listener for vsock forwarding."""
    
    def __init__(self, path: Path, expect_json: bool) -> None:
        self.path = path
        self.expect_json = expect_json
        self.messages: list[str] = []
        self.json_payloads: list[dict] = []
        self.error: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._got_data = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=2.0):
            raise RuntimeError(f"listener did not start for {self.path}")

    def wait_for_data(self, timeout: float) -> bool:
        return self._got_data.wait(timeout=timeout)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        try:
            self.path.unlink(missing_ok=True)
        except Exception:
            pass

    def _run(self) -> None:
        try:
            try:
                self.path.unlink(missing_ok=True)
            except Exception:
                pass
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.settimeout(0.5)
            server.bind(str(self.path))
            server.listen(1)
            self._ready.set()
            
            while not self._stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                    
                conn.settimeout(0.5)
                with conn:
                    # ===== HANDSHAKE =====
                    buf = b""
                    while not self._stop.is_set():
                        try:
                            chunk = conn.recv(1024)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        buf += chunk
                        if b"\n" in buf:
                            break
                    
                    if b"\n" in buf:
                        handshake_line, buf = buf.split(b"\n", 1)
                        handshake = handshake_line.decode("utf-8", errors="replace").strip()
                        
                        # Respond to handshake
                        if handshake.startswith("CONNECT"):
                            port = handshake.split()[-1] if len(handshake.split()) > 1 else "unknown"
                            response = f"OK {port}\n".encode()
                            conn.sendall(response)
                    
                    # ===== STREAM DATA =====
                    while not self._stop.is_set():
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        buf += chunk
                        
                        # Process complete lines
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            text = line.decode("utf-8", errors="replace").strip()
                            if not text:
                                continue
                            
                            self.messages.append(text)
                            if self.expect_json:
                                try:
                                    parsed = json.loads(text)
                                    if isinstance(parsed, dict):
                                        self.json_payloads.append(parsed)
                                except json.JSONDecodeError:
                                    pass
                            self._got_data.set()
            
            server.close()
        except Exception as exc:
            self.error = str(exc)
            self._ready.set()


def wait_for_path(path: Path, timeout: float) -> bool:
    """Wait for a path to exist."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return False


def firecracker_put(client: httpx.Client, endpoint: str, payload: dict) -> None:
    """Send PUT request to Firecracker API."""
    response = client.put(f"http://localhost{endpoint}", json=payload)
    response.raise_for_status()


def download_package(job_type: str, package: str, dest: Path) -> tuple[bytes, str]:
    """
    Download a package and return (artifact_bytes, sha256).
    
    For PyPI: downloads the .whl or .tar.gz
    For npm: downloads the .tgz
    """
    if job_type == "pypi":
        # Parse package name and version
        if "==" in package:
            name, version = package.split("==", 1)
        else:
            # Get latest version from PyPI
            url = f"https://pypi.org/pypi/{package}/json"
            resp = httpx.get(url, follow_redirects=True, timeout=30.0)
            resp.raise_for_status()
            metadata = resp.json()
            version = metadata["info"]["version"]
            name = package
        
        # Get package metadata
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        resp = httpx.get(url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
        metadata = resp.json()
        
        # Prefer wheel, fallback to sdist
        urls_list = metadata.get("urls", [])
        download_url = None
        
        for entry in urls_list:
            if entry["packagetype"] == "bdist_wheel":
                download_url = entry["url"]
                break
        
        if not download_url:
            for entry in urls_list:
                if entry["packagetype"] == "sdist":
                    download_url = entry["url"]
                    break
        
        if not download_url:
            raise RuntimeError(f"No downloadable artifact found for {name}=={version}")
        
        # Download the file
        print(f"[smoke] downloading {download_url}")
        resp = httpx.get(download_url, follow_redirects=True, timeout=60.0)
        resp.raise_for_status()
        artifact_bytes = resp.content
        
    elif job_type == "npm":
        # Get package metadata
        url = f"https://registry.npmjs.org/{package}"
        resp = httpx.get(url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
        metadata = resp.json()
        
        # Get latest version
        version = metadata.get("dist-tags", {}).get("latest")
        if not version:
            raise RuntimeError(f"No version found for {package}")
        
        # Get tarball URL
        tarball_url = metadata["versions"][version]["dist"]["tarball"]
        
        # Download the tarball
        print(f"[smoke] downloading {tarball_url}")
        resp = httpx.get(tarball_url, follow_redirects=True, timeout=60.0)
        resp.raise_for_status()
        artifact_bytes = resp.content
    else:
        raise ValueError(f"Unknown job_type: {job_type}")
    
    # Compute SHA256
    sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    
    # Save to disk
    dest.write_bytes(artifact_bytes)
    
    return artifact_bytes, sha256


def connect_and_send(
    vsock_path: Path,
    job_id: str,
    job_type: str,
    package: str,
    artifact_bytes: bytes,
    artifact_sha256: str,
    timeout: float,
) -> str:
    """
    Connect to vsock port 7000 and send job.
    
    Protocol:
      1. CONNECT 7000\n
      2. Wait for OK 7000\n
      3. Send JSON header\n
      4. Send artifact bytes
    """
    deadline = time.monotonic() + timeout
    last_err = ""

    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect(str(vsock_path))

                # ===== HANDSHAKE =====
                sock.sendall(b"CONNECT 7000\n")
                
                # Wait for handshake response
                ack = b""
                start = time.monotonic()
                while b"\n" not in ack and (time.monotonic() - start) < 5.0:
                    chunk = sock.recv(1024)
                    if not chunk:
                        raise ConnectionError("connection closed during handshake")
                    ack += chunk
                
                if not ack.startswith(b"OK"):
                    raise RuntimeError(f"vsock ack rejected: {ack!r}")

                print(f"[smoke] handshake OK: {ack.decode('utf-8', errors='replace').strip()}")

                # The host-side proxy consumes the first CONNECT line; the guest agent
                # still expects its own CONNECT on the forwarded stream.
                sock.sendall(b"CONNECT 7000\n")

                guest_ack = b""
                start = time.monotonic()
                while b"\n" not in guest_ack and (time.monotonic() - start) < 5.0:
                    chunk = sock.recv(1024)
                    if not chunk:
                        raise ConnectionError("connection closed during guest handshake")
                    guest_ack += chunk

                if not guest_ack.startswith(b"OK"):
                    raise RuntimeError(f"guest handshake rejected: {guest_ack!r}")

                print(f"[smoke] guest handshake OK: {guest_ack.decode('utf-8', errors='replace').strip()}")

                # ===== JSON HEADER =====
                header = {
                    "job_id": job_id,
                    "job_type": job_type,
                    "package": package,
                    "artifact_size": len(artifact_bytes),
                    "artifact_sha256": artifact_sha256,
                }

                payload = json.dumps(header, separators=(",", ":")).encode("utf-8")
                sock.sendall(payload + b"\n")
                print(f"[smoke] sent header: {header}")

                # ===== ARTIFACT BYTES =====
                if artifact_bytes:
                    sock.sendall(artifact_bytes)
                    print(f"[smoke] sent {len(artifact_bytes)} bytes of artifact")

                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

                return ack.decode("utf-8", errors="replace").strip()

        except Exception as exc:
            last_err = str(exc)
            print(f"[smoke] connection attempt failed: {exc}")
            time.sleep(0.25)

    raise RuntimeError(f"failed to deliver payload to port 7000: {last_err}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone Firecracker vsock smoke test")
    parser.add_argument("--firecracker-bin", default=os.getenv("FIRECRACKER_BINARY", "firecracker"))
    parser.add_argument("--kernel", default=os.getenv("FIRECRACKER_DEFAULT_KERNEL"))
    parser.add_argument("--rootfs", default=os.getenv("FIRECRACKER_DEFAULT_ROOTFS"))
    parser.add_argument("--guest-cid", type=int, default=int(os.getenv("FIRECRACKER_GUEST_CID", "3")))
    parser.add_argument(
        "--boot-args",
        default=os.getenv(
            "FIRECRACKER_BOOT_ARGS",
            "console=ttyS0 reboot=k panic=1 pci=off rw rootwait init=/run_at_start/init",
        ),
    )
    parser.add_argument("--job-type", choices=["npm", "pypi"], default="pypi")
    parser.add_argument("--package", default="requests")
    parser.add_argument("--artifact-file", default="", help="Use existing file instead of downloading")
    parser.add_argument("--boot-timeout", type=float, default=30.0)
    parser.add_argument("--stream-timeout", type=float, default=60.0)
    parser.add_argument("--skip-download", action="store_true", help="Use dummy artifact")
    args = parser.parse_args()

    if not args.kernel or not args.rootfs:
        print("[FAIL] Missing --kernel or --rootfs (or FIRECRACKER_DEFAULT_KERNEL/FIRECRACKER_DEFAULT_ROOTFS)")
        return 2

    kernel = Path(args.kernel)
    rootfs = Path(args.rootfs)
    if not kernel.is_file():
        print(f"[FAIL] Kernel not found: {kernel}")
        return 2
    if not rootfs.is_file():
        print(f"[FAIL] Rootfs not found: {rootfs}")
        return 2

    # ===== ARTIFACT PREPARATION =====
    artifact_bytes = b""
    artifact_sha256 = ""
    
    if args.skip_download:
        # Dummy artifact for testing
        artifact_bytes = b"smoke-test-dummy-artifact"
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        print(f"[smoke] using dummy artifact ({len(artifact_bytes)} bytes)")
    elif args.artifact_file:
        # Use provided file
        artifact_path = Path(args.artifact_file)
        if not artifact_path.is_file():
            print(f"[FAIL] Artifact file not found: {artifact_path}")
            return 2
        artifact_bytes = artifact_path.read_bytes()
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        print(f"[smoke] using artifact file: {artifact_path} ({len(artifact_bytes)} bytes, sha256={artifact_sha256})")
    else:
        # Download from registry
        try:
            workdir = Path(tempfile.mkdtemp(prefix="fc-download-", dir="/tmp"))
            download_path = workdir / "package.artifact"
            artifact_bytes, artifact_sha256 = download_package(args.job_type, args.package, download_path)
            print(f"[smoke] downloaded {args.package}: {len(artifact_bytes)} bytes, sha256={artifact_sha256}")
        except Exception as exc:
            print(f"[FAIL] Download failed: {exc}")
            return 2

    # Generate unique job ID
    job_id = str(uuid.uuid4())
    print(f"[smoke] job_id={job_id}")

    phases: dict[str, PhaseResult] = {}
    workdir = Path(tempfile.mkdtemp(prefix="fc-smoke-", dir="/tmp"))
    api_sock = workdir / "api.socket"
    vsock_path = workdir / "v.sock"
    telemetry_sock = workdir / "v.sock_7001"
    logs_sock = workdir / "v.sock_7002"
    rootfs_copy = workdir / "rootfs.ext4"
    
    print(f"[smoke] workdir: {workdir}")
    
    # Copy rootfs (Firecracker needs writable rootfs)
    shutil.copy2(rootfs, rootfs_copy)

    telemetry_listener = Listener(telemetry_sock, expect_json=False)
    logs_listener = Listener(logs_sock, expect_json=False)

    proc: subprocess.Popen[bytes] | None = None
    try:
        # ===== START LISTENERS =====
        telemetry_listener.start()
        logs_listener.start()
        print("[smoke] listeners started")

        # ===== START FIRECRACKER =====
        proc = subprocess.Popen(
            [args.firecracker_bin, "--api-sock", str(api_sock)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print("[smoke] firecracker process started")

        if not wait_for_path(api_sock, timeout=args.boot_timeout):
            phases["vm_boot"] = PhaseResult(False, f"api socket not created at {api_sock}")
            raise RuntimeError(phases["vm_boot"].detail)

        # ===== CONFIGURE VM =====
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(api_sock)), timeout=10.0) as client:
            firecracker_put(
                client,
                "/boot-source",
                {
                    "kernel_image_path": str(kernel),
                    "boot_args": args.boot_args,
                },
            )
            firecracker_put(
                client,
                "/drives/rootfs",
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(rootfs_copy),
                    "is_root_device": True,
                    "is_read_only": False,
                },
            )
            firecracker_put(
                client,
                "/vsock",
                {
                    "guest_cid": args.guest_cid,
                    "uds_path": str(vsock_path),
                },
            )
            print("[smoke] vm configured")
            
            # Start the VM
            firecracker_put(client, "/actions", {"action_type": "InstanceStart"})
            print("[smoke] vm started")

        # Wait for vsock to be ready
        if not wait_for_path(vsock_path, timeout=args.boot_timeout):
            phases["vm_boot"] = PhaseResult(False, f"vsock UDS not created at {vsock_path}")
            raise RuntimeError(phases["vm_boot"].detail)
        
        phases["vm_boot"] = PhaseResult(True, f"booted and vsock socket ready at {vsock_path}")

        # ===== SEND JOB =====
        ack = connect_and_send(
            vsock_path,
            job_id,
            args.job_type,
            args.package,
            artifact_bytes,
            artifact_sha256,
            timeout=args.stream_timeout,
        )
        phases["ingress_7000"] = PhaseResult(True, f"guest accepted job, ack: {ack}")

        # ===== WAIT FOR TELEMETRY =====
        got_telemetry = telemetry_listener.wait_for_data(timeout=args.stream_timeout)
        if got_telemetry:
            detail = f"received {len(telemetry_listener.messages)} telemetry lines"
            if telemetry_listener.messages:
                detail += f", first: {telemetry_listener.messages[0][:80]}"
            phases["telemetry_7001"] = PhaseResult(True, detail)
        else:
            phases["telemetry_7001"] = PhaseResult(False, "no telemetry received on v.sock_7001 before timeout")

        # ===== WAIT FOR LOGS =====
        got_logs = logs_listener.wait_for_data(timeout=args.stream_timeout)
        if got_logs:
            detail = f"received {len(logs_listener.messages)} log lines"
            if logs_listener.messages:
                detail += f", first: {logs_listener.messages[0][:80]}"
            phases["logs_7002"] = PhaseResult(True, detail)
        else:
            phases["logs_7002"] = PhaseResult(False, "no logs received on v.sock_7002 before timeout")

    except Exception as exc:
        import traceback
        traceback.print_exc()
        
        if "vm_boot" not in phases:
            phases["vm_boot"] = PhaseResult(False, f"failed during startup/configuration: {exc}")
        if "ingress_7000" not in phases:
            phases["ingress_7000"] = PhaseResult(False, f"guest ingress failed: {exc}")
        if "telemetry_7001" not in phases:
            phases["telemetry_7001"] = PhaseResult(False, "not reached")
        if "logs_7002" not in phases:
            phases["logs_7002"] = PhaseResult(False, "not reached")
    finally:
        # ===== CLEANUP =====
        telemetry_listener.stop()
        logs_listener.stop()

        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            stdout_b, stderr_b = proc.communicate(timeout=1)
            if stdout_b:
                print("\n[INFO] firecracker stdout:")
                print(stdout_b.decode("utf-8", errors="replace").strip())
            if stderr_b:
                print("\n[INFO] firecracker stderr:")
                print(stderr_b.decode("utf-8", errors="replace").strip())

        # Print captured messages
        if telemetry_listener.messages:
            print(f"\n[INFO] captured {len(telemetry_listener.messages)} telemetry messages:")
            for i, msg in enumerate(telemetry_listener.messages[:10]):
                print(f"  {i}: {msg}")
            if len(telemetry_listener.messages) > 10:
                print(f"  ... and {len(telemetry_listener.messages) - 10} more")
        
        if logs_listener.messages:
            print(f"\n[INFO] captured {len(logs_listener.messages)} log messages:")
            for i, msg in enumerate(logs_listener.messages):
                print(f"  {i}: {msg}")

        shutil.rmtree(workdir, ignore_errors=True)

    # ===== SUMMARY =====
    print("\n=== Firecracker Smoke Test Summary ===")
    order = ["vm_boot", "ingress_7000", "telemetry_7001", "logs_7002"]
    all_ok = True
    for phase in order:
        result = phases.get(phase, PhaseResult(False, "missing result"))
        status = "PASS" if result.ok else "FAIL"
        print(f"[{status}] {phase}: {result.detail}")
        all_ok = all_ok and result.ok

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())