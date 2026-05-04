#!/usr/bin/env python3
"""
Standalone Firecracker vsock smoke test with real package download, metadata extraction,
asynchronous waiting, and full log dumping.
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
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx

@dataclass
class PhaseResult:
    ok: bool
    detail: str

_log_file = None  # set in main() once --log-file is parsed


class _Tee:
    """Write to both a stream and _log_file simultaneously."""
    def __init__(self, stream):
        self._stream = stream

    def write(self, data: str) -> int:
        n = self._stream.write(data)
        if _log_file is not None:
            try:
                _log_file.write(data)
                _log_file.flush()
            except Exception:
                pass
        return n

    def flush(self):
        self._stream.flush()
        if _log_file is not None:
            try:
                _log_file.flush()
            except Exception:
                pass

    def fileno(self):
        return self._stream.fileno()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _write_console(text: str) -> None:
    """Write to the real console without depending on buffered print()."""
    if not text:
        return

    data = text.encode("utf-8", errors="replace")
    if not data.endswith(b"\n"):
        data += b"\n"

    if _log_file is not None:
        try:
            _log_file.write(data.decode("utf-8", errors="replace"))
            _log_file.flush()
        except Exception:
            pass

    try:
        fd = sys.__stdout__.fileno()
    except Exception:
        return

    offset = 0
    while offset < len(data):
        try:
            written = os.write(fd, data[offset:])
            if written <= 0:
                time.sleep(0.05)
                continue
            offset += written
        except BlockingIOError:
            time.sleep(0.05)
        except InterruptedError:
            continue
        except Exception:
            break

# ============================================================================
# NETWORK MANAGEMENT (TAP + iptables NAT)
# ============================================================================

def setup_tap_network(tap_name: str, vm_id: int = 0) -> tuple[str, str, str]:
    """Create a TAP device with iptables NAT for outbound internet access."""
    out_iface = _get_default_iface()
    ipt = _iptables()
    base = f"172.16.{vm_id}"
    host_ip = f"{base}.1/24"
    guest_ip = f"{base}.2"
    subnet = f"{base}.0/24"

    print(f"[smoke] ipt={ipt} iface={out_iface} subnet={subnet}")

    subprocess.run(["sudo", "ip", "link", "del", tap_name], stderr=subprocess.DEVNULL)

    user = os.environ.get("SUDO_USER", os.getenv("USER", "root"))
    cmds = [
        ["sudo", "ip", "tuntap", "add", "dev", tap_name, "mode", "tap", "user", user],
        ["sudo", "ip", "addr", "add", host_ip, "dev", tap_name],
        ["sudo", "ip", "link", "set", tap_name, "mtu", "1420"],
        ["sudo", "ip", "link", "set", tap_name, "up"],
        ["sudo", "ethtool", "-K", tap_name, "sg", "off", "tso", "off", "gso", "off", "gro", "off", "tx", "off", "rx", "off"],
        ["sudo", "ethtool", "-K", out_iface, "tx", "off"],
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
        # NAT
        ["sudo", ipt, "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", out_iface, "-j", "MASQUERADE"],
        ["sudo", ipt, "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", out_iface, "-j", "MASQUERADE"],
        # TCP: MSS clamp + checksum fill
        ["sudo", ipt, "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200"],
        ["sudo", ipt, "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200"],
        ["sudo", ipt, "-t", "mangle", "-C", "POSTROUTING", "-p", "tcp", "-j", "CHECKSUM", "--checksum-fill"],
        ["sudo", ipt, "-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "-j", "CHECKSUM", "--checksum-fill"],
        # UDP: checksum fill — fixes DNS in WSL2 nested NAT
        ["sudo", ipt, "-t", "mangle", "-C", "POSTROUTING", "-p", "udp", "-j", "CHECKSUM", "--checksum-fill"],
        ["sudo", ipt, "-t", "mangle", "-A", "POSTROUTING", "-p", "udp", "-j", "CHECKSUM", "--checksum-fill"],
        # Forward rules
        ["sudo", ipt, "-C", "FORWARD", "-i", tap_name, "-o", out_iface, "-j", "ACCEPT"],
        ["sudo", ipt, "-A", "FORWARD", "-i", tap_name, "-o", out_iface, "-j", "ACCEPT"],
        ["sudo", ipt, "-C", "FORWARD", "-o", tap_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["sudo", ipt, "-A", "FORWARD", "-o", tap_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[WARN] {' '.join(cmd)}: {r.stderr.strip()}")

    return guest_ip, f"{base}.1", out_iface


def teardown_tap_network(tap_name: str) -> None:
    subprocess.run(["sudo", "ip", "link", "del", tap_name], stderr=subprocess.DEVNULL)


def _iptables() -> str:
    return "iptables-legacy" if shutil.which("iptables-legacy") else "iptables"


def _get_default_iface() -> str:
    out = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("default") and "dev" in line:
            return line.split()[line.split().index("dev") + 1]
    return "eth0"



# ============================================================================
# CORE COMPONENTS
# ============================================================================

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

def download_package(job_type: str, package: str, dest: Path) -> tuple[bytes, str, str]:
    """
    Download a package and return (artifact_bytes, sha256, filename).
    """
    filename = "artifact.pkg"

    if job_type == "pypi":
        if "==" in package:
            name, version = package.split("==", 1)
        else:
            url = f"https://pypi.org/pypi/{package}/json"
            resp = httpx.get(url, follow_redirects=True, timeout=30.0)
            resp.raise_for_status()
            metadata = resp.json()
            version = metadata["info"]["version"]
            name = package
        
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        resp = httpx.get(url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
        metadata = resp.json()
        
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
        
        filename = download_url.split("/")[-1]

        print(f"[smoke] downloading {download_url} as {filename}")
        resp = httpx.get(download_url, follow_redirects=True, timeout=60.0)
        resp.raise_for_status()
        artifact_bytes = resp.content
        
    elif job_type == "npm":
        url = f"https://registry.npmjs.org/{package}"
        resp = httpx.get(url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
        metadata = resp.json()
        
        version = metadata.get("dist-tags", {}).get("latest")
        if not version:
            raise RuntimeError(f"No version found for {package}")
        
        tarball_url = metadata["versions"][version]["dist"]["tarball"]
        filename = tarball_url.split("/")[-1]

        print(f"[smoke] downloading {tarball_url} as {filename}")
        resp = httpx.get(tarball_url, follow_redirects=True, timeout=60.0)
        resp.raise_for_status()
        artifact_bytes = resp.content
    else:
        raise ValueError(f"Unknown job_type: {job_type}")
    
    sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    dest.write_bytes(artifact_bytes)
    
    return artifact_bytes, sha256, filename

def connect_and_send(
    vsock_path: Path,
    job_id: str,
    job_type: str,
    package: str,
    artifact_name: str,
    artifact_bytes: bytes,
    artifact_sha256: str,
    timeout: float,
) -> str:
    """Connect to vsock port 7000 and send job with metadata."""
    deadline = time.monotonic() + timeout
    last_err = ""

    while time.monotonic() < deadline:
        try:
            # Connect to the Unix Domain Socket that Firecracker maps to the guest vsock
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect(str(vsock_path))

                # --- STEP 1: Vsock proxy handshake ---
                # First send CONNECT to the Firecracker UDS proxy and read the proxy ack.
                sock.sendall(b"CONNECT 7000\n")

                proxy_ack = b""
                start = time.monotonic()
                while b"\n" not in proxy_ack and (time.monotonic() - start) < 5.0:
                    chunk = sock.recv(1024)
                    if not chunk:
                        raise ConnectionError("connection closed during proxy handshake")
                    proxy_ack += chunk

                if not proxy_ack.startswith(b"OK"):
                    raise RuntimeError(f"vsock proxy rejected CONNECT 7000: {proxy_ack!r}")

                # --- STEP 2: Guest handshake ---
                # The forwarded guest stream expects its own CONNECT line; send it
                # and read the guest ack before sending the JSON header.
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

                decoded_ack = guest_ack.decode('utf-8', errors='replace').strip()
                print(f"[smoke] Handshake successful: {decoded_ack}")

                # --- STEP 3: Send JSON Header ---
                header = {
                    "job_id": job_id,
                    "job_type": job_type,
                    "package": package,
                    "artifact_name": artifact_name,
                    "artifact_size": len(artifact_bytes),
                    "artifact_sha256": artifact_sha256,
                }

                payload = json.dumps(header, separators=(",", ":")).encode("utf-8")
                sock.sendall(payload + b"\n")
                print(f"[smoke] sent header: {header}")

                # --- STEP 3: Send Artifact Bytes ---
                if artifact_bytes:
                    sock.sendall(artifact_bytes)
                    print(f"[smoke] sent {len(artifact_bytes)} bytes of artifact")

                # Signal to the guest that we are done writing
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

                return decoded_ack

        except Exception as exc:
            last_err = str(exc)
            print(f"[smoke] connection attempt failed: {exc}")
            # Small sleep to prevent tight-looping while the VM is still booting
            time.sleep(0.5)

    raise RuntimeError(f"failed to deliver payload to port 7000 within {timeout}s: {last_err}")

def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone Firecracker vsock smoke test")
    parser.add_argument("--firecracker-bin", default=os.getenv("FIRECRACKER_BINARY", "firecracker"))
    parser.add_argument("--kernel", default=os.getenv("FIRECRACKER_DEFAULT_KERNEL"))
    parser.add_argument("--rootfs", default=os.getenv("FIRECRACKER_DEFAULT_ROOTFS"))
    parser.add_argument("--guest-cid", type=int, default=int(os.getenv("FIRECRACKER_GUEST_CID", "3")))
    parser.add_argument("--tap-name", default="fc-tap-smoke")
    parser.add_argument(
        "--boot-args",
        default=os.getenv(
            "FIRECRACKER_BOOT_ARGS",
            "console=ttyS0 reboot=k panic=1 pci=off rw rootwait random.trust_cpu=on init=/run_at_start/init",
        ),
    )
    parser.add_argument("--job-type", choices=["npm", "pypi"], default="pypi")
    parser.add_argument("--package", default="requests")
    parser.add_argument("--artifact-file", default="", help="Use existing file instead of downloading")
    parser.add_argument("--boot-timeout", type=float, default=30.0)
    parser.add_argument("--stream-timeout", type=float, default=300.0)  # 90s install + 60s*2 probes + 45s monitor + slack
    parser.add_argument("--skip-download", action="store_true", help="Use dummy artifact")
    parser.add_argument("--log-file", default="full_test_output.log")
    args = parser.parse_args()

    global _log_file
    _log_file = open(args.log_file, "w", buffering=1, encoding="utf-8")
    sys.stdout = _Tee(sys.__stdout__)
    sys.stderr = _Tee(sys.__stderr__)

    if not args.kernel or not args.rootfs:
        print("[FAIL] Missing --kernel or --rootfs")
        return 2

    kernel = Path(args.kernel)
    rootfs = Path(args.rootfs)
    if not kernel.is_file():
        print(f"[FAIL] Kernel not found: {kernel}")
        return 2
    if not rootfs.is_file():
        print(f"[FAIL] Rootfs not found: {rootfs}")
        return 2

    artifact_bytes = b""
    artifact_sha256 = ""
    artifact_name = "artifact.pkg"
    
    if args.skip_download:
        artifact_bytes = b"smoke-test-dummy-artifact"
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        artifact_name = "dummy-package-1.0.0-py3-none-any.whl" if args.job_type == "pypi" else "dummy-package.tgz"
        print(f"[smoke] using dummy artifact ({len(artifact_bytes)} bytes)")
    elif args.artifact_file:
        artifact_path = Path(args.artifact_file)
        if not artifact_path.is_file():
            print(f"[FAIL] Artifact file not found: {artifact_path}")
            return 2
        artifact_bytes = artifact_path.read_bytes()
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        artifact_name = artifact_path.name
        print(f"[smoke] using artifact file: {artifact_path} ({len(artifact_bytes)} bytes)")
    else:
        try:
            workdir = Path(tempfile.mkdtemp(prefix="fc-download-", dir="/tmp"))
            download_path = workdir / "package.artifact"
            artifact_bytes, artifact_sha256, artifact_name = download_package(args.job_type, args.package, download_path)
            print(f"[smoke] downloaded {args.package}: {len(artifact_bytes)} bytes, name={artifact_name}")
        except Exception as exc:
            print(f"[FAIL] Download failed: {exc}")
            return 2

    job_id = str(uuid.uuid4())
    print(f"[smoke] job_id={job_id}")

    phases: dict[str, PhaseResult] = {}
    workdir = Path(tempfile.mkdtemp(prefix="fc-smoke-", dir="/tmp"))
    api_sock = workdir / "api.socket"
    vsock_path = workdir / "v.sock"
    telemetry_sock = workdir / "v.sock_7001"
    logs_sock = workdir / "v.sock_7002"
    rootfs_copy = workdir / "rootfs.ext4"
    
    shutil.copy2(rootfs, rootfs_copy)

    telemetry_listener = Listener(telemetry_sock, expect_json=False)
    logs_listener = Listener(logs_sock, expect_json=False)

    proc: subprocess.Popen[bytes] | None = None

    try:
        # ===== NETWORK SETUP (TAP + iptables NAT) =====
        guest_ip, gateway_ip, out_iface = setup_tap_network(args.tap_name)
        phases["host_network"] = PhaseResult(True, f"TAP {args.tap_name} NAT via {out_iface}")
        boot_args = f"{args.boot_args} fc_ip={guest_ip} fc_gw={gateway_ip} fc_mask=24"

        telemetry_listener.start()
        logs_listener.start()

        proc = subprocess.Popen(
            ["sudo", args.firecracker_bin, "--api-sock", str(api_sock)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if not wait_for_path(api_sock, timeout=args.boot_timeout):
            phases["vm_boot"] = PhaseResult(False, f"api socket not created at {api_sock}")
            raise RuntimeError(phases["vm_boot"].detail)

        with httpx.Client(transport=httpx.HTTPTransport(uds=str(api_sock)), timeout=10.0) as client:
            firecracker_put(
                client,
                "/boot-source",
                {"kernel_image_path": str(kernel), "boot_args": boot_args},
            )
            firecracker_put(
                client,
                "/drives/rootfs",
                {"drive_id": "rootfs", "path_on_host": str(rootfs_copy), "is_root_device": True, "is_read_only": False},
            )
            firecracker_put(
                client,
                "/vsock",
                {"guest_cid": args.guest_cid, "uds_path": str(vsock_path)},
            )
            firecracker_put(
                client,
                "/network-interfaces/eth0",
                {
                    "iface_id": "eth0",
                    "guest_mac": "AA:FC:00:00:00:01",
                    "host_dev_name": args.tap_name,
                },
            )
            
            firecracker_put(client, "/actions", {"action_type": "InstanceStart"})

        if not wait_for_path(vsock_path, timeout=args.boot_timeout):
            phases["vm_boot"] = PhaseResult(False, f"vsock UDS not created at {vsock_path}")
            raise RuntimeError(phases["vm_boot"].detail)
        
        phases["vm_boot"] = PhaseResult(True, f"booted and vsock socket ready at {vsock_path}")

        # ===== SEND JOB WITH METADATA =====
        ack = connect_and_send(
            vsock_path,
            job_id,
            args.job_type,
            args.package,
            artifact_name,
            artifact_bytes,
            artifact_sha256,
            timeout=args.stream_timeout,
        )
        phases["ingress_7000"] = PhaseResult(True, f"guest accepted job, ack: {ack}")

        # ===== WAIT FOR AGENT COMPLETION =====
        print(f"[smoke] waiting up to {args.stream_timeout}s for agent to finish...")
        start_wait = time.monotonic()
        finished = False
        
        while time.monotonic() - start_wait < args.stream_timeout:
            # Check if any received telemetry line contains 'agent_finished'
            if any("agent_finished" in msg for msg in telemetry_listener.messages):
                finished = True
                break
            time.sleep(0.5)

        if finished:
            phases["execution"] = PhaseResult(True, "agent reported completion")
        else:
            phases["execution"] = PhaseResult(False, "timed out waiting for agent_finished")

        # ===== RECORD CHANNEL SUMMARIES =====
        t_count = len(telemetry_listener.messages)
        phases["telemetry_7001"] = PhaseResult(
            t_count > 0, 
            f"received {t_count} telemetry lines"
        )

        l_count = len(logs_listener.messages)
        phases["logs_7002"] = PhaseResult(
            l_count > 0, 
            f"received {l_count} log lines"
        )

    except Exception as exc:
        import traceback
        traceback.print_exc()
        if "vm_boot" not in phases: phases["vm_boot"] = PhaseResult(False, f"failed: {exc}")
    finally:
        telemetry_listener.stop()
        logs_listener.stop()

        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except: proc.kill()
            stdout_b, stderr_b = proc.communicate(timeout=1)
            if stdout_b: _write_console(stdout_b.decode("utf-8", errors="replace").strip())
            if stderr_b: _write_console(stderr_b.decode("utf-8", errors="replace").strip())

        teardown_tap_network(args.tap_name)

        # =========================================================
        # ===== NEW SECTION: PRINT ALL CAPTURED LOGS FULLY ========
        # =========================================================
        _write_console("\n\n" + "="*50)
        _write_console("=== FULL TELEMETRY DUMP (PORT 7001) ===")
        _write_console("="*50)
        if not telemetry_listener.messages:
            _write_console("  (No telemetry captured)")
        else:
            for msg in telemetry_listener.messages:
                _write_console(msg)

        _write_console("\n" + "="*50)
        _write_console("=== PIP / NPM OUTPUT (STDOUT lines from port 7002) ===")
        _write_console("="*50)
        pip_lines = [m for m in logs_listener.messages if m.startswith("STDOUT:")]
        if not pip_lines:
            _write_console("  (No pip/npm output captured)")
        else:
            for msg in pip_lines:
                _write_console(msg)

        _write_console("\n" + "="*50)
        _write_console("=== FULL LOG & STRACE DUMP (PORT 7002) ===")
        _write_console("="*50)
        if not logs_listener.messages:
            _write_console("  (No logs captured)")
        else:
            for msg in logs_listener.messages:
                _write_console(msg)
        _write_console("="*50 + "\n\n")

        shutil.rmtree(workdir, ignore_errors=True)

    _write_console("\n=== Firecracker Smoke Test Summary ===")
    order = ["host_network", "vm_boot", "ingress_7000", "execution", "telemetry_7001", "logs_7002"]
    all_ok = True
    for phase in order:
        result = phases.get(phase, PhaseResult(False, "missing result"))
        status = "PASS" if result.ok else "FAIL"
        _write_console(f"[{status}] {phase}: {result.detail}")
        all_ok = all_ok and result.ok

    return 0 if all_ok else 1

if __name__ == "__main__":
    raise SystemExit(main())