#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class PhaseResult:
    ok: bool
    detail: str


class Listener:
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
                    buf = b""
                    while not self._stop.is_set():
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        buf += chunk
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
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return False


def firecracker_put(client: httpx.Client, endpoint: str, payload: dict) -> None:
    response = client.put(f"http://localhost{endpoint}", json=payload)
    response.raise_for_status()


def connect_and_send(vsock_path: Path, job_type: str, package: str, artifact_bytes: bytes, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect(str(vsock_path))
                sock.sendall(b"CONNECT 7000\n")
                ack = sock.recv(1024)
                if not ack.startswith(b"OK"):
                    raise RuntimeError(f"vsock ack rejected: {ack!r}")
                payload = json.dumps({"job_type": job_type, "package": package}, separators=(",", ":")).encode("utf-8")
                sock.sendall(payload + b"\n")
                if artifact_bytes:
                    sock.sendall(artifact_bytes)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

                # Hold the ingress stream open briefly so guest startup writes on the same
                # channel do not fail with broken pipe before telemetry/log channels are used.
                grace_deadline = time.monotonic() + 2.0
                while time.monotonic() < grace_deadline:
                    remaining = max(0.0, grace_deadline - time.monotonic())
                    sock.settimeout(min(0.25, remaining))
                    try:
                        _ = sock.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    else:
                        continue
                return ack.decode("utf-8", errors="replace").strip()
        except Exception as exc:
            last_err = str(exc)
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
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw rootwait init=/sbin/init",
        ),
    )
    parser.add_argument("--job-type", choices=["npm", "pypi"], default="pypi")
    parser.add_argument("--package", default="requests")
    parser.add_argument("--artifact-file", default="")
    parser.add_argument("--boot-timeout", type=float, default=15.0)
    parser.add_argument("--stream-timeout", type=float, default=20.0)
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

    artifact_bytes = b"smoke-test-artifact"
    if args.artifact_file:
        artifact_path = Path(args.artifact_file)
        if not artifact_path.is_file():
            print(f"[FAIL] Artifact file not found: {artifact_path}")
            return 2
        artifact_bytes = artifact_path.read_bytes()

    phases: dict[str, PhaseResult] = {}
    workdir = Path(tempfile.mkdtemp(prefix="fc-smoke-", dir="/tmp"))
    api_sock = workdir / "api.socket"
    vsock_path = workdir / "v.sock"
    telemetry_sock = workdir / "v.sock_7001"
    logs_sock = workdir / "v.sock_7002"
    rootfs_copy = workdir / "rootfs.ext4"
    rootfs_copy.write_bytes(rootfs.read_bytes())

    telemetry_listener = Listener(telemetry_sock, expect_json=True)
    logs_listener = Listener(logs_sock, expect_json=False)

    proc: subprocess.Popen[bytes] | None = None
    try:
        telemetry_listener.start()
        logs_listener.start()

        proc = subprocess.Popen(
            [args.firecracker_bin, "--api-sock", str(api_sock)],
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
            firecracker_put(client, "/actions", {"action_type": "InstanceStart"})

        if not wait_for_path(vsock_path, timeout=args.boot_timeout):
            phases["vm_boot"] = PhaseResult(False, f"vsock UDS not created at {vsock_path}")
            raise RuntimeError(phases["vm_boot"].detail)
        phases["vm_boot"] = PhaseResult(True, f"booted and vsock socket ready at {vsock_path}")

        ack = connect_and_send(vsock_path, args.job_type, args.package, artifact_bytes, timeout=args.stream_timeout)
        phases["ingress_7000"] = PhaseResult(True, f"guest accepted CONNECT 7000 with ack: {ack}")

        got_telemetry = telemetry_listener.wait_for_data(timeout=args.stream_timeout)
        if got_telemetry:
            detail = telemetry_listener.messages[0]
            phases["telemetry_7001"] = PhaseResult(True, f"received telemetry line: {detail}")
        else:
            phases["telemetry_7001"] = PhaseResult(False, "no telemetry received on v.sock_7001 before timeout")

        got_logs = logs_listener.wait_for_data(timeout=args.stream_timeout)
        if got_logs:
            detail = logs_listener.messages[0]
            phases["logs_7002"] = PhaseResult(True, f"received log line: {detail}")
        else:
            phases["logs_7002"] = PhaseResult(False, "no logs received on v.sock_7002 before timeout")

    except Exception as exc:
        if "vm_boot" not in phases:
            phases["vm_boot"] = PhaseResult(False, f"failed during startup/configuration: {exc}")
        if "ingress_7000" not in phases:
            phases["ingress_7000"] = PhaseResult(False, f"guest ingress failed: {exc}")
        if "telemetry_7001" not in phases:
            phases["telemetry_7001"] = PhaseResult(False, "not reached")
        if "logs_7002" not in phases:
            phases["logs_7002"] = PhaseResult(False, "not reached")
    finally:
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
                print("[INFO] firecracker stdout:")
                print(stdout_b.decode("utf-8", errors="replace").strip())
            if stderr_b:
                print("[INFO] firecracker stderr:")
                print(stderr_b.decode("utf-8", errors="replace").strip())

        shutil.rmtree(workdir, ignore_errors=True)

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
