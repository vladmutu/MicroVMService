#!/usr/bin/env python3
"""
Firecracker network test — FIXED VERSION (WSL-safe, multi-VM safe)

Key changes:
- ❌ Removed bridge (fc-br0)
- ✅ Direct TAP + NAT
- ✅ Per-VM subnet (no collisions)
- ✅ Correct boot args injection
"""

import argparse
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import httpx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def wait_path(p: Path, t: float) -> bool:
    d = time.monotonic() + t
    while time.monotonic() < d:
        if p.exists():
            return True
        time.sleep(0.05)
    return False


def fc_put(client: httpx.Client, ep: str, body: dict) -> None:
    client.put(f"http://localhost{ep}", json=body).raise_for_status()


def get_default_iface() -> str:
    out = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("default") and "dev" in line:
            return line.split()[line.split().index("dev") + 1]
    return "eth0"


def _iptables() -> str:
    return "iptables-legacy" if shutil.which("iptables-legacy") else "iptables"


# ---------------------------------------------------------------------------
# TAP + NAT (NO BRIDGE)
# ---------------------------------------------------------------------------

def setup_tap(tap: str, iface: str, vm_id: int):
    ipt = _iptables()

    base = f"172.16.{vm_id}"
    host_ip = f"{base}.1/24"
    guest_ip = f"{base}.2"
    subnet = f"{base}.0/24"

    print(f"[net] iface={iface}, tap={tap}, subnet={subnet}")

    # Cleanup old
    subprocess.run(["sudo", "ip", "link", "del", tap], stderr=subprocess.DEVNULL)
    user = os.environ.get("SUDO_USER", os.getenv("USER", "root")) 
    cmds = [
        # 1. Standard TAP creation
        ["sudo", "ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user],
        ["sudo", "ip", "addr", "add", host_ip, "dev", tap],
        ["sudo", "ip", "link", "set", tap, "mtu", "1420"],
        ["sudo", "ip", "link", "set", tap, "up"],

        # 2. AGGRESSIVE ETHTOOL: Turn off EVERYTHING (sg, tso, gso, gro, tx, rx)
        ["sudo", "ethtool", "-K", tap, "sg", "off", "tso", "off", "gso", "off", "gro", "off", "tx", "off", "rx", "off"],
        # 2b. Disable TX offloading on WSL2's primary interface (CRITICAL for nested NAT)
        ["sudo", "ethtool", "-K", iface, "tx", "off"],

        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],

        # 3. Standard NAT
        ["sudo", ipt, "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"],
        ["sudo", ipt, "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"],

        # 4. HARDCODED MSS: Drop --clamp-mss-to-pmtu and force a tiny 1200 byte MSS 
        ["sudo", ipt, "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200"],
        ["sudo", ipt, "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1200"],

        # 5. WSL2 CHECKSUM FIX: Force Linux to calculate TCP checksums before leaving WSL2
        ["sudo", ipt, "-t", "mangle", "-C", "POSTROUTING", "-p", "tcp", "-j", "CHECKSUM", "--checksum-fill"],
        ["sudo", ipt, "-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "-j", "CHECKSUM", "--checksum-fill"],

        # 6. Standard Forward Rules (Unchanged)
        ["sudo", ipt, "-C", "FORWARD", "-i", tap, "-o", iface, "-j", "ACCEPT"],
        ["sudo", ipt, "-A", "FORWARD", "-i", tap, "-o", iface, "-j", "ACCEPT"],
        ["sudo", ipt, "-C", "FORWARD", "-o", tap, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["sudo", ipt, "-A", "FORWARD", "-o", tap, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]

    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[WARN] Command failed: {' '.join(cmd)}\nError: {result.stderr.strip()}")

    return guest_ip, f"{base}.1"


def teardown_tap(tap: str):
    subprocess.run(["sudo", "ip", "link", "del", tap], stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--firecracker-bin", default="firecracker")
    ap.add_argument("--tap", default="tap0")
    ap.add_argument("--vm-id", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--boot-args", default="console=ttyS0 reboot=k panic=1 pci=off rw rootwait random.trust_cpu=on init=/run_at_start/init")
    args = ap.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="fc-test-"))
    api_sock = workdir / "api.sock"
    rootfs_copy = workdir / "rootfs.ext4"
    shutil.copy2(args.rootfs, rootfs_copy)

    iface = get_default_iface()
    proc = None

    try:
        guest_ip, gw = setup_tap(args.tap, iface, args.vm_id)

        boot_args = (
            args.boot_args +
            f" fc_ip={guest_ip} fc_gw={gw} fc_mask=24"
        )

        proc = subprocess.Popen(
            [args.firecracker_bin, "--api-sock", str(api_sock)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def stream(pipe, tag):
            for line in pipe:
                print(f"{tag} {line.decode().rstrip()}", flush=True)

        threading.Thread(target=stream, args=(proc.stdout, "[guest]"), daemon=True).start()
        threading.Thread(target=stream, args=(proc.stderr, "[fc]"), daemon=True).start()

        if not wait_path(api_sock, 10):
            print("API socket not ready")
            return 1

        with httpx.Client(transport=httpx.HTTPTransport(uds=str(api_sock))) as c:
            fc_put(c, "/boot-source", {
                "kernel_image_path": args.kernel,
                "boot_args": boot_args,
            })

            fc_put(c, "/drives/rootfs", {
                "drive_id": "rootfs",
                "path_on_host": str(rootfs_copy),
                "is_root_device": True,
                "is_read_only": False,
            })

            fc_put(c, "/network-interfaces/eth0", {
                "iface_id": "eth0",
                "guest_mac": f"AA:FC:00:00:00:{args.vm_id+1:02x}",
                "host_dev_name": args.tap,
            })

            fc_put(c, "/actions", {"action_type": "InstanceStart"})

        print(f"\n[net-test] running for {args.timeout}s...\n")

        try:
            proc.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            print("[net-test] timeout (expected if VM keeps running)")

        print("\n[net-test] interface stats:")
        subprocess.run(["ip", "-s", "link", "show", args.tap])

    finally:
        if proc and proc.poll() is None:
            proc.kill()
        teardown_tap(args.tap)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()