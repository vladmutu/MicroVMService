from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VMConfig:
    firecracker_bin: Path
    kernel_path: Path
    rootfs_path: Path
    guest_cid: int = 3
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw rootwait init=/sbin/init"
    boot_timeout_sec: int = 15
    ingress_timeout_sec: int = 10
    ingress_grace_sec: int = 2
    analysis_timeout_sec: int = 120
    teardown_timeout_sec: int = 5
    results_dir: Path = Path("results")


@dataclass
class AppConfig:
    vm: VMConfig
    max_concurrent_jobs: int = 2
    api_host: str = "0.0.0.0"
    api_port: int = 8080


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def _env_path(name: str, default: str) -> Path:
    value = os.getenv(name, default)
    return Path(value)


def load_config() -> AppConfig:
    vm = VMConfig(
        firecracker_bin=_env_path("FIRECRACKER_BINARY", "firecracker"),
        kernel_path=_env_path("FIRECRACKER_DEFAULT_KERNEL", "/opt/firecracker/vmlinux"),
        rootfs_path=_env_path("FIRECRACKER_DEFAULT_ROOTFS", "/opt/firecracker/rootfs.ext4"),
        guest_cid=_env_int("FIRECRACKER_GUEST_CID", 3),
        boot_args=os.getenv(
            "FIRECRACKER_BOOT_ARGS",
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw rootwait init=/sbin/init",
        ),
        boot_timeout_sec=_env_int("VM_BOOT_TIMEOUT_SEC", 15),
        ingress_timeout_sec=_env_int("VM_INGRESS_TIMEOUT_SEC", 10),
        ingress_grace_sec=_env_int("VM_INGRESS_GRACE_SEC", 2),
        analysis_timeout_sec=_env_int("VM_ANALYSIS_TIMEOUT_SEC", 120),
        teardown_timeout_sec=_env_int("VM_TEARDOWN_TIMEOUT_SEC", 5),
        results_dir=_env_path("RESULTS_DIR", "results"),
    )

    return AppConfig(
        vm=vm,
        max_concurrent_jobs=_env_int("MAX_CONCURRENT_JOBS", 2),
        api_host=os.getenv("API_HOST", "0.0.0.0"),
        api_port=_env_int("API_PORT", 8080),
    )
