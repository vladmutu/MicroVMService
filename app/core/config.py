from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    service_name: str = "dynamic-analysis-service"
    provider_name: str = "sentinelflow-dynamic-analysis"
    environment: str = "dev"

    host: str = "0.0.0.0"
    port: int = 8080

    bearer_token: str | None = None

    # ── Analysis orchestration ────────────────────────────────────────
    analysis_timeout_seconds: float = Field(default=180.0, gt=1.0, le=600.0)
    max_concurrent_vms: int = Field(default=4, gt=0, le=64)

    # ── Package resolution ────────────────────────────────────────────
    package_download_timeout_seconds: float = Field(default=15.0, gt=1.0, le=120.0)
    package_download_max_bytes: int = Field(default=50 * 1024 * 1024, gt=1024)

    # ── Firecracker paths ─────────────────────────────────────────────
    firecracker_binary: str = "/usr/local/bin/firecracker"
    jailer_binary: str = "/usr/local/bin/jailer"
    firecracker_workdir: str = "/tmp/dynamic-analysis"
    firecracker_default_kernel: str = "/opt/firecracker/vmlinux"
    firecracker_default_rootfs: str = "/opt/firecracker/rootfs.ext4"
    firecracker_boot_args: str = (
        "console=ttyS0 reboot=k panic=1 pci=off "
        "root=/dev/vda rw rootwait init=/run_at_start/init"
    )

    # ── VM resources ──────────────────────────────────────────────────
    # Default to 1 vCPU to avoid guest kernel SMP/timer instability
    firecracker_vcpu_count: int = Field(default=1, gt=0, le=4)
    firecracker_mem_mib: int = Field(default=1024, gt=128, le=4096)

    # ── CID allocation (must be unique per concurrent VM, ≥ 3) ───────
    cid_range_start: int = Field(default=3, ge=3)
    cid_range_end: int = Field(default=100, ge=4)

    # ── VM lifecycle timeouts ─────────────────────────────────────────
    vm_boot_timeout_seconds: float = Field(default=250.0, gt=1.0, le=300.0)
    vm_ingress_timeout_seconds: float = Field(default=300.0, gt=1.0, le=600.0)
    vm_ingress_grace_seconds: float = Field(default=2.0, ge=0.0, le=15.0)
    vm_analysis_timeout_seconds: float = Field(default=300.0, gt=1.0, le=600.0)
    vm_teardown_timeout_seconds: float = Field(default=100.0, gt=0.5, le=600.0)

    # ── Vsock port assignments ────────────────────────────────────────
    vsock_ingress_port: int = Field(default=7000, gt=0, le=65535)
    vsock_telemetry_port: int = Field(default=7001, gt=0, le=65535)
    vsock_log_port: int = Field(default=7002, gt=0, le=65535)

    # ── TAP networking ────────────────────────────────────────────────
    tap_enabled: bool = True
    tap_prefix: str = "vmtap"
    tap_subnet_prefix: str = "172.16"  # 172.16.{slot}.0/30
    tap_host_interface: str = "eth0"   # WAN interface for NAT
    tap_dns_server: str = "8.8.8.8"

    # ── PostgreSQL (mandatory) ────────────────────────────────────────
    postgres_dsn: str = "postgresql://analysis:analysis@localhost:5432/dynamic_analysis"
    postgres_connect_timeout_seconds: float = Field(default=5.0, gt=0.1, le=30.0)
    postgres_pool_min_size: int = Field(default=2, ge=1, le=20)
    postgres_pool_max_size: int = Field(default=10, ge=1, le=50)

    # ── Results directory (for artifact temp files) ───────────────────
    results_dir: str = "results"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
