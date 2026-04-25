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

    analysis_timeout_seconds: float = Field(default=25.0, gt=1.0, le=300.0)
    max_concurrent_analyses: int = Field(default=8, gt=0, le=128)

    package_download_timeout_seconds: float = Field(default=15.0, gt=1.0, le=120.0)
    package_download_max_bytes: int = Field(default=50 * 1024 * 1024, gt=1024)

    firecracker_binary: str = "/usr/local/bin/firecracker"
    jailer_binary: str = "/usr/local/bin/jailer"
    firecracker_workdir: str = "/tmp/dynamic-analysis"
    firecracker_chroot_base_dir: str = "/tmp/dynamic-analysis/jailer"
    firecracker_default_kernel: str = "/opt/firecracker/vmlinux"
    firecracker_default_rootfs: str = "/opt/firecracker/rootfs.ext4"
    firecracker_boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw rootwait init=/sbin/init"

    firecracker_vcpu_count: int = Field(default=1, gt=0, le=4)
    firecracker_mem_mib: int = Field(default=512, gt=128, le=4096)
    firecracker_guest_cid: int = Field(default=3, gt=2, le=2**32 - 1)
    firecracker_control_port: int = Field(default=7000, gt=0, le=65535)
    firecracker_telemetry_port: int = Field(default=7001, gt=0, le=65535)
    firecracker_log_port: int = Field(default=7002, gt=0, le=65535)
    firecracker_guest_stream_timeout_seconds: float = Field(default=4.0, gt=0.1, le=30.0)
    firecracker_ingress_grace_seconds: float = Field(default=1.5, ge=0.0, le=15.0)
    firecracker_enable_overlay: bool = True
    firecracker_enable_cgroups: bool = True
    firecracker_cgroup_root: str = "/sys/fs/cgroup"
    firecracker_cgroup_parent: str = "dynamic-analysis"
    firecracker_cgroup_version: str = "2"

    postgres_dsn: str | None = None
    postgres_connect_timeout_seconds: float = Field(default=5.0, gt=0.1, le=30.0)
    postgres_pool_min_size: int = Field(default=1, ge=1, le=20)
    postgres_pool_max_size: int = Field(default=5, ge=1, le=50)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
