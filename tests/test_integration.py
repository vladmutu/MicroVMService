from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_firecracker_telemetry_fields_present_when_available() -> None:
    payload = {
        "ecosystem": "npm",
        "package_name": "lodash",
        "package_version": "4.17.21",
        "sandbox_type": "firecracker",
        "firecracker_config": {
            "kernel_path": "/opt/firecracker/vmlinux",
            "rootfs_path": "/opt/firecracker/rootfs.ext4",
        },
    }

    fake = {
        "suspicious_syscalls": 3,
        "syscall_categories": ["credential_access"],
        "outbound_connections": 1,
        "destinations": ["203.0.113.3:443"],
        "sensitive_writes": 2,
        "write_paths": ["/etc/ld.so.preload"],
        "vm_evasion_observed": False,
    }

    with patch("app.services.sandbox.firecracker_manager.FirecrackerManager.run_vm", new_callable=AsyncMock) as run_vm:
        run_vm.return_value.stdout = __import__("json").dumps(fake)
        run_vm.return_value.stderr = ""
        response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["syscall_trace"] is not None
    assert data["network_activity"] is not None
    assert data["filesystem_changes"] is not None


def test_partial_on_global_timeout() -> None:
    payload = {
        "ecosystem": "npm",
        "package_name": "express",
        "package_version": "4.19.2",
        "sandbox_type": "generic",
    }

    with patch("app.services.analysis_engine.AnalysisEngine._analyze_inner", new_callable=AsyncMock) as inner:
        async def too_slow(_):
            raise TimeoutError

        inner.side_effect = too_slow
        response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["coverage"] == "partial"
    assert data["timed_out"] is True


def test_firecracker_job_logs_endpoint() -> None:
    payload = {
        "ecosystem": "npm",
        "package_name": "lodash",
        "package_version": "4.17.21",
        "sandbox_type": "firecracker",
        "firecracker_config": {
            "kernel_path": "/opt/firecracker/vmlinux",
            "rootfs_path": "/opt/firecracker/rootfs.ext4",
        },
    }

    fake = {
        "suspicious_syscalls": 2,
        "syscall_categories": ["credential_access"],
        "outbound_connections": 1,
        "destinations": ["203.0.113.3:443"],
        "sensitive_writes": 1,
        "write_paths": ["/etc/ld.so.preload"],
        "vm_evasion_observed": False,
    }

    with patch("app.services.sandbox.firecracker_manager.FirecrackerManager.run_vm", new_callable=AsyncMock) as run_vm:
        run_vm.return_value.stdout = __import__("json").dumps(fake)
        run_vm.return_value.stderr = ""
        analyze_response = client.post("/analyze", json=payload)

    assert analyze_response.status_code == 200
    job_id = analyze_response.json()["job_id"]

    logs_response = client.get(f"/jobs/{job_id}/logs")
    assert logs_response.status_code == 200

    logs = logs_response.json()
    assert logs["job_id"] == job_id
    assert logs["entries"]
    assert any(entry["source"] == "host" for entry in logs["entries"])
