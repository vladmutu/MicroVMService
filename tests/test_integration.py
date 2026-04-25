"""
test_integration.py — Integration tests with mocked Firecracker VM lifecycle.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.services.ioc_detector import IOCEvidence
from app.services.sandbox.vm_lifecycle import VMRunResult


@pytest.fixture()
def client():
    """Create a TestClient with mocked persistence."""
    with patch("app.services.persistence.PostgresPersistence") as MockPersistence:
        mock_persistence = AsyncMock()
        mock_persistence.is_connected = True
        mock_persistence.initialize = AsyncMock()
        mock_persistence.close = AsyncMock()
        mock_persistence.create_job = AsyncMock()
        mock_persistence.update_job_status = AsyncMock()
        mock_persistence.write_telemetry = AsyncMock()
        mock_persistence.write_log = AsyncMock()
        mock_persistence.write_verdict = AsyncMock()
        mock_persistence.get_logs = AsyncMock(return_value=[])
        MockPersistence.return_value = mock_persistence

        from app.main import app
        with TestClient(app) as c:
            yield c


def _make_mock_result(verdict: str = "benign", **kwargs) -> VMRunResult:
    """Helper to create a mock VMRunResult."""
    return VMRunResult(
        evidence=IOCEvidence(
            verdict=verdict,
            dynamic_hit=verdict != "benign",
            network_iocs=kwargs.get("network_iocs", []),
            process_iocs=kwargs.get("process_iocs", []),
            file_iocs=kwargs.get("file_iocs", []),
            dns_iocs=kwargs.get("dns_iocs", []),
            crypto_iocs=kwargs.get("crypto_iocs", []),
            raw_line_count=kwargs.get("raw_line_count", 100),
            outbound_connections=len(kwargs.get("network_iocs", [])),
            suspicious_syscalls=len(kwargs.get("process_iocs", [])),
            sensitive_writes=len(kwargs.get("file_iocs", [])),
        ),
        telemetry_events=[{"event": "agent_finished", "job_id": "test"}],
        log_lines=["[agent] test log line"],
    )


def test_firecracker_returns_ioc_detail(client) -> None:
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

    mock_result = _make_mock_result(
        verdict="malicious",
        network_iocs=["public_ip:8.8.8.8"],
        process_iocs=["suspicious_exec:curl http://evil.com"],
        file_iocs=["sensitive_file:/etc/shadow"],
    )

    with patch(
        "app.services.sandbox.vm_lifecycle.VMLifecycleManager.run_analysis",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["ioc_detail"] is not None
    assert data["ioc_detail"]["verdict"] == "malicious"
    assert data["ioc_detail"]["dynamic_hit"] is True
    assert data["syscall_trace"] is not None
    assert data["network_activity"] is not None


def test_partial_on_global_timeout(client) -> None:
    payload = {
        "ecosystem": "npm",
        "package_name": "express",
        "package_version": "4.19.2",
        "sandbox_type": "generic",
    }

    with patch(
        "app.services.analysis_engine.AnalysisEngine._analyze_inner",
        new_callable=AsyncMock,
    ) as inner:
        async def too_slow(*args):
            raise TimeoutError

        inner.side_effect = too_slow
        response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["coverage"] == "partial"
    assert data["timed_out"] is True


def test_health_endpoints(client) -> None:
    assert client.get("/healthz").status_code == 200
