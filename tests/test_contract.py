from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_analyze_contract_completed_generic() -> None:
    payload = {
        "ecosystem": "pypi",
        "package_name": "requests",
        "package_version": "2.32.3",
        "sandbox_type": "generic",
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    expected_keys = {
        "status",
        "coverage",
        "risk_score",
        "provider",
        "job_id",
        "timed_out",
        "vm_evasion_observed",
        "syscall_trace",
        "network_activity",
        "filesystem_changes",
    }
    assert expected_keys.issubset(data.keys())
    assert data["status"] in {"completed", "partial", "failed"}
    assert data["coverage"] in {"full", "partial", "none"}
    assert isinstance(data["provider"], str)
    assert isinstance(data["job_id"], str)
    assert isinstance(data["timed_out"], bool)
    assert isinstance(data["vm_evasion_observed"], bool)


def test_analyze_rejects_extra_fields() -> None:
    payload = {
        "ecosystem": "npm",
        "package_name": "left-pad",
        "package_version": "1.3.0",
        "sandbox_type": "generic",
        "unexpected": True,
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


def test_health_endpoints() -> None:
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
