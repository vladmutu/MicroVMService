# Dynamic Analysis Service (SentinelFlow Compatible)

Production-ready Python 3.12 service exposing a synchronous `POST /analyze` endpoint with strict wire compatibility for SentinelFlow backend integration.

## Architecture

```mermaid
flowchart LR
    SF[SentinelFlow Backend] -->|POST /analyze| API[FastAPI Service]
    API --> AUTH[Optional Bearer Auth]
    API --> ORCH[AnalysisEngine + Bounded Semaphore]
    ORCH --> RES[PackageResolver\nPyPI/NPM metadata + artifact download]
    ORCH -->|sandbox_type=generic| GEN[GenericSandboxRunner\nDeterministic telemetry fallback]
    ORCH -->|sandbox_type=firecracker| FC[FirecrackerSandboxRunner]
    FC --> FCM[FirecrackerManager\nJailer + Firecracker subprocess]
    FCM --> VM[Ephemeral MicroVM]
    VM --> CP[Vsock control plane]
    VM --> TEL[Guest JSON telemetry]
    VM --> LOGS[Guest log stream]
    ORCH --> RISK[Risk Normalization]
    API --> PROM[/metrics Prometheus]
    API --> JOBS[/jobs/{job_id}/logs]
    API --> RESP[SentinelFlow-compatible JSON response]
```

## Project Layout

- `app/main.py`: FastAPI app bootstrap.
- `app/api/routes.py`: `/analyze`, `/jobs/{job_id}/logs`, `/healthz`, `/readyz`, `/metrics`.
- `app/models/contracts.py`: Pydantic v2 request/response contracts.
- `app/core/config.py`: environment-driven settings.
- `app/core/auth.py`: optional Bearer token validation.
- `app/services/analysis_engine.py`: orchestration, timeout, status/coverage mapping.
- `app/services/package_resolver.py`: npm/PyPI name+version resolution and download.
- `app/services/sandbox/generic.py`: deterministic fallback telemetry.
- `app/services/sandbox/firecracker.py`: Firecracker telemetry and guest stream parsing.
- `app/services/sandbox/firecracker_manager.py`: jailer + firecracker lifecycle, vsock control plane, and teardown hardening.
- `app/services/risk.py`: risk normalization to `[0,1]`.
- `app/services/metrics.py`: Prometheus counters/histograms/gauges.
- `tests/test_contract.py`: wire-compat contract tests.
- `tests/test_integration.py`: timeout and Firecracker telemetry integration tests.

## Request Contract

`POST /analyze`

```json
{
  "ecosystem": "npm|pypi",
  "package_name": "string",
  "package_version": "string",
  "sandbox_type": "generic|firecracker",
  "firecracker_config": {
    "kernel_path": "string",
    "rootfs_path": "string"
  },
  "artifact": {
    "artifact_name": "string",
    "artifact_suffix": "string",
    "artifact_size": 0,
    "artifact_sha256": "64-char-hex"
  }
}
```

Unknown fields are rejected with protocol error (`422`).

## Response Contract

Always returns JSON with:

- `status`: `completed|partial|failed`
- `coverage`: `full|partial|none`
- `risk_score`: `float in [0,1]` or `null`
- `provider`: `string`
- `job_id`: `string`
- `timed_out`: `boolean`
- `vm_evasion_observed`: `boolean`

Optional Firecracker telemetry fields are included when available:

- `syscall_trace`
- `network_activity`
- `filesystem_changes`

Per-job logs are available at `GET /jobs/{job_id}/logs` and `GET /analyze/{job_id}/logs`.

## Error Taxonomy and Mapping

- Auth failures (`401`): missing/invalid bearer token when configured.
- Protocol failures (`422`): invalid payload type/schema/unknown fields.
- Analysis timeouts: HTTP `200` with `status=partial`, `coverage=partial`, `timed_out=true`.
- Package/sandbox failures: HTTP `200` with `status=failed`, `coverage=none`, `risk_score=null`.

## Firecracker Isolation Design

`FirecrackerManager` enforces the lifecycle skeleton for secure microVM execution:

- immutable kernel/rootfs inputs
- per-run ephemeral workspace
- jailer-wrapped firecracker process
- CPU/memory limits from config
- per-run vsock control socket plus guest telemetry/log streams
- hard wall-clock timeout via `asyncio.wait_for`
- no NICs attached by default (default-deny outbound)
- controlled artifact ingress as a single payload file
- guaranteed best-effort cleanup of temporary artifacts
- best-effort cgroup and socket teardown on exit

For full production, extend cleanup to include network namespaces, cgroups, and mount teardown hooks integrated with your host runtime.

## Run Locally

### 1) Python

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### 2) Docker Compose

```bash
docker compose up --build
```

The Docker image includes the extra host tooling needed for Firecracker/KVM-oriented setups, and the compose file mounts `/dev/kvm` with elevated privileges so the microVM runtime can start on Linux hosts.

## SentinelFlow Integration

Point SentinelFlow backend to:

- `DYNAMIC_ANALYSIS_PROVIDER=remote`
- `DYNAMIC_ANALYSIS_REMOTE_URL=http://<host>:8080/analyze`
- `DYNAMIC_ANALYSIS_TIMEOUT_MS` aligned with `ANALYSIS_TIMEOUT_SECONDS`
- `DYNAMIC_ANALYSIS_BEARER_TOKEN` matching `BEARER_TOKEN` if auth is enabled

No backend code changes required.

## Production Hardening Checklist

- run service as non-root and read-only filesystem where possible
- place firecracker/jailer binaries in immutable, verified paths
- use signed immutable base rootfs snapshots
- enforce network egress deny by default in host firewall/netns
- enforce cgroup v2 memory/cpu/pids limits per VM and service process
- mount per-run overlayfs as writable layer and always unmount on teardown
- inject artifacts through controlled copy mechanism only
- set strict max artifact size and download timeout (already implemented)
- emit structured logs with request/job IDs and redact secrets
- configure Prometheus scraping and alert on timeout/failure rate spikes
- add chaos tests for cleanup guarantees on crashes/timeouts
- perform regular rootfs/kernel patch and CVE scanning

## Test

```bash
pytest -q
```
