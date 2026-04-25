from app.services.telemetry import Telemetry


def normalize_risk_score(telemetry: Telemetry, coverage: str) -> float | None:
    if coverage == "none":
        return None

    t = telemetry.normalized()
    weighted = (
        min(t.suspicious_syscalls, 50) * 0.012
        + min(t.outbound_connections, 20) * 0.02
        + min(t.sensitive_writes, 20) * 0.02
        + (0.1 if t.vm_evasion_observed else 0.0)
    )
    return round(min(max(weighted, 0.0), 1.0), 4)
