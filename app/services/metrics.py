from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

REQUEST_COUNTER = Counter(
    "dynamic_analysis_requests_total",
    "Total analyze requests",
    labelnames=("ecosystem", "sandbox_type", "status"),
)
REQUEST_DURATION = Histogram(
    "dynamic_analysis_request_duration_seconds",
    "Analyze request durations",
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60),
)
IN_FLIGHT = Gauge("dynamic_analysis_in_flight", "In-flight analyze jobs")


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
