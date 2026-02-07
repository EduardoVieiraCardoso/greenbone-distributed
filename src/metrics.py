"""
Prometheus metrics for Scan Hub.
"""

from prometheus_client import Counter, Gauge, Histogram

# Scans submitted (by type)
SCANS_SUBMITTED = Counter(
    "scanhub_scans_submitted_total",
    "Total scans submitted",
    ["scan_type"],
)

# Scans completed (by final GVM status)
SCANS_COMPLETED = Counter(
    "scanhub_scans_completed_total",
    "Total scans that reached a terminal state",
    ["gvm_status"],
)

# Scans failed (adapter-level errors, not GVM status)
SCANS_FAILED = Counter(
    "scanhub_scans_failed_total",
    "Total scans that failed due to adapter/connection errors",
)

# Currently active scans (running in background)
SCANS_ACTIVE = Gauge(
    "scanhub_scans_active",
    "Number of scans currently in progress",
)

# Active scans per probe
SCANS_ACTIVE_PER_PROBE = Gauge(
    "scanhub_probe_scans_active",
    "Number of scans currently in progress per probe",
    ["probe"],
)

# Scans routed to each probe
PROBE_SCANS_ROUTED = Counter(
    "scanhub_probe_scans_routed_total",
    "Total scans routed to each probe",
    ["probe"],
)

# Scan duration from start to completion
SCAN_DURATION = Histogram(
    "scanhub_scan_duration_seconds",
    "Scan duration from start to terminal state",
    buckets=[60, 300, 600, 1800, 3600, 7200, 14400, 28800, 43200, 86400],
)

# GVM connection errors
GVM_CONNECTION_ERRORS = Counter(
    "scanhub_gvm_connection_errors_total",
    "Total GVM connection failures",
    ["probe"],
)
