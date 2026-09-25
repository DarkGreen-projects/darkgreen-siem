"""Shared input size / allowlist constants for API validation."""

from __future__ import annotations

MAX_SEARCH_Q = 1024
MAX_COMMENT_BODY = 4000
MAX_COMMENT_AUTHOR = 64
MAX_INGEST_BATCH = 200
MAX_RAW_BYTES = 256 * 1024
MAX_SYSLOG_BYTES = 64 * 1024
# Soft rate limit: max syslog datagrams accepted per window (process-local).
SYSLOG_RATE_LIMIT = 200
SYSLOG_RATE_WINDOW_SEC = 1.0
MAX_RULE_NAME = 256
MAX_RULE_TEXT = 4000
MAX_WINDOW_MINUTES = 10080  # 7 days
MAX_COOLDOWN_MINUTES = 10080
MAX_THRESHOLD = 1_000_000
MAX_MATCH_KEYS = 20
MAX_MATCH_VALUE_LEN = 256

ALLOWED_INGEST_CHANNELS = frozenset({"http", "syslog", "seed", "agent", "file"})
ALLOWED_SOURCE_TYPES = frozenset({"firewall", "windows", "cloud_auth", "siem_export"})
ALLOWED_MATCH_KEYS = frozenset(
    {
        "src_ip",
        "dst_ip",
        "user",
        "host",
        "action",
        "severity",
        "source_type",
        "vendor",
        "device",
        "ingest_channel",
        "message",
        "event_id",
        "channel",
        "provider",
        # JSONB labels (Cynet process/hash/mitre)
        "labels.hash",
        "labels.hash_type",
        "labels.process",
        "labels.process_path",
        "labels.cmdline",
        "labels.parent_process",
        "labels.technique",
        "labels.category",
        "labels.filename",
        "labels.sensor_id",
        "labels.detection_name",
        "labels.alert_id",
    }
)


def escape_like(value: str) -> str:
    """Escape SQL LIKE metacharacters %, _, and \\."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
