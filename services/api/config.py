from __future__ import annotations

import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://siem:siem@localhost:5432/darkgreen_siem"
    rules_dir: str = "rules"
    samples_dir: str = "samples"
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5140
    syslog_shared_secret: str = ""
    seed_on_start: bool = True
    cors_origins: str = "http://localhost:8080,http://127.0.0.1:8080"
    rule_interval_sec: int = 15
    auth_enabled: bool = True
    allow_insecure_no_auth: bool = False
    strict_secrets: bool = False
    disable_openapi: bool = False
    allow_insecure_webhooks: bool = False
    egress_host_allowlist: str = ""
    trust_x_forwarded_for: bool = False
    run_background_jobs: bool = True
    demo_username: str = "analyst"
    demo_password: str = "darkgreen"
    auth_secret: str = "darkgreen-siem-dev-secret-change-me"
    siem_api_token: str = "dg-lab-token-change-me"
    retention_days: int = 7
    health_stale_minutes: int = 5
    health_silent_minutes: int = 30
    silence_alerts_enabled: bool = True
    purge_interval_sec: int = 300
    vt_api_key: str = ""
    vt_cache_ttl_hours: int = 24
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    notify_webhook_url: str = ""
    notify_format: str = "slack"
    notify_min_severity: str = "high"
    sla_ack_minutes: str = ""  # JSON object or empty = defaults
    sla_close_minutes: str = ""
    llm_enabled: bool = False
    llm_api_url: str = "https://api.openai.com/v1/chat/completions"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    default_tenant_id: str = "lab"
    default_tenant_name: str = "Lab"


@lru_cache
def get_settings() -> Settings:
    data: dict = {}
    if os.getenv("DATABASE_URL"):
        data["database_url"] = os.environ["DATABASE_URL"]
    if os.getenv("RULES_DIR"):
        data["rules_dir"] = os.environ["RULES_DIR"]
    if os.getenv("SAMPLES_DIR"):
        data["samples_dir"] = os.environ["SAMPLES_DIR"]
    if os.getenv("SYSLOG_HOST"):
        data["syslog_host"] = os.environ["SYSLOG_HOST"]
    if os.getenv("SYSLOG_PORT"):
        data["syslog_port"] = int(os.environ["SYSLOG_PORT"])
    if os.getenv("SYSLOG_SHARED_SECRET"):
        data["syslog_shared_secret"] = os.environ["SYSLOG_SHARED_SECRET"]
    if os.getenv("SEED_ON_START"):
        data["seed_on_start"] = os.environ["SEED_ON_START"].lower() in {"1", "true", "yes"}
    if os.getenv("CORS_ORIGINS"):
        data["cors_origins"] = os.environ["CORS_ORIGINS"]
    if os.getenv("RULE_INTERVAL_SEC"):
        data["rule_interval_sec"] = int(os.environ["RULE_INTERVAL_SEC"])
    if os.getenv("AUTH_ENABLED"):
        data["auth_enabled"] = os.environ["AUTH_ENABLED"].lower() in {"1", "true", "yes"}
    if os.getenv("ALLOW_INSECURE_NO_AUTH"):
        data["allow_insecure_no_auth"] = os.environ["ALLOW_INSECURE_NO_AUTH"].lower() in {
            "1",
            "true",
            "yes",
        }
    if os.getenv("STRICT_SECRETS"):
        data["strict_secrets"] = os.environ["STRICT_SECRETS"].lower() in {"1", "true", "yes"}
    if os.getenv("DISABLE_OPENAPI"):
        data["disable_openapi"] = os.environ["DISABLE_OPENAPI"].lower() in {"1", "true", "yes"}
    if os.getenv("ALLOW_INSECURE_WEBHOOKS"):
        data["allow_insecure_webhooks"] = os.environ["ALLOW_INSECURE_WEBHOOKS"].lower() in {
            "1",
            "true",
            "yes",
        }
    if os.getenv("EGRESS_HOST_ALLOWLIST"):
        data["egress_host_allowlist"] = os.environ["EGRESS_HOST_ALLOWLIST"]
    if os.getenv("TRUST_X_FORWARDED_FOR"):
        data["trust_x_forwarded_for"] = os.environ["TRUST_X_FORWARDED_FOR"].lower() in {
            "1",
            "true",
            "yes",
        }
    if os.getenv("RUN_BACKGROUND_JOBS"):
        data["run_background_jobs"] = os.environ["RUN_BACKGROUND_JOBS"].lower() in {
            "1",
            "true",
            "yes",
        }
    if os.getenv("DEMO_USERNAME"):
        data["demo_username"] = os.environ["DEMO_USERNAME"]
    if os.getenv("DEMO_PASSWORD"):
        data["demo_password"] = os.environ["DEMO_PASSWORD"]
    if os.getenv("AUTH_SECRET"):
        data["auth_secret"] = os.environ["AUTH_SECRET"]
    if os.getenv("SIEM_API_TOKEN"):
        data["siem_api_token"] = os.environ["SIEM_API_TOKEN"]
    if os.getenv("RETENTION_DAYS"):
        data["retention_days"] = int(os.environ["RETENTION_DAYS"])
    if os.getenv("HEALTH_STALE_MINUTES"):
        data["health_stale_minutes"] = int(os.environ["HEALTH_STALE_MINUTES"])
    if os.getenv("HEALTH_SILENT_MINUTES"):
        data["health_silent_minutes"] = int(os.environ["HEALTH_SILENT_MINUTES"])
    if os.getenv("SILENCE_ALERTS_ENABLED"):
        data["silence_alerts_enabled"] = os.environ["SILENCE_ALERTS_ENABLED"].lower() in {
            "1",
            "true",
            "yes",
        }
    if os.getenv("PURGE_INTERVAL_SEC"):
        data["purge_interval_sec"] = int(os.environ["PURGE_INTERVAL_SEC"])
    if os.getenv("VT_API_KEY"):
        data["vt_api_key"] = os.environ["VT_API_KEY"]
    if os.getenv("VT_CACHE_TTL_HOURS"):
        data["vt_cache_ttl_hours"] = int(os.environ["VT_CACHE_TTL_HOURS"])
    if os.getenv("ABUSEIPDB_API_KEY"):
        data["abuseipdb_api_key"] = os.environ["ABUSEIPDB_API_KEY"]
    if os.getenv("OTX_API_KEY"):
        data["otx_api_key"] = os.environ["OTX_API_KEY"]
    if os.getenv("NOTIFY_WEBHOOK_URL"):
        data["notify_webhook_url"] = os.environ["NOTIFY_WEBHOOK_URL"]
    if os.getenv("NOTIFY_FORMAT"):
        data["notify_format"] = os.environ["NOTIFY_FORMAT"]
    if os.getenv("NOTIFY_MIN_SEVERITY"):
        data["notify_min_severity"] = os.environ["NOTIFY_MIN_SEVERITY"]
    if os.getenv("SLA_ACK_MINUTES"):
        data["sla_ack_minutes"] = os.environ["SLA_ACK_MINUTES"]
    if os.getenv("SLA_CLOSE_MINUTES"):
        data["sla_close_minutes"] = os.environ["SLA_CLOSE_MINUTES"]
    if os.getenv("LLM_ENABLED"):
        data["llm_enabled"] = os.environ["LLM_ENABLED"].lower() in {"1", "true", "yes"}
    if os.getenv("LLM_API_URL"):
        data["llm_api_url"] = os.environ["LLM_API_URL"]
    if os.getenv("LLM_API_KEY"):
        data["llm_api_key"] = os.environ["LLM_API_KEY"]
    if os.getenv("LLM_MODEL"):
        data["llm_model"] = os.environ["LLM_MODEL"]
    if os.getenv("DEFAULT_TENANT_ID"):
        data["default_tenant_id"] = os.environ["DEFAULT_TENANT_ID"]
    if os.getenv("DEFAULT_TENANT_NAME"):
        data["default_tenant_name"] = os.environ["DEFAULT_TENANT_NAME"]
    return Settings(**data)


WEAK_AUTH_SECRETS = frozenset(
    {
        "darkgreen-siem-dev-secret-change-me",
        "darkgreen-siem-compose-secret",
    }
)
WEAK_API_TOKENS = frozenset(
    {
        "dg-lab-token-change-me",
        "dg-lab-token-compose",
    }
)
WEAK_DEMO_PASSWORDS = frozenset(
    {
        "darkgreen",
        "password",
        "admin",
        "changeme",
        "change-me-demo-password",
    }
)
WEAK_SYSLOG_SECRETS = frozenset(
    {
        "",
        "dg-lab-syslog",
        "changeme",
        "secret",
    }
)
WEAK_DB_PASSWORD_FRAGMENTS = frozenset({"siem:siem@", "postgres:postgres@", ":password@"})


def secrets_are_weak(settings: Settings | None = None) -> bool:
    s = settings or get_settings()
    return (s.auth_secret or "") in WEAK_AUTH_SECRETS or (
        s.siem_api_token or ""
    ) in WEAK_API_TOKENS


def _weak_lab_findings(settings: Settings) -> list[str]:
    findings: list[str] = []
    if (settings.auth_secret or "") in WEAK_AUTH_SECRETS:
        findings.append("AUTH_SECRET")
    if (settings.siem_api_token or "") in WEAK_API_TOKENS:
        findings.append("SIEM_API_TOKEN")
    if (settings.demo_password or "") in WEAK_DEMO_PASSWORDS:
        findings.append("DEMO_PASSWORD")
    syslog_sec = (getattr(settings, "syslog_shared_secret", None) or "").strip()
    if syslog_sec in WEAK_SYSLOG_SECRETS:
        findings.append("SYSLOG_SHARED_SECRET")
    db_url = (getattr(settings, "database_url", None) or "").lower()
    if any(frag in db_url for frag in WEAK_DB_PASSWORD_FRAGMENTS):
        findings.append("DATABASE_URL_PASSWORD")
    return findings


def enforce_startup_secrets(settings: Settings | None = None) -> None:
    """Fail closed when STRICT_SECRETS and defaults remain; else warn."""
    import logging

    s = settings or get_settings()
    log = logging.getLogger("darkgreen-siem")
    findings = _weak_lab_findings(s)
    if findings:
        msg = (
            "Weak lab secrets detected ("
            + ", ".join(findings)
            + "). Rotate before any non-lab exposure."
        )
        if s.strict_secrets:
            raise RuntimeError(f"STRICT_SECRETS=true: {msg}")
        log.warning(msg)
    if getattr(s, "trust_x_forwarded_for", False):
        log.warning(
            "TRUST_X_FORWARDED_FOR=true: ensure a trusted reverse proxy sets "
            "X-Real-IP / X-Forwarded-For; clients can otherwise spoof rate-limit keys."
        )
