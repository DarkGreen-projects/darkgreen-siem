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
    seed_on_start: bool = True
    cors_origins: str = "http://localhost:8080,http://127.0.0.1:8080"
    rule_interval_sec: int = 15
    auth_enabled: bool = True
    demo_username: str = "analyst"
    demo_password: str = "darkgreen"
    auth_secret: str = "darkgreen-siem-dev-secret-change-me"
    siem_api_token: str = "dg-lab-token-change-me"


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
    if os.getenv("SEED_ON_START"):
        data["seed_on_start"] = os.environ["SEED_ON_START"].lower() in {"1", "true", "yes"}
    if os.getenv("CORS_ORIGINS"):
        data["cors_origins"] = os.environ["CORS_ORIGINS"]
    if os.getenv("RULE_INTERVAL_SEC"):
        data["rule_interval_sec"] = int(os.environ["RULE_INTERVAL_SEC"])
    if os.getenv("AUTH_ENABLED"):
        data["auth_enabled"] = os.environ["AUTH_ENABLED"].lower() in {"1", "true", "yes"}
    if os.getenv("DEMO_USERNAME"):
        data["demo_username"] = os.environ["DEMO_USERNAME"]
    if os.getenv("DEMO_PASSWORD"):
        data["demo_password"] = os.environ["DEMO_PASSWORD"]
    if os.getenv("AUTH_SECRET"):
        data["auth_secret"] = os.environ["AUTH_SECRET"]
    if os.getenv("SIEM_API_TOKEN"):
        data["siem_api_token"] = os.environ["SIEM_API_TOKEN"]
    return Settings(**data)
