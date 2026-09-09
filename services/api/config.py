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


@lru_cache
def get_settings() -> Settings:
    # Allow classic DATABASE_URL env without alias boilerplate
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
    return Settings(**data)
