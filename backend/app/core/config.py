from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    app_name: str = "Agent Sentinel"
    api_prefix: str = "/api/v1"
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./agent_sentinel.db")
    cors_origins: list[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if origin.strip()
    ]
    api_key_pepper: str = os.getenv("API_KEY_PEPPER", "dev-only-change-me")
    admin_api_key: str | None = os.getenv("ADMIN_API_KEY")
    enable_demo_seed: bool = os.getenv("ENABLE_DEMO_SEED", "true").lower() == "true"
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "240"))
    fail_closed: bool = os.getenv("SENTINEL_FAIL_CLOSED", "true").lower() == "true"


@lru_cache
def get_settings() -> Settings:
    return Settings()
