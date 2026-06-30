from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    app_name: str = "Agent Sentinel"
    api_prefix: str = "/api/v1"
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./agent_sentinel.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    celery_broker_url: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    cors_origins: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if origin.strip()
    ]
    api_key_pepper: str = os.getenv("API_KEY_PEPPER", "dev-only-change-me")
    admin_api_key: str | None = os.getenv("ADMIN_API_KEY")
    enable_demo_seed: bool = os.getenv("ENABLE_DEMO_SEED", "true").lower() == "true"
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "240"))
    fail_closed: bool = os.getenv("SENTINEL_FAIL_CLOSED", "true").lower() == "true"
    allow_open_register: bool = (
        os.getenv("AGENT_SENTINEL_ALLOW_OPEN_REGISTER", "true").lower() == "true"
    )
    # JWT configuration. No hardcoded default secret: in production, an unset
    # JWT_SECRET_KEY is a startup error (see get_settings). In development we
    # fall back to an obvious dev-only value so local dev keeps working.
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    access_token_expire_minutes: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )
    refresh_token_expire_days: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    oauth_redirect_uri: str = os.getenv(
        "OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback"
    )

    @property
    def is_production(self) -> bool:
        """True when running in a production environment."""
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    # Fail-closed guard: never silently start a production server without a real
    # JWT signing key or without an admin API key. These must be set explicitly.
    if settings.is_production:
        if not settings.jwt_secret_key:
            raise RuntimeError("JWT_SECRET_KEY must be set in production.")
        if not settings.admin_api_key:
            raise RuntimeError("ADMIN_API_KEY must be set in production.")
    if not settings.jwt_secret_key:
        # Local development fallback (never used in production due to the guard above).
        settings.jwt_secret_key = "dev-only-jwt-secret-change-in-production"
    return settings
