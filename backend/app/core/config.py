from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    app_name: str = "Agent Sentinel"
    api_prefix: str = "/api/v1"
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./agent_sentinel.db")
    database_pool_size: int = int(os.getenv("DATABASE_POOL_SIZE", "10"))
    database_max_overflow: int = int(os.getenv("DATABASE_MAX_OVERFLOW", "20"))
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
    enable_demo_seed: bool = (
        os.getenv(
            "ENABLE_DEMO_SEED",
            "false" if environment.lower() == "production" else "true",
        ).lower()
        == "true"
    )
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "240"))
    rate_limit_enabled: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    fail_closed: bool = os.getenv("SENTINEL_FAIL_CLOSED", "true").lower() == "true"
    allow_open_register: bool = (
        os.getenv(
            "AGENT_SENTINEL_ALLOW_OPEN_REGISTER",
            "false" if environment.lower() == "production" else "true",
        ).lower()
        == "true"
    )
    # JWT configuration. No hardcoded default secret: in production, an unset
    # JWT_SECRET_KEY is a startup error (see get_settings). In development we
    # fall back to an obvious dev-only value so local dev keeps working.
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "agent-sentinel")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "agent-sentinel-api")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    refresh_token_expire_days: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")
    oauth_callback_url: str = os.getenv(
        "OAUTH_CALLBACK_URL", "http://localhost:8000/api/v1/auth/google/callback"
    )
    cookie_domain: str | None = os.getenv("COOKIE_DOMAIN") or None
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    opensearch_url: str = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")

    @property
    def is_production(self) -> bool:
        """True when running in a production environment."""
        return self.environment.lower() == "production"

    @property
    def cookie_secure(self) -> bool:
        return self.is_production


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    # Fail-closed guard: never silently start a production server without a real
    # JWT signing key or without an admin API key. These must be set explicitly.
    if settings.is_production:
        if len(settings.jwt_secret_key) < 32:
            raise RuntimeError("JWT_SECRET_KEY must contain at least 32 characters in production.")
        if not settings.admin_api_key or len(settings.admin_api_key) < 32:
            raise RuntimeError("ADMIN_API_KEY must contain at least 32 characters in production.")
        if len(settings.api_key_pepper) < 32 or "change-me" in settings.api_key_pepper:
            raise RuntimeError("API_KEY_PEPPER must be a strong secret in production.")
        if settings.database_url.startswith("sqlite"):
            raise RuntimeError("PostgreSQL is required in production.")
        if "*" in settings.cors_origins:
            raise RuntimeError("Wildcard CORS origins are forbidden in production.")
        if not settings.frontend_url.startswith("https://"):
            raise RuntimeError("FRONTEND_URL must use HTTPS in production.")
        if settings.google_client_id and not settings.oauth_callback_url.startswith("https://"):
            raise RuntimeError("OAUTH_CALLBACK_URL must use HTTPS in production.")
    if not settings.jwt_secret_key:
        # Local development fallback (never used in production due to the guard above).
        settings.jwt_secret_key = "dev-only-jwt-secret-change-in-production"
    return settings
