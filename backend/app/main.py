from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid

from dotenv import load_dotenv

# Load environment variables from a local .env (if present) BEFORE importing
# modules that read settings. Previously python-dotenv was a dependency but was
# never invoked, so .env was silently ignored when not injected by the launcher.
load_dotenv()

import redis.asyncio as redis_async
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select

from app.api.auth import router as auth_router
from app.api.dependencies import require_admin_key
from app.api.google_auth import router as google_auth_router
from app.api.mcp_proxy import router as mcp_proxy_router
from app.api.routes import router
from app.core.config import get_settings
from app.core.metrics import record_http, render_prometheus
from app.db.session import SessionLocal
from app.services.seed import seed_demo_data
from app.services.trace_sanitizer import safe_validation_errors

settings = get_settings()
redis_client = redis_async.from_url(settings.redis_url, decode_responses=True)
logger = logging.getLogger("agent_sentinel.api")

app = FastAPI(
    title="Agent Sentinel API",
    description="Runtime security platform for autonomous AI agents.",
    version="0.1.0",
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # The default 422 body echoes the offending request input (and a ctx that may
    # hold the raw exception). For a telemetry product the input can be a secret,
    # so strip input/ctx and return only type/loc/msg (R-001). This also avoids
    # recursing a deeply-nested payload during response serialization
    # (RecursionError -> HTTP 500). Shared with the robustness harness.
    return JSONResponse(
        status_code=422, content={"detail": safe_validation_errors(exc.errors())}
    )


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    request.state.request_id = request_id
    start = time.perf_counter()
    client = request.client.host if request.client else "unknown"
    credential = (
        request.headers.get("authorization")
        or request.headers.get("x-agent-sentinel-key")
        or request.headers.get("x-api-key")
        or request.cookies.get("sentinel_access")
    )
    rate_identity = (
        "credential:" + hashlib.sha256(credential.encode("utf-8")).hexdigest()[:24]
        if credential
        else "client:" + client
    )
    now = time.time()

    count = 0
    if settings.rate_limit_enabled:
        key = f"rate_limit:{rate_identity}"
        try:
            async with redis_client.pipeline() as pipe:
                pipe.zremrangebyscore(key, 0, now - 60)
                pipe.zcard(key)
                pipe.zadd(key, {f"{now}:{request_id}": now})
                pipe.expire(key, 60)
                results = await asyncio.wait_for(pipe.execute(), timeout=0.5)
                count = results[1]
        except Exception as exc:
            logger.warning(
                json.dumps(
                    {
                        "event": "rate_limiter_unavailable",
                        "request_id": request_id,
                        "path": request.url.path,
                        "error": type(exc).__name__,
                    }
                )
            )
            if (
                settings.is_production
                and settings.fail_closed
                and request.url.path.endswith("/enforce/action")
            ):
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "Enforcement dependency unavailable",
                        "request_id": request_id,
                    },
                    headers={"x-request-id": request_id},
                )

    if count >= settings.rate_limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "request_id": request_id},
            headers={"x-request-id": request_id, "retry-after": "60"},
        )

    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["x-request-id"] = request_id
    response.headers["x-process-time-ms"] = str(duration_ms)
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["x-frame-options"] = "DENY"
    response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.is_production:
        response.headers["content-security-policy"] = "default-src 'none'; frame-ancestors 'none'"
    else:
        response.headers["content-security-policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
        )
    principal = getattr(request.state, "principal", None)
    logger.info(
        json.dumps(
            {
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "actor_type": getattr(principal, "actor_type", None),
                "org_id": str(principal.org_id) if principal else None,
            }
        )
    )
    route = request.scope.get("route")
    metric_path = getattr(route, "path", request.url.path)
    record_http(request.method, metric_path, response.status_code, duration_ms)
    return response


@app.on_event("startup")
def startup() -> None:
    db = SessionLocal()
    try:
        if settings.enable_demo_seed:
            seed_demo_data(db)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.on_event("shutdown")
async def shutdown() -> None:
    await redis_client.aclose()


@app.get("/ready")
async def ready() -> JSONResponse:
    checks = {
        "database": "down",
        "redis": "disabled" if not settings.rate_limit_enabled else "down",
    }
    db = SessionLocal()
    try:
        db.execute(select(1))
        checks["database"] = "ok"
    except Exception:
        pass
    finally:
        db.close()
    if settings.rate_limit_enabled:
        try:
            await asyncio.wait_for(redis_client.ping(), timeout=0.5)
            checks["redis"] = "ok"
        except Exception:
            pass
    healthy = checks["database"] == "ok" and checks["redis"] in {"ok", "disabled"}
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ready" if healthy else "not_ready", "checks": checks},
    )


@app.get("/internal/metrics", include_in_schema=False, response_class=PlainTextResponse)
def metrics(_: None = Depends(require_admin_key)) -> str:
    return render_prometheus()


app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(google_auth_router)
app.include_router(router, prefix=settings.api_prefix)
app.include_router(mcp_proxy_router, prefix=settings.api_prefix)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "tagline": "Trust Nothing. Verify Every Thought.",
        "docs": "/docs",
    }
