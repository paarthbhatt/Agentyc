from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque

from dotenv import load_dotenv

# Load environment variables from a local .env (if present) BEFORE importing
# modules that read settings. Previously python-dotenv was a dependency but was
# never invoked, so .env was silently ignored when not injected by the launcher.
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.auth import router as auth_router
from app.api.google_auth import router as google_auth_router
from app.api.routes import router
from app.api.mcp_proxy import router as mcp_proxy_router
from app.core.config import get_settings
from app.db.session import Base, SessionLocal, engine
from app.services.seed import seed_demo_data

import redis.asyncio as redis_async

settings = get_settings()
redis_client = redis_async.from_url(settings.redis_url, decode_responses=True)

app = FastAPI(
    title="Agent Sentinel API",
    description="Runtime security platform for autonomous AI agents.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    start = time.perf_counter()
    client = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Redis Sliding Window Rate Limiter
    key = f"rate_limit:{client}"
    try:
        async with redis_client.pipeline() as pipe:
            # Remove timestamps older than 60 seconds
            pipe.zremrangebyscore(key, 0, now - 60)
            # Count the remaining items
            pipe.zcard(key)
            # Add the current timestamp
            pipe.zadd(key, {str(now): now})
            # Set an expiration on the key so it cleans itself up
            pipe.expire(key, 60)
            
            results = await pipe.execute()
            count = results[1]
    except Exception as e:
        print(f"Redis rate limiting error: {e}")
        count = 0  # Fail-open if Redis is down

    if count >= settings.rate_limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "request_id": request_id},
            headers={"x-request-id": request_id, "retry-after": "60"},
        )

    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    response.headers["x-process-time-ms"] = str(
        round((time.perf_counter() - start) * 1000, 2)
    )
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["x-frame-options"] = "DENY"
    response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["content-security-policy"] = (
        "default-src 'self' http://localhost:* ws://localhost:* https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:* https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' http://localhost:* https://cdn.jsdelivr.net; "
        "img-src 'self' data: http://localhost:*; "
        "connect-src 'self' http://localhost:* ws://localhost:*; "
        "frame-ancestors 'none'"
    )
    return response


@app.on_event("startup")
def startup() -> None:
    if settings.is_production and not settings.jwt_secret_key:
        raise RuntimeError("JWT_SECRET_KEY must be set in production.")
    if settings.is_production and not settings.admin_api_key:
        raise RuntimeError("ADMIN_API_KEY must be set in production.")
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
