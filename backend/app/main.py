from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.api.auth import router as auth_router
from app.core.config import get_settings
from app.db.session import Base, SessionLocal, engine
from app.services.seed import seed_demo_data

settings = get_settings()
_rate_windows: dict[str, deque[float]] = defaultdict(deque)

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
    window = _rate_windows[client]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= settings.rate_limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "request_id": request_id},
            headers={"x-request-id": request_id, "retry-after": "60"},
        )
    window.append(now)

    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    response.headers["x-process-time-ms"] = str(round((time.perf_counter() - start) * 1000, 2))
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["x-frame-options"] = "DENY"
    response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["content-security-policy"] = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; frame-ancestors 'none'"
    return response


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if settings.enable_demo_seed:
            seed_demo_data(db)
    finally:
        db.close()


app.include_router(auth_router)
app.include_router(router, prefix=settings.api_prefix)


@app.get("/")
def root() -> dict[str, str]:
    return {"name": settings.app_name, "tagline": "Trust Nothing. Verify Every Thought.", "docs": "/docs"}
