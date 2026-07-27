from __future__ import annotations

import os

from celery import Celery

from app.core.config import get_settings

settings = get_settings()
worker_mode = os.getenv("WORKER_MODE", "core").strip().lower()
if worker_mode not in {"core", "analytics"}:
    raise RuntimeError("WORKER_MODE must be either 'core' or 'analytics'")

queue_name = worker_mode
dispatch_task = (
    "app.tasks.dispatch_analytics_outbox"
    if worker_mode == "analytics"
    else "app.tasks.dispatch_core_outbox"
)

celery_app = Celery(
    "agent_sentinel_worker",
    broker=settings.celery_broker_url,
    backend=settings.redis_url,
    include=["app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_default_queue=queue_name,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=270,
    task_time_limit=300,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 3600},
    result_expires=3600,
    beat_schedule={
        f"dispatch-{worker_mode}-outbox": {
            "task": dispatch_task,
            "schedule": 10.0,
            "options": {"queue": queue_name, "expires": 9},
        }
    },
    task_routes={
        "app.tasks.dispatch_core_outbox": {"queue": "core"},
        "app.tasks.dispatch_analytics_outbox": {"queue": "analytics"},
    },
)
