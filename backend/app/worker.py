from celery import Celery
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "agent_sentinel_worker",
    broker=settings.celery_broker_url,
    backend=settings.redis_url,
    include=["app.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300, # 5 minute max runtime per task
)
