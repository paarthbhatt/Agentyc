from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parent


def _post_json(url: str, payload: dict[str, Any], *, bearer_token: str | None = None) -> dict[str, Any]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def main() -> int:
    base_url = os.getenv("AGENT_SENTINEL_URL", "http://localhost:8000").rstrip("/")
    email = os.getenv("AGENT_SENTINEL_DEMO_EMAIL", "admin@admin")
    password = os.getenv("AGENT_SENTINEL_DEMO_PASSWORD", "admin")

    auth = _post_json(
        f"{base_url}/api/v1/auth/login",
        {"email": email, "password": password},
    )
    access_token = auth["access_token"]

    created = _post_json(
        f"{base_url}/api/v1/agents",
        {
            "name": os.getenv("AGENT_SENTINEL_DEMO_AGENT_NAME", f"Demo Agent {uuid.uuid4().hex[:8]}"),
            "framework": "custom",
            "owner": email,
            "role": "finance_agent",
        },
        bearer_token=access_token,
    )
    agent_id = str(created["agent"]["id"])
    api_key = created["api_key"]

    print(f"Registered agent: {agent_id}")
    print(f"API key: {api_key}")

    demo_env = os.environ.copy()
    demo_env["AGENT_SENTINEL_AGENT_ID"] = agent_id
    demo_env["AGENT_SENTINEL_API_KEY"] = api_key
    result = subprocess.run(
        [sys.executable, str(ROOT / "demo" / "attack_demo.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=demo_env,
        check=False,
    )
    print("--- Demo script output ---")
    print(result.stdout, end="")
    print(result.stderr, file=sys.stderr, end="")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
