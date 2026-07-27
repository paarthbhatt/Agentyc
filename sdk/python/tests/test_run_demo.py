from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import run_demo


class StubResponse:
    def __init__(self, payload: dict):
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "StubResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class RunDemoTests(unittest.TestCase):
    @patch("run_demo.subprocess.run")
    @patch("run_demo.urllib.request.urlopen")
    def test_login_agent_creation_and_attack_execution(self, urlopen, run) -> None:
        urlopen.side_effect = [
            StubResponse({"access_token": "human-token"}),
            StubResponse({"agent": {"id": "agent-456"}, "api_key": "agent-key"}),
        ]
        run.return_value = Mock(returncode=0, stdout="Blocked as expected\n", stderr="")
        environment = {
            "AGENT_SENTINEL_URL": "https://sentinel.example/",
            "AGENT_SENTINEL_DEMO_EMAIL": "owner@example.com",
            "AGENT_SENTINEL_DEMO_PASSWORD": "correct-password",
            "AGENT_SENTINEL_DEMO_AGENT_NAME": "Unit Test Agent",
        }

        with patch.dict(os.environ, environment, clear=True):
            exit_code = run_demo.main()

        self.assertEqual(exit_code, 0)
        login_request = urlopen.call_args_list[0].args[0]
        self.assertEqual(login_request.full_url, "https://sentinel.example/api/v1/auth/login")
        self.assertIsNone(login_request.get_header("Authorization"))
        self.assertEqual(
            json.loads(login_request.data),
            {"email": "owner@example.com", "password": "correct-password"},
        )

        create_request = urlopen.call_args_list[1].args[0]
        self.assertEqual(create_request.full_url, "https://sentinel.example/api/v1/agents")
        self.assertEqual(create_request.get_header("Authorization"), "Bearer human-token")
        self.assertEqual(json.loads(create_request.data)["name"], "Unit Test Agent")

        attack_env = run.call_args.kwargs["env"]
        self.assertEqual(attack_env["AGENT_SENTINEL_AGENT_ID"], "agent-456")
        self.assertEqual(attack_env["AGENT_SENTINEL_API_KEY"], "agent-key")
        self.assertEqual(run.call_args.args[0][1], str(ROOT / "demo" / "attack_demo.py"))


if __name__ == "__main__":
    unittest.main()
