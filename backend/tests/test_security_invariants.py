from __future__ import annotations

import unittest

from fastapi.routing import APIRoute

from app.auth.password import hash_password, verify_password
from app.main import app
from app.models import (
    Agent,
    AttestationRecord,
    AuditLog,
    BehaviorBaseline,
    Incident,
    IntegrationOutbox,
    MCPAssessment,
    MemoryObject,
    MultiAgentMessage,
    PolicyPack,
    RedTeamScenario,
    SandboxProfile,
    TelemetryEvent,
    ThreatIntelIndicator,
    Tool,
)

AUTH_DEPENDENCIES = {
    "get_current_principal",
    "get_agent_principal",
    "get_tenant_principal",
    "require_csrf",
    "require_user_csrf",
}


def _dependency_names(dependant) -> set[str]:
    names: set[str] = set()
    for dependency in dependant.dependencies:
        if dependency.call:
            names.add(dependency.call.__name__)
        names.update(_dependency_names(dependency))
    return names


class SecurityInvariantTests(unittest.TestCase):
    def test_password_hashing_handles_long_unicode_inputs(self) -> None:
        password = "correct horse battery staple" * 20 + "\N{SNOWMAN}"
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password(password + "x", hashed))

    def test_all_non_auth_api_routes_declare_authentication(self) -> None:
        intentionally_public = {
            ("/api/v1/health", "GET"),
            ("/api/v1/auth/login", "POST"),
            ("/api/v1/auth/register", "POST"),
            ("/api/v1/auth/refresh", "POST"),
            ("/api/v1/auth/logout", "POST"),
            ("/api/v1/auth/google/login", "GET"),
            ("/api/v1/auth/google/callback", "GET"),
        }
        missing: list[str] = []
        for route in app.routes:
            if not isinstance(route, APIRoute) or not route.path.startswith("/api/v1"):
                continue
            for method in route.methods or set():
                if (route.path, method) in intentionally_public:
                    continue
                names = _dependency_names(route.dependant)
                if not names.intersection(AUTH_DEPENDENCIES):
                    missing.append(f"{method} {route.path}")
        self.assertEqual(missing, [], f"Routes missing authentication: {missing}")

    def test_every_tenant_owned_model_has_org_id(self) -> None:
        tenant_models = [
            Agent,
            AttestationRecord,
            AuditLog,
            BehaviorBaseline,
            Incident,
            IntegrationOutbox,
            MCPAssessment,
            MemoryObject,
            MultiAgentMessage,
            PolicyPack,
            RedTeamScenario,
            SandboxProfile,
            TelemetryEvent,
            ThreatIntelIndicator,
            Tool,
        ]
        missing = [
            model.__name__ for model in tenant_models if "org_id" not in model.__table__.columns
        ]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
