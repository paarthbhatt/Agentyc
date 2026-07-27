from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base, get_db
from app.main import app, settings
from app.models import Agent, Organization, OrganizationMember, RefreshSession, User


class AuthHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.Session = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(self.engine)

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_db
        self.old_rate_limit_enabled = settings.rate_limit_enabled
        self.old_allow_open_register = settings.allow_open_register
        settings.rate_limit_enabled = False
        settings.allow_open_register = True
        self.client = TestClient(app, raise_server_exceptions=False)

    def tearDown(self) -> None:
        self.client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()
        settings.rate_limit_enabled = self.old_rate_limit_enabled
        settings.allow_open_register = self.old_allow_open_register

    @staticmethod
    def _register(client: TestClient, email: str, org_name: str) -> dict:
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": email,
                "password": "strong-password-123",
                "org_name": org_name,
            },
        )
        if response.status_code != 201:
            raise AssertionError(response.text)
        return response.json()

    @staticmethod
    def _csrf(client: TestClient) -> dict[str, str]:
        return {"x-csrf-token": client.cookies.get("sentinel_csrf")}

    def _add_organization(self, email: str, name: str) -> str:
        with self.Session() as db:
            user = db.query(User).filter(User.email == email).one()
            org = Organization(
                name=name,
                slug=f"{name.lower()}-{user.id}",
                owner_id=user.id,
            )
            db.add(org)
            db.flush()
            db.add(OrganizationMember(org_id=org.id, user_id=user.id, role="admin"))
            db.commit()
            return str(org.id)

    def test_refresh_replay_revokes_only_the_compromised_descendant_chain(self) -> None:
        auth = self._register(self.client, "rotation@example.com", "Rotation")
        independent_client = TestClient(app, raise_server_exceptions=False)
        try:
            independent_login = independent_client.post(
                "/api/v1/auth/login",
                json={
                    "email": "rotation@example.com",
                    "password": "strong-password-123",
                },
            )
            self.assertEqual(independent_login.status_code, 200, independent_login.text)
            independent_refresh = independent_login.json()["refresh_token"]

            root_refresh = auth["refresh_token"]
            first_rotation = self.client.post(
                "/api/v1/auth/refresh", json={"refresh_token": root_refresh}
            )
            self.assertEqual(first_rotation.status_code, 200, first_rotation.text)
            child_refresh = first_rotation.json()["refresh_token"]
            second_rotation = self.client.post(
                "/api/v1/auth/refresh", json={"refresh_token": child_refresh}
            )
            self.assertEqual(second_rotation.status_code, 200, second_rotation.text)
            latest_refresh = second_rotation.json()["refresh_token"]

            replay = self.client.post("/api/v1/auth/refresh", json={"refresh_token": root_refresh})
            self.assertEqual(replay.status_code, 401, replay.text)
            compromised_descendant = self.client.post(
                "/api/v1/auth/refresh", json={"refresh_token": latest_refresh}
            )
            self.assertEqual(compromised_descendant.status_code, 401, compromised_descendant.text)

            independent_rotation = independent_client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": independent_refresh},
            )
            self.assertEqual(independent_rotation.status_code, 200, independent_rotation.text)
        finally:
            independent_client.close()

    def test_switch_requires_current_refresh_and_links_the_rotation(self) -> None:
        auth = self._register(self.client, "switch@example.com", "Primary")
        target_org_id = self._add_organization("switch@example.com", "Target")
        csrf = self._csrf(self.client)
        original_refresh = auth["refresh_token"]

        self.client.cookies.delete("sentinel_refresh")
        missing_refresh = self.client.post(
            "/api/v1/auth/switch-organization",
            headers=csrf,
            json={"org_id": target_org_id},
        )
        self.assertEqual(missing_refresh.status_code, 401, missing_refresh.text)

        self.client.cookies.set("sentinel_refresh", original_refresh)
        switched = self.client.post(
            "/api/v1/auth/switch-organization",
            headers=csrf,
            json={"org_id": target_org_id},
        )
        self.assertEqual(switched.status_code, 200, switched.text)
        switched_refresh = switched.json()["refresh_token"]

        with self.Session() as db:
            original = (
                db.query(RefreshSession)
                .filter(RefreshSession.token_hash.isnot(None))
                .order_by(RefreshSession.created_at)
                .first()
            )
            self.assertIsNotNone(original.revoked_at)
            self.assertIsNotNone(original.replaced_by_id)

        replay_client = TestClient(app, raise_server_exceptions=False)
        try:
            replay = replay_client.post(
                "/api/v1/auth/refresh", json={"refresh_token": original_refresh}
            )
            self.assertEqual(replay.status_code, 401, replay.text)
            descendant = replay_client.post(
                "/api/v1/auth/refresh", json={"refresh_token": switched_refresh}
            )
            self.assertEqual(descendant.status_code, 401, descendant.text)
        finally:
            replay_client.close()

    def test_switch_rejects_a_refresh_session_owned_by_another_user(self) -> None:
        self._register(self.client, "owner@example.com", "Owner")
        target_org_id = self._add_organization("owner@example.com", "Owner Target")
        other_client = TestClient(app, raise_server_exceptions=False)
        try:
            other_auth = self._register(other_client, "other@example.com", "Other")
            self.client.cookies.set("sentinel_refresh", other_auth["refresh_token"])
            response = self.client.post(
                "/api/v1/auth/switch-organization",
                headers=self._csrf(self.client),
                json={"org_id": target_org_id},
            )
            self.assertEqual(response.status_code, 401, response.text)

            other_refresh_still_works = other_client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": other_auth["refresh_token"]},
            )
            self.assertEqual(
                other_refresh_still_works.status_code,
                200,
                other_refresh_still_works.text,
            )
        finally:
            other_client.close()

    def test_empty_bearer_header_cannot_bypass_cookie_csrf(self) -> None:
        self._register(self.client, "csrf@example.com", "CSRF")
        response = self.client.post(
            "/api/v1/agents",
            headers={"authorization": "Bearer "},
            json={"name": "CSRF bypass", "role": "research_agent"},
        )
        self.assertIn(response.status_code, {401, 403}, response.text)

    def test_inactive_and_expired_agent_identities_cannot_authenticate(self) -> None:
        self._register(self.client, "agents@example.com", "Agents")
        created = self.client.post(
            "/api/v1/agents",
            headers=self._csrf(self.client),
            json={"name": "Runtime Agent", "role": "research_agent"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        agent_id = created.json()["agent"]["id"]
        api_key = created.json()["api_key"]
        headers = {"x-agent-sentinel-key": api_key}
        event = {"agent_id": agent_id, "event_type": "auth.probe"}

        with self.Session() as db:
            agent = db.get(Agent, agent_id)
            agent.identity.active = False
            db.commit()
        inactive = self.client.post("/api/v1/telemetry/events", headers=headers, json=event)
        self.assertEqual(inactive.status_code, 403, inactive.text)

        with self.Session() as db:
            agent = db.get(Agent, agent_id)
            agent.identity.active = True
            agent.identity.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.commit()
        expired = self.client.post("/api/v1/telemetry/events", headers=headers, json=event)
        self.assertEqual(expired.status_code, 403, expired.text)

    def test_human_principal_uses_live_membership_and_role(self) -> None:
        self._register(self.client, "membership@example.com", "Membership")
        with self.Session() as db:
            user = db.query(User).filter(User.email == "membership@example.com").one()
            membership = (
                db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).one()
            )
            membership.role = "analyst"
            db.commit()

        denied_admin_mutation = self.client.post(
            "/api/v1/agents",
            headers=self._csrf(self.client),
            json={"name": "Denied Agent", "role": "research_agent"},
        )
        self.assertEqual(denied_admin_mutation.status_code, 403, denied_admin_mutation.text)

        with self.Session() as db:
            user = db.query(User).filter(User.email == "membership@example.com").one()
            db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).delete()
            db.commit()
        removed_membership = self.client.get("/api/v1/auth/session")
        self.assertEqual(removed_membership.status_code, 401, removed_membership.text)


if __name__ == "__main__":
    unittest.main()
