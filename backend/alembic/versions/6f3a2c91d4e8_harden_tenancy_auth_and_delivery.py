"""Harden tenancy, authentication, audit history, and delivery.

Revision ID: 6f3a2c91d4e8
Revises: 96799ffe7a70
Create Date: 2026-07-27

"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

import sqlalchemy as sa

import app.models
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6f3a2c91d4e8"
down_revision: str | None = "96799ffe7a70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_SQLITE_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

_NEW_TENANT_TABLES = (
    "mcp_assessments",
    "sandbox_profiles",
    "threat_intel_indicators",
    "attestation_records",
    "behavior_baselines",
    "multi_agent_messages",
    "red_team_scenarios",
)


def _is_sqlite() -> bool:
    return op.get_bind().dialect.name == "sqlite"


def _constraint_name(names: tuple[str, str]) -> str:
    postgres_name, sqlite_name = names
    return sqlite_name if _is_sqlite() else postgres_name


def _sqlite_unique_name(
    table_name: str,
    columns: tuple[str, ...],
    *,
    unnamed_name: str,
) -> str:
    """Resolve the constraint name exposed by SQLite's duplicate-unique reflection."""

    for constraint in sa.inspect(op.get_bind()).get_unique_constraints(table_name):
        if tuple(constraint["column_names"]) == columns:
            return constraint["name"] or unnamed_name
    raise RuntimeError(
        f"Expected a unique constraint on {table_name}({', '.join(columns)})"
    )


def _unique_constraint_names(table_name: str, columns: tuple[str, ...]) -> list[str]:
    return [
        constraint["name"]
        for constraint in sa.inspect(op.get_bind()).get_unique_constraints(table_name)
        if tuple(constraint["column_names"]) == columns and constraint["name"]
    ]


def _alter_table(
    table_name: str,
    *,
    not_null: tuple[tuple[str, sa.types.TypeEngine], ...] = (),
    drop_uniques: tuple[tuple[str, str], ...] = (),
    create_uniques: tuple[tuple[str, tuple[str, ...]], ...] = (),
    create_foreign_keys: tuple[
        tuple[str, str, tuple[str, ...], tuple[str, ...]], ...
    ] = (),
    drop_foreign_keys: tuple[str, ...] = (),
    drop_columns: tuple[str, ...] = (),
) -> None:
    """Apply table changes through batch mode when SQLite requires a rebuild."""

    if _is_sqlite():
        with op.batch_alter_table(
            table_name,
            recreate="always",
            naming_convention=_SQLITE_NAMING_CONVENTION,
        ) as batch_op:
            for names in drop_uniques:
                batch_op.drop_constraint(_constraint_name(names), type_="unique")
            for name in drop_foreign_keys:
                batch_op.drop_constraint(name, type_="foreignkey")
            for column_name, existing_type in not_null:
                batch_op.alter_column(
                    column_name,
                    existing_type=existing_type,
                    nullable=False,
                )
            for name, referred_table, local_columns, remote_columns in create_foreign_keys:
                batch_op.create_foreign_key(
                    name,
                    referred_table,
                    list(local_columns),
                    list(remote_columns),
                )
            for name, columns in create_uniques:
                batch_op.create_unique_constraint(name, list(columns))
            for column_name in drop_columns:
                batch_op.drop_column(column_name)
        return

    for names in drop_uniques:
        op.drop_constraint(_constraint_name(names), table_name, type_="unique")
    for name in drop_foreign_keys:
        op.drop_constraint(name, table_name, type_="foreignkey")
    for column_name, existing_type in not_null:
        op.alter_column(
            table_name,
            column_name,
            existing_type=existing_type,
            nullable=False,
        )
    for name, referred_table, local_columns, remote_columns in create_foreign_keys:
        op.create_foreign_key(
            name,
            table_name,
            referred_table,
            list(local_columns),
            list(remote_columns),
        )
    for name, columns in create_uniques:
        op.create_unique_constraint(name, table_name, list(columns))
    for column_name in drop_columns:
        op.drop_column(table_name, column_name)


def _backfill_tenant_ownership() -> None:
    bind = op.get_bind()
    related_agents = {
        "attestation_records": "agent_id",
        "behavior_baselines": "agent_id",
        "incidents": "agent_id",
        "memory_objects": "agent_id",
        "multi_agent_messages": "source_agent_id",
        "red_team_scenarios": "agent_id",
        "telemetry_events": "agent_id",
    }

    for table_name, agent_column in related_agents.items():
        bind.execute(
            sa.text(
                f"""
                UPDATE {table_name}
                SET org_id = (
                    SELECT agents.org_id
                    FROM agents
                    WHERE agents.id = {table_name}.{agent_column}
                )
                WHERE {agent_column} IS NOT NULL
                """
            )
        )

    cross_tenant_messages = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM multi_agent_messages AS messages
            JOIN agents AS source_agent ON source_agent.id = messages.source_agent_id
            JOIN agents AS target_agent ON target_agent.id = messages.target_agent_id
            WHERE source_agent.org_id <> target_agent.org_id
            """
        )
    ).scalar_one()
    if cross_tenant_messages:
        raise RuntimeError(
            "Cannot assign tenant ownership to cross-organization legacy "
            f"multi-agent messages ({cross_tenant_messages})"
        )

    # Standalone tenant data, nullable red-team rows, and any orphaned legacy
    # references are assigned to the oldest organization deterministically.
    for table_name in _NEW_TENANT_TABLES:
        bind.execute(
            sa.text(
                f"""
                UPDATE {table_name}
                SET org_id = (
                    SELECT organizations.id
                    FROM organizations
                    ORDER BY organizations.created_at, organizations.id
                    LIMIT 1
                )
                WHERE org_id IS NULL
                """
            )
        )

    unresolved = []
    for table_name in _NEW_TENANT_TABLES:
        count = bind.execute(
            sa.text(f"SELECT COUNT(*) FROM {table_name} WHERE org_id IS NULL")
        ).scalar_one()
        if count:
            unresolved.append(f"{table_name} ({count})")
    if unresolved:
        raise RuntimeError(
            "Cannot assign tenant ownership without an existing organization: "
            + ", ".join(unresolved)
        )


def _deduplicate_legacy_identifiers() -> None:
    bind = op.get_bind()

    agents = sa.table(
        "agents",
        sa.column("id", app.models.GUID()),
        sa.column("org_id", app.models.GUID()),
        sa.column("name", sa.String(160)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    seen_agent_names: set[tuple[str, str]] = set()
    agent_rows = bind.execute(
        sa.select(agents).order_by(
            agents.c.org_id,
            agents.c.name,
            agents.c.created_at,
            agents.c.id,
        )
    ).mappings()
    for row in agent_rows:
        org_key = str(row["org_id"])
        name = row["name"]
        key = (org_key, name)
        if key not in seen_agent_names:
            seen_agent_names.add(key)
            continue

        digest = hashlib.sha256(str(row["id"]).encode("utf-8")).hexdigest()[:12]
        suffix = f"-{digest}"
        candidate = f"{name[: 160 - len(suffix)]}{suffix}"
        bind.execute(
            agents.update()
            .where(agents.c.id == row["id"])
            .values(name=candidate)
        )
        seen_agent_names.add((org_key, candidate))

    attestations = sa.table(
        "attestation_records",
        sa.column("id", app.models.GUID()),
        sa.column("org_id", app.models.GUID()),
        sa.column("agent_id", app.models.GUID()),
        sa.column("action_id", sa.String(120)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    seen_actions: set[tuple[str, str, str]] = set()
    attestation_rows = bind.execute(
        sa.select(attestations).order_by(
            attestations.c.org_id,
            attestations.c.agent_id,
            attestations.c.action_id,
            attestations.c.created_at,
            attestations.c.id,
        )
    ).mappings()
    for row in attestation_rows:
        prefix = (str(row["org_id"]), str(row["agent_id"]))
        action_id = row["action_id"]
        key = (*prefix, action_id)
        if key not in seen_actions:
            seen_actions.add(key)
            continue

        digest = hashlib.sha256(str(row["id"]).encode("utf-8")).hexdigest()[:16]
        suffix = f":legacy:{digest}"
        candidate = f"{action_id[: 120 - len(suffix)]}{suffix}"
        bind.execute(
            attestations.update()
            .where(attestations.c.id == row["id"])
            .values(action_id=candidate)
        )
        seen_actions.add((*prefix, candidate))


def _hash_payload(payload: dict) -> str:
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _backfill_audit_chain() -> None:
    bind = op.get_bind()
    audit_logs = sa.table(
        "audit_logs",
        sa.column("id", app.models.GUID()),
        sa.column("org_id", app.models.GUID()),
        sa.column("user_id", app.models.GUID()),
        sa.column("actor_type", sa.String(40)),
        sa.column("actor_id", sa.String(160)),
        sa.column("action", sa.String(160)),
        sa.column("resource_type", sa.String(80)),
        sa.column("resource_id", sa.String(160)),
        sa.column("details", sa.JSON()),
        sa.column("request_id", sa.String(120)),
        sa.column("previous_hash", sa.String(128)),
        sa.column("record_hash", sa.String(128)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )

    previous_by_org: dict[str, str] = {}
    rows = bind.execute(
        sa.select(audit_logs).order_by(
            audit_logs.c.org_id,
            audit_logs.c.created_at,
            audit_logs.c.id,
        )
    ).mappings()
    for row in rows:
        org_key = str(row["org_id"])
        actor_type = "user" if row["user_id"] is not None else "system"
        actor_id = str(row["user_id"]) if row["user_id"] is not None else None
        previous_hash = previous_by_org.get(org_key)
        record_hash = _hash_payload(
            {
                "org_id": org_key,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "details": row["details"] or {},
                "request_id": None,
                "previous_hash": previous_hash,
            }
        )
        bind.execute(
            audit_logs.update()
            .where(audit_logs.c.id == row["id"])
            .values(
                actor_type=actor_type,
                actor_id=actor_id,
                previous_hash=previous_hash,
                record_hash=record_hash,
            )
        )
        previous_by_org[org_key] = record_hash


def _backfill_attestation_chain() -> None:
    bind = op.get_bind()
    attestations = sa.table(
        "attestation_records",
        sa.column("id", app.models.GUID()),
        sa.column("org_id", app.models.GUID()),
        sa.column("agent_id", app.models.GUID()),
        sa.column("action_id", sa.String(120)),
        sa.column("session_id", sa.String(120)),
        sa.column("goal", sa.Text()),
        sa.column("reasoning_summary", sa.Text()),
        sa.column("resources_accessed", sa.JSON()),
        sa.column("security_score", sa.Integer()),
        sa.column("decision_payload", sa.JSON()),
        sa.column("previous_hash", sa.String(128)),
        sa.column("record_hash", sa.String(128)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )

    previous_by_agent: dict[tuple[str, str], str] = {}
    rows = bind.execute(
        sa.select(attestations).order_by(
            attestations.c.org_id,
            attestations.c.agent_id,
            attestations.c.created_at,
            attestations.c.id,
        )
    ).mappings()
    for row in rows:
        chain_key = (str(row["org_id"]), str(row["agent_id"]))
        previous_hash = previous_by_agent.get(chain_key)
        record_hash = _hash_payload(
            {
                "schema": "legacy-attestation-v1",
                "org_id": chain_key[0],
                "agent_id": chain_key[1],
                "action_id": row["action_id"],
                "session_id": row["session_id"],
                "goal": row["goal"],
                "reasoning_summary": row["reasoning_summary"],
                "resources_accessed": row["resources_accessed"] or [],
                "security_score": row["security_score"],
                "policy_id": None,
                "policy_version": None,
                "decision_payload": {},
                "previous_hash": previous_hash,
            }
        )
        bind.execute(
            attestations.update()
            .where(attestations.c.id == row["id"])
            .values(
                decision_payload={},
                previous_hash=previous_hash,
                record_hash=record_hash,
            )
        )
        previous_by_agent[chain_key] = record_hash


def upgrade() -> None:
    guid = app.models.GUID()

    for table_name in _NEW_TENANT_TABLES:
        op.add_column(table_name, sa.Column("org_id", app.models.GUID(), nullable=True))

    op.add_column(
        "agents",
        sa.Column(
            "grace_period_api_key_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "telemetry_events",
        sa.Column("client_event_id", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "policy_packs",
        sa.Column("version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "sandbox_profiles",
        sa.Column("enforcement_status", sa.String(length=40), nullable=True),
    )

    op.add_column(
        "attestation_records",
        sa.Column("policy_id", app.models.GUID(), nullable=True),
    )
    op.add_column(
        "attestation_records",
        sa.Column("policy_version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "attestation_records",
        sa.Column("decision_payload", sa.JSON(), nullable=True),
    )
    op.add_column(
        "attestation_records",
        sa.Column("previous_hash", sa.String(length=128), nullable=True),
    )

    op.add_column(
        "audit_logs",
        sa.Column("actor_type", sa.String(length=40), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("actor_id", sa.String(length=160), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("request_id", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("previous_hash", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("record_hash", sa.String(length=128), nullable=True),
    )

    _backfill_tenant_ownership()
    op.get_bind().execute(sa.text("UPDATE policy_packs SET version = 1 WHERE version IS NULL"))
    op.get_bind().execute(
        sa.text(
            "UPDATE sandbox_profiles "
            "SET enforcement_status = 'policy_only' "
            "WHERE enforcement_status IS NULL"
        )
    )
    _deduplicate_legacy_identifiers()
    _backfill_audit_chain()
    _backfill_attestation_chain()

    # The initial revision combined named constraints with column-level unique
    # flags. Keep one named constraint and make the lookup indexes non-unique.
    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=False)
    if _is_sqlite():
        reflected_unique_name = _sqlite_unique_name(
            "api_keys",
            ("key_hash",),
            unnamed_name="uq_api_keys_key_hash",
        )
        _alter_table(
            "api_keys",
            drop_uniques=(("api_keys_key_hash_key", reflected_unique_name),),
            create_uniques=(("uq_api_key_hash", ("key_hash",)),),
        )
    else:
        unique_names = _unique_constraint_names("api_keys", ("key_hash",))
        legacy_names = [name for name in unique_names if name != "uq_api_key_hash"]
        for name in legacy_names:
            op.drop_constraint(name, "api_keys", type_="unique")
        if "uq_api_key_hash" not in unique_names:
            op.create_unique_constraint(
                "uq_api_key_hash",
                "api_keys",
                ["key_hash"],
            )

    _alter_table(
        "mcp_assessments",
        not_null=(("org_id", guid),),
        create_foreign_keys=((
            "fk_mcp_assessments_org_id_organizations",
            "organizations",
            ("org_id",),
            ("id",),
        ),),
    )
    op.create_index("ix_mcp_assessments_org_id", "mcp_assessments", ["org_id"])

    _alter_table(
        "sandbox_profiles",
        not_null=(("org_id", guid), ("enforcement_status", sa.String(length=40))),
        drop_uniques=(("sandbox_profiles_name_key", "uq_sandbox_profiles_name"),),
        create_uniques=(("uq_sandbox_org_name", ("org_id", "name")),),
        create_foreign_keys=((
            "fk_sandbox_profiles_org_id_organizations",
            "organizations",
            ("org_id",),
            ("id",),
        ),),
    )
    op.create_index("ix_sandbox_profiles_org_id", "sandbox_profiles", ["org_id"])

    _alter_table(
        "threat_intel_indicators",
        not_null=(("org_id", guid),),
        create_foreign_keys=((
            "fk_threat_intel_indicators_org_id_organizations",
            "organizations",
            ("org_id",),
            ("id",),
        ),),
    )
    op.create_index(
        "ix_threat_intel_indicators_org_id",
        "threat_intel_indicators",
        ["org_id"],
    )

    _alter_table(
        "attestation_records",
        not_null=(("org_id", guid), ("decision_payload", sa.JSON())),
        create_uniques=((
            "uq_attestation_agent_action",
            ("org_id", "agent_id", "action_id"),
        ),),
        create_foreign_keys=(
            (
                "fk_attestation_records_org_id_organizations",
                "organizations",
                ("org_id",),
                ("id",),
            ),
            (
                "fk_attestation_records_policy_id_policy_packs",
                "policy_packs",
                ("policy_id",),
                ("id",),
            ),
        ),
    )
    op.create_index("ix_attestation_records_org_id", "attestation_records", ["org_id"])

    _alter_table(
        "behavior_baselines",
        not_null=(("org_id", guid),),
        drop_uniques=((
            "uq_behavior_baseline_agent_id",
            "uq_behavior_baseline_agent_id",
        ),),
        create_uniques=((
            "uq_behavior_baseline_org_agent",
            ("org_id", "agent_id"),
        ),),
        create_foreign_keys=((
            "fk_behavior_baselines_org_id_organizations",
            "organizations",
            ("org_id",),
            ("id",),
        ),),
    )
    op.create_index("ix_behavior_baselines_org_id", "behavior_baselines", ["org_id"])

    _alter_table(
        "multi_agent_messages",
        not_null=(("org_id", guid),),
        create_foreign_keys=((
            "fk_multi_agent_messages_org_id_organizations",
            "organizations",
            ("org_id",),
            ("id",),
        ),),
    )
    op.create_index("ix_multi_agent_messages_org_id", "multi_agent_messages", ["org_id"])

    _alter_table(
        "red_team_scenarios",
        not_null=(("org_id", guid),),
        create_foreign_keys=((
            "fk_red_team_scenarios_org_id_organizations",
            "organizations",
            ("org_id",),
            ("id",),
        ),),
    )
    op.create_index("ix_red_team_scenarios_org_id", "red_team_scenarios", ["org_id"])

    _alter_table(
        "agents",
        create_uniques=(("uq_agent_org_name", ("org_id", "name")),),
    )
    _alter_table(
        "tools",
        drop_uniques=(("tools_name_key", "uq_tools_name"),),
        create_uniques=(("uq_tool_org_name", ("org_id", "name")),),
    )
    _alter_table(
        "policy_packs",
        not_null=(("version", sa.Integer()),),
        drop_uniques=(("policy_packs_name_key", "uq_policy_packs_name"),),
        create_uniques=(("uq_policy_org_name", ("org_id", "name")),),
    )
    _alter_table(
        "telemetry_events",
        create_uniques=((
            "uq_event_agent_client_id",
            ("org_id", "agent_id", "client_event_id"),
        ),),
    )
    _alter_table(
        "audit_logs",
        not_null=(
            ("actor_type", sa.String(length=40)),
            ("record_hash", sa.String(length=128)),
        ),
    )
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])

    op.create_table(
        "refresh_sessions",
        sa.Column("id", app.models.GUID(), nullable=False),
        sa.Column("user_id", app.models.GUID(), nullable=False),
        sa.Column("org_id", app.models.GUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", app.models.GUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_refresh_sessions_org_id", "refresh_sessions", ["org_id"])
    op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])

    op.create_table(
        "integration_outbox",
        sa.Column("id", app.models.GUID(), nullable=False),
        sa.Column("org_id", app.models.GUID(), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("aggregate_type", sa.String(length=80), nullable=False),
        sa.Column("aggregate_id", sa.String(length=160), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_integration_outbox_aggregate_id",
        "integration_outbox",
        ["aggregate_id"],
    )
    op.create_index(
        "ix_integration_outbox_created_at",
        "integration_outbox",
        ["created_at"],
    )
    op.create_index(
        "ix_integration_outbox_event_type",
        "integration_outbox",
        ["event_type"],
    )
    op.create_index("ix_integration_outbox_org_id", "integration_outbox", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_integration_outbox_org_id", table_name="integration_outbox")
    op.drop_index("ix_integration_outbox_event_type", table_name="integration_outbox")
    op.drop_index("ix_integration_outbox_created_at", table_name="integration_outbox")
    op.drop_index("ix_integration_outbox_aggregate_id", table_name="integration_outbox")
    op.drop_table("integration_outbox")

    op.drop_index("ix_refresh_sessions_user_id", table_name="refresh_sessions")
    op.drop_index("ix_refresh_sessions_org_id", table_name="refresh_sessions")
    op.drop_table("refresh_sessions")

    op.drop_index("ix_audit_logs_request_id", table_name="audit_logs")
    _alter_table(
        "audit_logs",
        drop_columns=(
            "record_hash",
            "previous_hash",
            "request_id",
            "actor_id",
            "actor_type",
        ),
    )
    _alter_table(
        "telemetry_events",
        drop_uniques=(("uq_event_agent_client_id", "uq_event_agent_client_id"),),
        drop_columns=("client_event_id",),
    )
    _alter_table(
        "policy_packs",
        drop_uniques=(("uq_policy_org_name", "uq_policy_org_name"),),
        create_uniques=((
            _constraint_name(("policy_packs_name_key", "uq_policy_packs_name")),
            ("name",),
        ),),
        drop_columns=("version",),
    )
    _alter_table(
        "tools",
        drop_uniques=(("uq_tool_org_name", "uq_tool_org_name"),),
        create_uniques=((
            _constraint_name(("tools_name_key", "uq_tools_name")),
            ("name",),
        ),),
    )
    _alter_table(
        "agents",
        drop_uniques=(("uq_agent_org_name", "uq_agent_org_name"),),
        drop_columns=("grace_period_api_key_expires_at",),
    )

    op.drop_index("ix_red_team_scenarios_org_id", table_name="red_team_scenarios")
    _alter_table(
        "red_team_scenarios",
        drop_foreign_keys=("fk_red_team_scenarios_org_id_organizations",),
        drop_columns=("org_id",),
    )

    op.drop_index("ix_multi_agent_messages_org_id", table_name="multi_agent_messages")
    _alter_table(
        "multi_agent_messages",
        drop_foreign_keys=("fk_multi_agent_messages_org_id_organizations",),
        drop_columns=("org_id",),
    )

    op.drop_index("ix_behavior_baselines_org_id", table_name="behavior_baselines")
    _alter_table(
        "behavior_baselines",
        drop_uniques=((
            "uq_behavior_baseline_org_agent",
            "uq_behavior_baseline_org_agent",
        ),),
        create_uniques=(("uq_behavior_baseline_agent_id", ("agent_id",)),),
        drop_foreign_keys=("fk_behavior_baselines_org_id_organizations",),
        drop_columns=("org_id",),
    )

    op.drop_index("ix_attestation_records_org_id", table_name="attestation_records")
    _alter_table(
        "attestation_records",
        drop_uniques=((
            "uq_attestation_agent_action",
            "uq_attestation_agent_action",
        ),),
        drop_foreign_keys=(
            "fk_attestation_records_policy_id_policy_packs",
            "fk_attestation_records_org_id_organizations",
        ),
        drop_columns=(
            "previous_hash",
            "decision_payload",
            "policy_version",
            "policy_id",
            "org_id",
        ),
    )

    op.drop_index(
        "ix_threat_intel_indicators_org_id",
        table_name="threat_intel_indicators",
    )
    _alter_table(
        "threat_intel_indicators",
        drop_foreign_keys=("fk_threat_intel_indicators_org_id_organizations",),
        drop_columns=("org_id",),
    )

    op.drop_index("ix_sandbox_profiles_org_id", table_name="sandbox_profiles")
    _alter_table(
        "sandbox_profiles",
        drop_uniques=(("uq_sandbox_org_name", "uq_sandbox_org_name"),),
        create_uniques=((
            _constraint_name(("sandbox_profiles_name_key", "uq_sandbox_profiles_name")),
            ("name",),
        ),),
        drop_foreign_keys=("fk_sandbox_profiles_org_id_organizations",),
        drop_columns=("enforcement_status", "org_id"),
    )

    op.drop_index("ix_mcp_assessments_org_id", table_name="mcp_assessments")
    _alter_table(
        "mcp_assessments",
        drop_foreign_keys=("fk_mcp_assessments_org_id_organizations",),
        drop_columns=("org_id",),
    )

    if _is_sqlite():
        _alter_table(
            "api_keys",
            drop_uniques=(("uq_api_key_hash", "uq_api_key_hash"),),
            create_uniques=(
                ("uq_api_key_hash", ("key_hash",)),
                ("uq_api_keys_key_hash", ("key_hash",)),
            ),
        )
    else:
        op.create_unique_constraint(
            "api_keys_key_hash_key",
            "api_keys",
            ["key_hash"],
        )
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)
    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=True)
