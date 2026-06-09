"""Initial schema setup with all tables

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-06-07 11:27:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email', name='uq_user_email')
    )
    op.create_index('ix_users_email', 'users', ['email'])

    # Create organizations table
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug', name='uq_org_slug')
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    # Create organization_members table
    op.create_table(
        'organization_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', sa.String(40), nullable=False, server_default='analyst'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id', 'user_id', name='uq_org_member_user')
    )
    op.create_index('ix_organization_members_org_id', 'organization_members', ['org_id'])
    op.create_index('ix_organization_members_user_id', 'organization_members', ['user_id'])

    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False),
        sa.Column('scopes', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('name', sa.String(255), nullable=False, server_default='API Key'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash', name='uq_api_key_hash')
    )
    op.create_index('ix_api_keys_org_id', 'api_keys', ['org_id'])

    # Create agents table
    op.create_table(
        'agents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('framework', sa.String(80), nullable=False, server_default='custom'),
        sa.Column('owner', sa.String(160), nullable=False, server_default='unassigned'),
        sa.Column('environment', sa.String(80), nullable=False, server_default='development'),
        sa.Column('status', sa.String(40), nullable=False, server_default='active'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('trust_level', sa.Integer(), nullable=False, server_default='70'),
        sa.Column('api_key_hash', sa.String(128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agents_org_id', 'agents', ['org_id'])

    # Create agent_identities table
    op.create_table(
        'agent_identities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', sa.String(80), nullable=False, server_default='research_agent'),
        sa.Column('permissions', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('agent_id', name='uq_agent_identity_agent_id')
    )

    # Create tools table
    op.create_table(
        'tools',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('type', sa.String(60), nullable=False, server_default='api'),
        sa.Column('endpoint', sa.String(500), nullable=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('trust_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('status', sa.String(40), nullable=False, server_default='unverified'),
        sa.Column('allowed_roles', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('known_risks', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('usage_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('incident_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create telemetry_events table
    op.create_table(
        'telemetry_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', sa.String(120), nullable=True),
        sa.Column('event_type', sa.String(80), nullable=False),
        sa.Column('severity', sa.String(30), nullable=False, server_default='info'),
        sa.Column('payload', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('trust_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_telemetry_events_agent_id', 'telemetry_events', ['agent_id'])
    op.create_index('ix_telemetry_events_session_id', 'telemetry_events', ['session_id'])
    op.create_index('ix_telemetry_events_event_type', 'telemetry_events', ['event_type'])
    op.create_index('ix_telemetry_events_severity', 'telemetry_events', ['severity'])
    op.create_index('ix_telemetry_events_occurred_at', 'telemetry_events', ['occurred_at'])

    # Create incidents table
    op.create_table(
        'incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', sa.String(120), nullable=True),
        sa.Column('title', sa.String(240), nullable=False),
        sa.Column('category', sa.String(80), nullable=True),
        sa.Column('severity', sa.String(30), nullable=True),
        sa.Column('status', sa.String(40), nullable=False, server_default='open'),
        sa.Column('root_cause', sa.Text(), nullable=False, server_default=''),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('response_actions', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_incidents_agent_id', 'incidents', ['agent_id'])
    op.create_index('ix_incidents_session_id', 'incidents', ['session_id'])
    op.create_index('ix_incidents_category', 'incidents', ['category'])
    op.create_index('ix_incidents_severity', 'incidents', ['severity'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    op.create_index('ix_incidents_created_at', 'incidents', ['created_at'])

    # Create memory_objects table
    op.create_table(
        'memory_objects',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source', sa.String(160), nullable=False, server_default='unknown'),
        sa.Column('content_hash', sa.String(128), nullable=False),
        sa.Column('preview', sa.Text(), nullable=False, server_default=''),
        sa.Column('trust_level', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('security_status', sa.String(40), nullable=False, server_default='active'),
        sa.Column('indicators', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('modified_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_memory_objects_agent_id', 'memory_objects', ['agent_id'])

    # Create attestation_records table
    op.create_table(
        'attestation_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_id', sa.String(120), nullable=True),
        sa.Column('session_id', sa.String(120), nullable=True),
        sa.Column('goal', sa.Text(), nullable=False, server_default=''),
        sa.Column('reasoning_summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('resources_accessed', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('security_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('record_hash', sa.String(128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_attestation_records_agent_id', 'attestation_records', ['agent_id'])
    op.create_index('ix_attestation_records_action_id', 'attestation_records', ['action_id'])
    op.create_index('ix_attestation_records_session_id', 'attestation_records', ['session_id'])

    # Create threat_intel_indicators table
    op.create_table(
        'threat_intel_indicators',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('indicator_type', sa.String(80), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(30), nullable=False, server_default='medium'),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='70'),
        sa.Column('source', sa.String(160), nullable=False, server_default='local'),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_threat_intel_indicators_indicator_type', 'threat_intel_indicators', ['indicator_type'])
    op.create_index('ix_threat_intel_indicators_severity', 'threat_intel_indicators', ['severity'])

    # Create multi_agent_messages table
    op.create_table(
        'multi_agent_messages',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source_agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', sa.String(120), nullable=True),
        sa.Column('task', sa.Text(), nullable=False, server_default=''),
        sa.Column('requested_permissions', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('trust_inheritance_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('decision', sa.String(30), nullable=False, server_default='allow'),
        sa.Column('reasons', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['source_agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['target_agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_multi_agent_messages_source_agent_id', 'multi_agent_messages', ['source_agent_id'])
    op.create_index('ix_multi_agent_messages_target_agent_id', 'multi_agent_messages', ['target_agent_id'])
    op.create_index('ix_multi_agent_messages_session_id', 'multi_agent_messages', ['session_id'])

    # Create sandbox_profiles table
    op.create_table(
        'sandbox_profiles',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('runtime', sa.String(60), nullable=False, server_default='docker'),
        sa.Column('network_policy', sa.String(60), nullable=False, server_default='deny_by_default'),
        sa.Column('filesystem_policy', sa.String(60), nullable=False, server_default='read_only'),
        sa.Column('shell_policy', sa.String(60), nullable=False, server_default='disabled'),
        sa.Column('database_policy', sa.String(60), nullable=False, server_default='scoped'),
        sa.Column('allowed_hosts', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('allowed_paths', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('resource_limits', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create behavior_baselines table
    op.create_table(
        'behavior_baselines',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('normal_tools', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('normal_actions', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('normal_resources', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('anomaly_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('agent_id', name='uq_behavior_baseline_agent_id')
    )
    op.create_index('ix_behavior_baselines_agent_id', 'behavior_baselines', ['agent_id'])

    # Create red_team_scenarios table
    op.create_table(
        'red_team_scenarios',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(180), nullable=False),
        sa.Column('category', sa.String(80), nullable=True),
        sa.Column('attack_steps', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('expected_controls', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('severity', sa.String(30), nullable=False, server_default='high'),
        sa.Column('status', sa.String(40), nullable=False, server_default='generated'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_red_team_scenarios_agent_id', 'red_team_scenarios', ['agent_id'])
    op.create_index('ix_red_team_scenarios_category', 'red_team_scenarios', ['category'])

    # Create mcp_assessments table
    op.create_table(
        'mcp_assessments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('server_name', sa.String(160), nullable=False),
        sa.Column('tool_name', sa.String(160), nullable=False),
        sa.Column('description_hash', sa.String(128), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('trust_score', sa.Integer(), nullable=False, server_default='70'),
        sa.Column('verdict', sa.String(40), nullable=False, server_default='approved'),
        sa.Column('findings', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_mcp_assessments_server_name', 'mcp_assessments', ['server_name'])
    op.create_index('ix_mcp_assessments_tool_name', 'mcp_assessments', ['tool_name'])


def downgrade() -> None:
    # Drop all tables in reverse order
    op.drop_table('mcp_assessments')
    op.drop_table('red_team_scenarios')
    op.drop_table('behavior_baselines')
    op.drop_table('sandbox_profiles')
    op.drop_table('multi_agent_messages')
    op.drop_table('threat_intel_indicators')
    op.drop_table('attestation_records')
    op.drop_table('memory_objects')
    op.drop_table('incidents')
    op.drop_table('telemetry_events')
    op.drop_table('tools')
    op.drop_table('agent_identities')
    op.drop_table('agents')
    op.drop_table('api_keys')
    op.drop_table('organization_members')
    op.drop_table('organizations')
    op.drop_table('users')
