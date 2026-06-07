from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, EmailStr

Decision = Literal["allow", "block", "challenge", "log_only"]


# Auth Schemas
class UserRegister(BaseModel):
    """User registration request."""
    email: EmailStr
    password: str = Field(min_length=8, max_length=255)
    org_name: str = Field(min_length=1, max_length=255)


class UserLogin(BaseModel):
    """User login request."""
    email: EmailStr
    password: str = Field(min_length=1, max_length=255)


class TokenRefresh(BaseModel):
    """Token refresh request."""
    refresh_token: str


class UserRead(BaseModel):
    """User read response."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    is_active: bool
    created_at: datetime


class OrganizationRead(BaseModel):
    """Organization read response."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    created_at: datetime


class OrganizationMemberRead(BaseModel):
    """Organization member read response."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    role: str
    created_at: datetime


class APIKeyCreate(BaseModel):
    """API key creation request."""
    name: str = Field(min_length=1, max_length=255)
    expires_at: datetime | None = None


class APIKeyRead(BaseModel):
    """API key read response."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    created_at: datetime
    expires_at: datetime | None


class AuthTokenResponse(BaseModel):
    """Auth token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserRead
    organization: OrganizationRead


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    framework: str = "custom"
    owner: str = "unassigned"
    environment: str = "development"
    role: str = "research_agent"
    permissions: dict[str, Any] | None = None


class AgentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    framework: str
    owner: str
    environment: str
    status: str
    risk_score: int
    trust_level: int
    created_at: datetime


class AgentCreateResponse(BaseModel):
    agent: AgentRead
    api_key: str


class IdentityUpsert(BaseModel):
    role: str
    permissions: dict[str, Any]
    expires_at: datetime | None = None
    active: bool = True


class IdentityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    role: str
    permissions: dict[str, Any]
    expires_at: datetime | None
    active: bool
    created_at: datetime


class ToolCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    type: str = "api"
    endpoint: str | None = None
    description: str = ""
    trust_score: int = Field(default=50, ge=0, le=100)
    status: str = "unverified"
    allowed_roles: list[str] = Field(default_factory=list)
    known_risks: list[str] = Field(default_factory=list)


class ToolRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    type: str
    endpoint: str | None
    description: str
    trust_score: int
    status: str
    allowed_roles: list[str]
    known_risks: list[str]
    usage_count: int
    incident_count: int
    created_at: datetime


class TelemetryEventCreate(BaseModel):
    agent_id: UUID
    session_id: str = "default"
    event_type: str
    severity: str = "info"
    payload: dict[str, Any] = Field(default_factory=dict)
    trust_score: int = Field(default=50, ge=0, le=100)
    risk_score: int = Field(default=20, ge=0, le=100)


class TelemetryEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    session_id: str
    event_type: str
    severity: str
    payload: dict[str, Any]
    trust_score: int
    risk_score: int
    occurred_at: datetime


class EnforcementRequest(BaseModel):
    agent_id: UUID
    session_id: str = "default"
    action_id: str | None = None
    goal: str
    reasoning_summary: str = ""
    tool_name: str
    tool_type: str = "api"
    action: str
    resource: str
    resource_sensitivity: str = "internal"
    input_text: str = ""
    memory_object_ids: list[UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnforcementDecision(BaseModel):
    decision: Decision
    intent_match_score: int
    risk_score: int
    trust_score: int
    severity: str
    reasons: list[str]
    recommended_response_actions: list[str]
    incident_id: UUID | None = None
    attestation_id: UUID | None = None


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    session_id: str
    title: str
    category: str
    severity: str
    status: str
    root_cause: str
    evidence: dict[str, Any]
    response_actions: list[str]
    created_at: datetime
    updated_at: datetime


class IncidentUpdate(BaseModel):
    status: str | None = None
    response_actions: list[str] | None = None


class MemoryCreate(BaseModel):
    agent_id: UUID
    source: str = "unknown"
    content: str


class MemoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    source: str
    content_hash: str
    preview: str
    trust_level: int
    security_status: str
    indicators: list[str]
    created_at: datetime
    modified_at: datetime


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    risk_score: int = 0
    trust_score: int = 50


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class DashboardSummary(BaseModel):
    active_agents: int
    global_risk_score: int
    ongoing_attacks: int
    blocked_actions: int
    prompt_injection_attempts: int
    memory_poisoning_alerts: int
    trust_violations: int
    identity_violations: int


class ThreatIntelCreate(BaseModel):
    indicator_type: str
    value: str
    severity: str = "medium"
    confidence: int = Field(default=70, ge=0, le=100)
    source: str = "local"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    active: bool = True


class ThreatIntelRead(ThreatIntelCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime


class MultiAgentMessageCreate(BaseModel):
    source_agent_id: UUID
    target_agent_id: UUID
    session_id: str = "default"
    task: str
    requested_permissions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MultiAgentMessageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_agent_id: UUID
    target_agent_id: UUID
    session_id: str
    task: str
    requested_permissions: list[str]
    trust_inheritance_score: int
    risk_score: int
    decision: str
    reasons: list[str]
    created_at: datetime


class SandboxProfileCreate(BaseModel):
    name: str
    runtime: str = "docker"
    network_policy: str = "deny_by_default"
    filesystem_policy: str = "read_only"
    shell_policy: str = "disabled"
    database_policy: str = "scoped"
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    resource_limits: dict[str, Any] = Field(default_factory=lambda: {"cpu": "1", "memory": "512Mi", "timeout_seconds": 300})


class SandboxProfileRead(SandboxProfileCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime


class BehaviorBaselineRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    normal_tools: list[str]
    normal_actions: list[str]
    normal_resources: list[str]
    event_count: int
    anomaly_count: int
    last_score: int
    updated_at: datetime


class MCPAssessmentCreate(BaseModel):
    server_name: str
    tool_name: str
    description: str
    declared_capabilities: list[str] = Field(default_factory=list)
    signed: bool = False
    pinned_version: str | None = None


class MCPAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    server_name: str
    tool_name: str
    description_hash: str
    risk_score: int
    trust_score: int
    verdict: str
    findings: list[str]
    created_at: datetime


class RedTeamGenerateRequest(BaseModel):
    agent_id: UUID | None = None
    goal: str = ""
    tools: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)


class RedTeamScenarioRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID | None
    name: str
    category: str
    attack_steps: list[str]
    expected_controls: list[str]
    severity: str
    status: str
    created_at: datetime
