# Agent Sentinel Build Phases

## Phase 0 — Foundation

Implemented:

- Monorepo layout
- FastAPI backend
- React TypeScript frontend
- Docker Compose with PostgreSQL, Redis, optional Neo4j, optional OpenSearch
- Seeded demo data
- Basic security headers and CORS configuration

## Phase 1 — Agent EDR

Implemented:

- Agent registration
- Agent identities and scoped permissions
- Telemetry ingestion
- Runtime event storage
- Agent event timeline API
- Python SDK event recording

## Phase 2 — Cognitive Firewall

Implemented:

- Pre-execution `/api/v1/enforce/action` endpoint
- Intent Match Score
- Identity permission checks
- Tool trust scoring
- Memory influence trust
- Prompt-injection indicators
- Rule-based risk scoring
- Block/challenge/allow decisions
- Attestation records

## Phase 3 — Tool Trust and Memory Security

Implemented:

- Tool registry
- Tool trust API
- Memory object API
- Memory poisoning detection
- Memory quarantine status

## Phase 4 — Incident Response and Replay

Implemented:

- Automatic incident creation
- Recommended response actions
- Agent suspension on critical incidents
- Incident timeline
- Attack replay API and dashboard panel

## Phase 5 — Security Graph

Implemented:

- Agent → event → tool → resource → incident graph API
- Trust/risk labels on graph nodes
- Dashboard graph preview

## Phase 6 — Product Polish

Implemented:

- Dark SOC dashboard
- KPI cards
- Live attack timeline
- Risk leaderboard
- Incident queue
- Tool trust heatmap
- Cognitive Firewall focus panel
- Demo attack script

## Phase 7 — Advanced AI Security Layer

Implemented:

- MCP tool/server assessment API
- MCP hidden-instruction and dangerous-capability detection
- Local threat intelligence indicator database
- Multi-agent delegation risk scoring
- Trust inheritance scoring
- Trust laundering and privilege escalation signals
- Sandbox profile management for Docker/Kubernetes/local policy intent
- Behavioral baseline learning from telemetry
- Baseline anomaly scoring
- White-box red-team scenario generation
- Live telemetry Server-Sent Events stream
- Dashboard panels for MCP security, threat intel, baselines, red team, sandbox, and multi-agent security
- Python SDK helpers for MCP assessment and multi-agent delegation

## Deferred for later hardening

- Real authentication for human users
- Alembic-managed migrations
- OpenSearch telemetry indexing
- Neo4j native graph persistence
- Celery enrichment workers
- Actual container/Kubernetes sandbox enforcement hooks
- Enterprise SSO and tenant administration
- Production-grade immutable storage backend
