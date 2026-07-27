# Agent Sentinel implementation status

This file is a delivery ledger, not a roadmap claim. A feature is marked **enforced** only when Agent Sentinel can deny the covered request path. **Recorded** features store or analyze evidence. **Simulated** features model a control but do not apply it to an external runtime. **Experimental** integrations are not supported production paths.

## Phase status

| Phase | Status | What is present | What remains |
| --- | --- | --- | --- |
| 0. Foundation | Partial | FastAPI, React/TypeScript, SQLAlchemy, Alembic, PostgreSQL/Redis local Compose services, separate API/worker commands, health checks, request IDs, readiness, and structured request logs. | A high-availability deployment topology, secret-manager integration, production metrics/alerts, and disaster-recovery evidence. |
| 1. Agent EDR | Enforced / recorded | Tenant-scoped agent registration, per-agent keys, idempotent telemetry ingestion, event timelines, and SDK recording. | Load/retention testing, ingestion backpressure, bulk export, and an operated long-term event store. |
| 2. Cognitive Firewall | Enforced | Pre-execution decisions using identity, intent, trust, memory, policy, and heuristic risk signals; idempotent action attestations. | Formal policy semantics, policy simulation/diff tooling, adversarial evaluation, and proof that every target runtime routes through the boundary. |
| 3. Tool trust and memory | Enforced / recorded | Organization-scoped tools and policies, memory ingestion, heuristic poisoning checks, and quarantine state. | Connectors that guarantee quarantine is honored by external memory/vector stores and richer provenance verification. |
| 4. Incidents and replay | Enforced / recorded | Automatic incident creation, response recommendations, response endpoints, replay timelines, key revocation, and hash-linked audit records. | Durable notification/escalation integrations, evidence export, legal retention controls, and independently operated append-only storage. |
| 5. Security graph | Recorded / experimental | SQL-derived graph responses and Neo4j integration code. | Production tenant isolation in the secondary graph store, reliable synchronization/rebuild tooling, and integration tests against Neo4j. |
| 6. Product UI | Prototype | Authenticated SOC-style dashboard views for agents, incidents, policy, memory, graph, replay, MCP, sandbox, threat intel, and red team. | Accessibility audit, browser end-to-end tests, large-data ergonomics, and production UX hardening. |
| 7. Advanced security layer | Mixed | Authenticated MCP assessment/proxy paths, local threat indicators, delegation scoring, baseline heuristics, SSE telemetry, sandbox profiles, and red-team scenario generation. | Sandbox enforcement is simulated; threat feeds are local; secondary-store and worker integrations remain experimental. |

## Security hardening status

### Implemented and covered by repository tests

- A canonical principal carries actor type, organization, role, and optional agent identity.
- Covered product reads and writes derive organization scope from the authenticated principal.
- Human sessions support rotating refresh records; replaying an old refresh token is rejected.
- Browser-cookie administrator mutations require CSRF validation; bearer requests do not.
- Google OAuth uses authorization-code flow with `state` and PKCE and returns tokens in cookies rather than URL query parameters.
- Agent API keys use a peppered HMAC hash, are bound to one agent, and support rotation and revocation.
- The primary API workflow tests anonymous denial, cross-tenant denial, agent impersonation denial, idempotent telemetry, enforcement, incidents, replay, and refresh rotation.
- SDK tests cover request contracts, idempotency identifiers, wrappers, and fail-open/fail-closed client behavior.

These tests are evidence for the covered paths, not proof that the whole system is free from authorization bugs.

### CI-enforced release checks

- Backend unit and API integration tests.
- SDK tests plus source/wheel build and metadata validation.
- Frontend TypeScript and Vite production build.
- Alembic upgrade, downgrade, re-upgrade, and model-drift check on PostgreSQL.
- Docker Compose rendering and backend/frontend image builds.
- Blocking high/critical filesystem scans for vulnerable dependencies, committed secrets, and configuration findings.

### Simulated or advisory controls

- Sandbox profiles describe intended network, filesystem, shell, database, and resource policy. They do not configure Docker, Kubernetes, seccomp, AppArmor, or another runtime.
- Red-team generation creates white-box test scenarios. It does not execute attacks or validate that a target resisted them.
- Behavior baselines, intent matching, prompt-injection detection, MCP findings, trust scores, and risk scores are deterministic heuristics. They are signals, not guarantees of safety.
- Incident response actions include recommendations and selected application-level state changes. They do not automatically rotate cloud credentials, isolate hosts, or modify external IAM.

### Experimental integrations

- Core Celery/outbox delivery and optional OpenSearch/Neo4j analytics have deployment scaffolding. They still require tenant-boundary verification, failure/reconciliation tests, and production operational evidence.
- The local Compose file separates core and `analytics` profiles and includes health checks, but it remains a single-host development topology rather than a high-availability deployment.

### Deferred production evidence

- Independent penetration test and threat-model review.
- Sustained load, soak, failover, and recovery testing.
- Restore drills with measured recovery point and recovery time objectives.
- Signed releases, SBOM publication, provenance attestations, and a documented release approval process.
- External append-only audit retention and verification tooling.
- Production observability with SLOs, paging, dashboards, and incident drills.
- Enterprise identity lifecycle, organization administration, and SCIM/SAML support.

Release decisions must use the gates in [docs/PRODUCTION.md](docs/PRODUCTION.md), not the presence of a UI page or model class.
