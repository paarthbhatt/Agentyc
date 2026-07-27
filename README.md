# Agent Sentinel

Agent Sentinel is a prototype runtime security control plane for autonomous AI agents. It records agent activity, evaluates selected actions before execution, and provides tenant-scoped investigation views for telemetry, incidents, memory, policy, and trust data.

> **Deployment status:** This repository is not a finished enterprise security product and has not received an independent security assessment. The primary API path now has tenant-aware human and agent authentication, but the local Compose topology, optional data-store integrations, and operational controls still require hardening before an internet-facing or high-assurance deployment. See [SECURITY.md](SECURITY.md) and [docs/PRODUCTION.md](docs/PRODUCTION.md).

## Capability status

The status words in this table are deliberate:

- **Enforced** means the request path can deny an operation before the wrapped action executes.
- **Recorded** means the platform stores or analyzes data but is not itself an isolation boundary.
- **Simulated** means the feature models a control or generates findings without applying that control to an external runtime.
- **Experimental** means code exists but the integration is not a supported production path.
- **Deferred** means the capability should not be relied on yet.

| Capability | Status | Current boundary |
| --- | --- | --- |
| Human authentication and tenant scoping | Enforced | Password or Google OAuth session; organization membership is checked for covered API resources. |
| Browser sessions | Enforced | Secure-cookie mode in production, rotating refresh sessions, and CSRF checks on administrator mutations. |
| Agent authentication | Enforced | Per-agent HMAC-hashed API keys; an agent key is restricted to that agent and organization. |
| Pre-execution action checks | Enforced | Rule-based intent, identity, tool, memory, policy, and risk checks at `/enforce/action`. Only calls routed through this boundary are protected. |
| MCP proxy execution | Enforced | Agent-authenticated proxy requests pass through the same decision engine. This does not secure MCP traffic that bypasses the proxy. |
| Telemetry, incidents, replay, and dashboard | Recorded | Stored in the primary SQL database and exposed through tenant-scoped APIs. |
| Memory poisoning checks | Recorded / enforced | Heuristic content checks can quarantine submitted memory objects; they do not inspect every external memory store. |
| Audit logs and attestations | Tamper-evident | Hash-linked records make in-database tampering detectable when verified. They are not immutable storage or an external transparency log. |
| Policy packs and tool trust | Enforced | Rule-engine inputs are scoped to an organization and applied by the enforcement endpoint. |
| Behavior baselines and anomaly scores | Recorded | Heuristic summaries derived from ingested telemetry. |
| Threat intelligence | Recorded | Organization-local indicators only; no managed external feed or automatic distribution is included. |
| Security graph | Recorded / experimental | The API can derive a graph from SQL records. Neo4j synchronization is experimental. |
| OpenSearch indexing and Celery enrichment | Experimental | Worker and indexing code exists, but the repository does not claim an operated, production-ready pipeline. |
| Sandbox profiles | Simulated | Profiles express intended Docker/Kubernetes/local restrictions; they are not connected to admission or runtime enforcement. |
| Red-team scenarios | Simulated | Deterministic white-box scenario generation, not an autonomous penetration-testing system. |
| Python SDK | Enforced at wrapper boundary | The core client, LangChain wrapper, and LangGraph wrapper call the API before protected operations. Unwrapped code is outside the boundary. |

The detailed implementation and deferral ledger is in [PHASES.md](PHASES.md).

## Local development

Docker Compose is a development/demo topology. Its core profile starts PostgreSQL, Redis, the API, core Celery worker/beat processes, and the frontend. Neo4j, OpenSearch, and their analytics workers are isolated behind the optional `analytics` profile. Published ports are bound to loopback; do not expose this single-host topology directly to untrusted networks.

```bash
cp .env.example .env
docker compose up --build
```

On PowerShell, use `Copy-Item .env.example .env` for the first command.

- Frontend: `http://localhost:5173`
- Development API docs: `http://localhost:8000/docs`
- Readiness: `http://localhost:8000/ready`

The frontend image calls `/api/v1` on its own origin, and Nginx forwards that path unchanged to the backend. The direct backend port is for local diagnostics only. API documentation is disabled when `ENVIRONMENT=production`. The example keeps demo seeding disabled. To include the experimental analytics services, use `docker compose --profile analytics up --build` after replacing all example credentials.

### Backend without Docker

```bash
cd backend
python -m venv .venv
python -m pip install -r requirements.lock
alembic upgrade head
uvicorn app.main:app --reload
```

Activate the virtual environment before installing dependencies. The default database is SQLite; set `DATABASE_URL` to use PostgreSQL.

### Frontend without Docker

```bash
cd frontend
npm ci
npm run dev
```

## Authentication model

Human users authenticate with password login or Google OAuth. The API accepts the access JWT in an HttpOnly cookie or as `Authorization: Bearer <token>`. Browser-cookie administrator mutations also require the `sentinel_csrf` value in the `x-csrf-token` header. Production defaults disable password registration. Configuring Google OAuth currently permits self-provisioning by any verified Google account accepted by the OAuth client; there is no application-level email-domain allowlist.

Agents use `x-agent-sentinel-key`. Agent keys are returned once at creation or rotation and are stored only as peppered HMAC-SHA256 hashes. A key authorizes one agent in one organization; it is not a human dashboard credential.

`ADMIN_API_KEY` is a production startup requirement retained for bootstrap/administrative compatibility. It is not a substitute for tenant membership on normal product routes. The canonical model is documented in [docs/PRODUCTION.md](docs/PRODUCTION.md#authentication-and-authorization).

## Register and use an agent

In development, register a human and organization, then use the returned access token to create an agent:

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "content-type: application/json" \
  -d '{"email":"owner@example.com","password":"use-a-long-local-password","org_name":"Example Org"}'

curl -X POST http://localhost:8000/api/v1/agents \
  -H "content-type: application/json" \
  -H "authorization: Bearer <access-token>" \
  -d '{"name":"Demo Agent","framework":"custom","owner":"owner@example.com","role":"finance_agent"}'
```

Store the returned `api_key` in a secret manager. Send it as `x-agent-sentinel-key` from the SDK or agent runtime. Open password registration should remain disabled in production. Leave Google OAuth disabled unless provider/edge restrictions make its current self-provisioning behavior acceptable.

## Tests and CI

```bash
cd backend
python -m unittest discover -s tests -v
```

```bash
cd sdk/python
python -m unittest discover -s tests -v
python -m build
```

```bash
cd frontend
npm ci
npm run build
```

The GitHub Actions workflow also exercises Alembic upgrade/downgrade on PostgreSQL, rejects model/migration drift, installs the same locked backend dependencies used by the image, validates both Compose profiles, boots the health-gated core stack, verifies `/api/v1` through the frontend origin, builds the application images, and scans for high/critical dependency, secret, and configuration findings.

## Production and operations

- [Production configuration and trust boundaries](docs/PRODUCTION.md)
- [Backup, restore, key rotation, migrations, and incidents](docs/OPERATIONS.md)
- [Security policy and known limitations](SECURITY.md)
- [Implementation status](PHASES.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
