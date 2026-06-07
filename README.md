# Agent Sentinel

**Trust Nothing. Verify Every Thought.**

Agent Sentinel is a runtime security platform for autonomous AI agents. It treats every agent as a user, workload, insider threat, and machine identity. The current implementation includes runtime telemetry, pre-execution enforcement, intent matching, tool trust, memory security, incident response, replay, multi-agent security, MCP assessment, behavioral baselines, red-team scenario generation, sandbox policy profiles, and a SOC-style dashboard.

## Implemented product capabilities

- Agent EDR telemetry ingestion
- Agent identity and scoped permissions
- Cognitive Firewall with Intent Match Score
- Tool Trust System
- Memory Security Engine
- Rule-based Risk Engine
- Automated incident creation and response recommendations
- Immutable-style attestation records with hashes
- Attack replay timeline
- Agent security graph API and dashboard preview
- Python SDK with pre-tool-call enforcement
- Dark SOC dashboard inspired by EDR/SIEM platforms
- Live Server-Sent Events telemetry stream
- MCP security assessment for hidden instructions and dangerous capabilities
- Multi-agent delegation and trust inheritance scoring
- Local threat intelligence indicator database
- Sandbox profile management
- Behavioral baseline learning and anomaly scoring
- White-box red-team scenario generation

## Quickstart with Docker

```bash
docker compose up --build
```

Open:

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000/docs`

The backend seeds demo data on first startup.

## Local backend without Docker

```bash
cd backend
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

By default, the backend uses SQLite at `backend/agent_sentinel.db` unless `DATABASE_URL` is set.

## Local frontend

```bash
cd frontend
npm install
npm run dev
```

## Register an agent

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "content-type: application/json" \
  -H "x-admin-api-key: local-demo-admin-key" \
  -d '{"name":"Demo Agent","framework":"custom","owner":"security@example.com","role":"finance_agent"}'
```

Save the returned `agent.id` and `api_key` for SDK usage.

## Run the demo attack

```bash
set AGENT_SENTINEL_AGENT_ID=<agent-id>
set AGENT_SENTINEL_API_KEY=<api-key>
python demo/attack_demo.py
```

The demo asks a finance agent to summarize quarterly sales, then attempts to read payroll records. Agent Sentinel should block the action, create an incident, and make the sequence available in replay.

## API groups

- `/api/v1/agents`
- `/api/v1/telemetry/events`
- `/api/v1/telemetry/stream`
- `/api/v1/enforce/action`
- `/api/v1/tools`
- `/api/v1/trust/tools`
- `/api/v1/risk/agents`
- `/api/v1/memory`
- `/api/v1/incidents`
- `/api/v1/replay`
- `/api/v1/graph`
- `/api/v1/policies`
- `/api/v1/threats`
- `/api/v1/threats/indicators`
- `/api/v1/mcp/assess`
- `/api/v1/mcp/assessments`
- `/api/v1/multi-agent/messages`
- `/api/v1/sandbox/profiles`
- `/api/v1/baselines/agents/{agent_id}`
- `/api/v1/redteam/generate`
- `/api/v1/redteam/scenarios`

## Tests

```bash
cd backend
python -m unittest discover -s tests
```

```bash
cd frontend
npm run build
```

## Security notes

- Agent API keys are generated once and stored only as HMAC-SHA256 hashes.
- Admin write APIs can be protected with `ADMIN_API_KEY` and `x-admin-api-key`.
- The SDK supports fail-closed behavior when the enforcement API is unavailable.
- Sensitive memory content is hashed and only a short preview is stored.
- Every enforcement decision creates telemetry and an attestation record.
- This build has API-key protection for agents/admin writes, but does not yet implement full human-user SSO or tenant isolation; add those before real multi-user deployment.
- Sandbox profiles currently model and expose enforcement policy intent; wire them to actual Docker/Kubernetes admission/runtime controls before relying on them as isolation boundaries.

## Build phases

See `PHASES.md` for the implemented phase breakdown and deferred hardening work.
