# Production configuration and trust boundaries

Agent Sentinel is not production-certified. This guide defines the minimum configuration and evidence expected before a controlled non-local trial. It does not turn the local Compose file into a production architecture.

## Reference boundary

PostgreSQL is the system of record for organizations, identities, agents, telemetry, policy, incidents, memory metadata, audit data, and integration-outbox state. Redis supports rate limiting and task transport. Neo4j and OpenSearch are experimental derived stores; they must not become authorization or evidence-completeness dependencies.

Run the API and workers as separate processes against the same PostgreSQL database. The local Compose model demonstrates that process split and keeps analytics services in an optional profile, but it is not a high-availability architecture. Apply migrations from one controlled release job, not from every replica. Place the API behind TLS, an authenticated edge, request-size limits, independent rate limiting, and network policies. Do not publish PostgreSQL, Redis, Neo4j, or OpenSearch ports.

## Authentication and authorization

| Principal | Credential | Scope | Intended use |
| --- | --- | --- | --- |
| Human owner/admin | Access JWT in HttpOnly cookie or Bearer header | One organization, role-derived read/write | Dashboard and organization administration. Cookie mutations require CSRF. |
| Human member | Access JWT in cookie or Bearer header | One organization, read unless role grants more | Investigation/read paths. |
| Agent | `x-agent-sentinel-key` | One agent and its organization | Telemetry, enforcement, memory, MCP, and delegation paths explicitly accepting agent principals. |
| Bootstrap/system operator | `ADMIN_API_KEY` where explicitly wired | System bootstrap/compatibility only | Not a replacement for organization membership. |

Access JWTs carry user and organization identifiers but are accepted only while the user remains active and the organization membership still exists. Refresh tokens are hashed in the database and rotated on use. Reuse of a replaced/revoked refresh token is rejected. JWT signing currently uses one symmetric HS256 secret; automatic multi-key rollover is not implemented.

Agent keys are shown at creation/rotation and stored as HMAC-SHA256 values using `API_KEY_PEPPER`. A key is checked against the claimed agent. Rotation keeps the prior key valid for five minutes; revocation invalidates both current and grace keys and marks the agent revoked.

Password/open registration is convenient for development. Production defaults disable it through `AGENT_SENTINEL_ALLOW_OPEN_REGISTER=false`. Google OAuth uses `state` and PKCE, but currently self-provisions an organization for any verified Google account accepted by the configured client. There is no application-level domain/user allowlist. Leave OAuth disabled unless provider/edge restrictions, consent settings, and client-secret custody make that enrollment behavior acceptable.

## Required configuration

Start from [.env.example](../.env.example) as a name/reference list, not as a production secret file.

| Setting | Production requirement |
| --- | --- |
| `ENVIRONMENT` | `production`; disables API docs and enables the `Secure` cookie flag. |
| `DATABASE_URL` | PostgreSQL using a least-privilege application role; SQLite is rejected. |
| `JWT_SECRET_KEY` | Independent high-entropy secret from a secret manager. Rotation signs every user out. |
| `API_KEY_PEPPER` | Independent high-entropy secret from a secret manager. Changing it invalidates all agent keys. |
| `ADMIN_API_KEY` | Independent high-entropy bootstrap secret; required at startup even if no normal route consumes it. |
| `ENABLE_DEMO_SEED` | `false`. |
| `AGENT_SENTINEL_ALLOW_OPEN_REGISTER` | `false` unless an explicit, monitored enrollment window is approved. |
| `CORS_ORIGINS` | Exact HTTPS dashboard origins only. |
| `FRONTEND_URL` | Exact HTTPS post-OAuth destination. |
| `OAUTH_CALLBACK_URL` | Exact HTTPS callback registered with Google. |
| `COOKIE_DOMAIN` | Omit for host-only cookies where possible; otherwise set the narrowest reviewed domain. |
| `REDIS_URL` | Private, authenticated, encrypted Redis endpoint where supported. |
| `RATE_LIMIT_ENABLED` | `true`; also enforce limits at the edge. |
| `SENTINEL_FAIL_CLOSED` | `true` for the enforcement API. |

Use distinct credentials per environment. Prevent secrets from entering shell history, CI output, crash reports, frontend variables, container layers, or observability labels. `VITE_*` variables are public browser configuration and must never contain secrets.

## Browser origin and routing

The production frontend image is compiled with `VITE_API_BASE=/api/v1`. Its Nginx configuration forwards `/api/*` unchanged to the backend service, so browser API calls, session cookies, refreshes, CSRF checks, and the Google callback can remain on one public origin. Publish the frontend or an equivalent TLS ingress as the browser-facing endpoint; do not publish the backend container as a second public origin.

For a deployment at `https://sentinel.example`, use `FRONTEND_URL=https://sentinel.example`, `OAUTH_CALLBACK_URL=https://sentinel.example/api/v1/auth/google/callback`, and an exact `CORS_ORIGINS` allowlist. Register that callback exactly with Google. The local Compose file binds its diagnostic API and frontend ports to `127.0.0.1`; an external orchestrator should keep PostgreSQL, Redis, workers, and the backend on private networks and expose only the TLS ingress.

The optional `analytics` Compose profile also requires a non-placeholder `NEO4J_AUTH` in `username/password` form and a strong `OPENSEARCH_INITIAL_ADMIN_PASSWORD`. In production, keep OpenSearch certificate verification enabled and provide `OPENSEARCH_CA_CERTS` for the trusted CA. These credentials do not make the analytics profile a supported production architecture.

## Deployment preflight

1. Pin an exact reviewed commit and require a green CI run for it.
2. Review the threat model for the agents, tools, data sensitivity, and bypass paths in this deployment.
3. Verify a recent PostgreSQL backup and complete a restore rehearsal in an isolated database.
4. Run `alembic upgrade head` once from a release job and verify `alembic current --check-heads`.
5. Start the API with demo seeding and open registration disabled. Confirm `/ready` reports database and Redis readiness.
6. Probe `/healthz` and `/api/v1/health` through the public frontend origin; the latter must reach the backend without rewriting `/api/v1`.
7. Test human login, CSRF rejection, agent creation, telemetry, an allowed decision, a blocked decision, incident/replay, cross-tenant denial, key rotation, and key revocation.
8. Verify TLS, CORS, cookie attributes, network policy, edge rate limits, body-size limits, timeouts, and log redaction from outside the cluster.
9. Confirm alerts exist for readiness failure, elevated 401/403/429/5xx rates, enforcement latency/errors, database capacity, Redis failure, worker backlog, and backup failure.
10. Record rollback owners, incident contacts, recovery objectives, and the exact release/database revisions.

## Release gates

A production claim is not justified until all of the following are evidenced:

- Independent security review of authentication, tenant isolation, SDK bypasses, and infrastructure.
- PostgreSQL migration and restore drills on production-sized data.
- Load, soak, backpressure, worker-retry, and dependency-failure tests.
- Tenant-isolation verification for every enabled secondary store and exported log stream.
- A supported audit-chain verifier and external retention/immutability strategy.
- Signed/versioned artifacts, dependency/SBOM review, and a vulnerability-remediation process.
- On-call ownership, SLOs, dashboards, paging, and a completed incident exercise.

Until then, describe the deployment as a controlled prototype or pilot and state which calls are actually routed through enforcement.
