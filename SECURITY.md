# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting flow:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability** under Security Advisories.
3. Include the affected commit/version, impact, reproduction steps, and any proof of concept, logs, or screenshots.

The project aims to acknowledge reports within 5 business days and provide an initial assessment within 14 days. These are response targets, not a contractual service-level agreement.

## Supported versions

Only the latest code on `main` is currently eligible for security fixes. There is no long-term-support release line. Until versioned releases and signed artifacts are published, deployers must pin and record the exact commit they operate.

## Security and deployment status

Agent Sentinel is a security-focused prototype, not a production-certified security boundary. It has not received an independent audit or penetration test. A passing CI run demonstrates that the checked behavior and repository scans passed at one commit; it does not certify the deployment, its infrastructure, or every authorization path.

Current primary-path controls include:

- Organization-scoped human principals backed by password login or Google OAuth.
- HttpOnly access/refresh cookies, rotating refresh sessions, and CSRF checks for cookie-authenticated administrator mutations.
- `state` and PKCE on Google OAuth.
- Per-agent API keys stored as peppered HMAC-SHA256 hashes and bound to one agent and organization.
- Tenant filters and not-found responses on covered product resources.
- Rule-based pre-execution decisions, idempotency identifiers, request IDs, security headers, and audit/attestation hash chains.
- Production startup rejection for missing JWT/admin secrets, the development API-key pepper, or SQLite.

## Known limitations and trust boundaries

- Enforcement covers only calls sent through `/api/v1/enforce/action`, the MCP proxy, or an SDK/wrapper that invokes them. Code that bypasses those paths is not protected.
- Detection, intent, risk, trust, behavior, memory, and MCP scores are heuristics. They can produce false positives and false negatives.
- Hash-linked audit and attestation rows are tamper-evident only when the chain is independently verified. Database administrators can still modify or delete both records and hashes. This is not immutable/WORM storage.
- Sandbox profiles are policy models only. They do not enforce container, Kubernetes, filesystem, process, or network isolation.
- Red-team scenarios are generated test plans, not executed penetration tests.
- Threat intelligence is local organization data; no curated feed freshness or provenance service is included.
- Neo4j, OpenSearch, Celery, and outbox paths are experimental. Do not rely on secondary stores for authorization, evidence completeness, or tenant separation until their schemas, credentials, reconciliation, and isolation have been tested end to end.
- The checked-in Compose topology is for local development. It uses single-host PostgreSQL/Redis and local application ports; optional analytics services are single-node. It does not provide TLS termination, a secret manager, host hardening, high availability, or managed backups.
- When Google OAuth is configured, any verified Google account accepted by that OAuth client can self-provision an organization. The application does not implement an email-domain or user allowlist.
- Rate limiting depends on Redis. In production fail-closed mode, an unavailable limiter rejects enforcement requests, while other routes may continue without rate limiting. Put an independently operated rate limit and network policy at the edge.
- The Python SDK is synchronous and protects only wrapped operations. Its optional fail-open mode must not be enabled for high-risk actions.
- No external secret manager, automatic JWT signing-key rollover, external audit archive, backup scheduler, paging integration, or supported multi-region design is included.

## Minimum deployment requirements

Before any non-local deployment:

- Set `ENVIRONMENT=production`, disable demo seeding and open registration, and use PostgreSQL.
- Generate independent high-entropy values for `JWT_SECRET_KEY`, `API_KEY_PEPPER`, and `ADMIN_API_KEY`; keep them in a secret manager, not `.env` or Compose files.
- Terminate TLS at a trusted reverse proxy, restrict CORS to exact origins, set the cookie domain deliberately, and restrict direct access to the API and data stores.
- Operate Redis with authentication, encryption, persistence/availability appropriate to the use case, and edge rate limiting.
- Run migrations as a controlled one-off deployment step after a verified backup. Do not let every API/worker replica race to migrate.
- Confirm all GitHub Actions checks pass for the exact commit and review any scanner exceptions.
- Complete the readiness gates in [docs/PRODUCTION.md](docs/PRODUCTION.md) and rehearse [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Credential exposure response

If any credential may have been exposed, revoke or rotate it at the provider first; removing it from the current tree is not sufficient. Search history, CI logs, artifacts, images, caches, and forks, then document the affected interval and inspect audit data for use.

Changing `API_KEY_PEPPER` invalidates all existing agent-key hashes because dual-pepper verification is not implemented. Follow the coordinated procedure in [docs/OPERATIONS.md](docs/OPERATIONS.md#key-rotation).

## Historical credential exposure

A Google OAuth client secret was previously committed and pushed. The project records that the credential was revoked and rotated and that history was rewritten. Old clones and forks may still contain the value; re-clone from current `main` and treat any copy of the old credential as compromised.
