# Operations runbook

This runbook is a baseline for operators. Adapt commands to the platform and rehearse them against an isolated copy before an incident. Never make a production database the first place a backup, restore, downgrade, or key-rotation procedure is tested.

## Ownership and records

For each environment, record the release commit, Alembic revision, PostgreSQL instance/backup policy, secret versions, OAuth client, Redis instance, public endpoints, data-retention policy, on-call owner, and recovery objectives. Keep this inventory outside the application database so it remains available during an outage.

PostgreSQL is the source of truth. Redis queues/rate-limit entries are transient operational state. Neo4j and OpenSearch are experimental derived stores; if a deployment chooses to depend on them, it must define separate backup and rebuild procedures because the repository does not provide a complete reconciliation command.

## PostgreSQL backup and restore

Use provider-native snapshots plus logical backups where practical. Encrypt backups, restrict access, separate backup credentials from application credentials, and test restores on a schedule.

Example logical backup:

```bash
pg_dump --format=custom --no-owner --no-acl --file agent_sentinel.dump "$DATABASE_URL"
pg_restore --list agent_sentinel.dump
```

Restore into a new, empty database first:

```bash
createdb agent_sentinel_restore_test
pg_restore --exit-on-error --no-owner --no-acl --dbname agent_sentinel_restore_test agent_sentinel.dump
```

Point a restricted validation process at the restored database and verify:

```bash
cd backend
DATABASE_URL=postgresql+psycopg://<user>:<password>@<host>/agent_sentinel_restore_test alembic current --check-heads
```

Also verify representative organization, agent, telemetry, incident, audit, refresh-session, and outbox counts; foreign-key integrity; newest/oldest timestamps; and a tenant-scoped read workflow. Do not reconnect production traffic until the target revision and data checks are understood.

For an actual restore, stop writers, preserve the failed database for investigation, restore to a replacement instance, validate it, rotate database credentials if compromise is suspected, update the secret/reference atomically, then reopen traffic gradually. Record the achieved recovery point and recovery time.

## Migration deployment and rollback

Before migration:

1. Read the migration and its downgrade function. Identify locks, table rewrites, destructive operations, backfills, and application compatibility.
2. Take and verify a backup. Test the exact migration against a recent production-like restore.
3. Run `alembic current`, `alembic heads`, and `alembic upgrade head --sql` from `backend/` with the intended environment.
4. Stop or drain writers when the migration is not backward compatible.
5. Run `alembic upgrade head` once, then `alembic current --check-heads` and application smoke tests.

Prefer a forward fix after a release reaches production. Use `alembic downgrade <revision>` only when its downgrade has been reviewed and tested and the running application is compatible with the old schema. A downgrade cannot recover data discarded by a destructive upgrade; restore the verified backup instead.

Do not edit the `alembic_version` table manually, run migrations concurrently from API replicas, or combine schema rollback with unreviewed application rollback. Preserve migration logs and timestamps as incident evidence.

## Key rotation

### Agent API key

An organization owner/admin calls `POST /api/v1/agents/{agent_id}/rotate-key` using a human session. Store the returned key immediately in the agent's secret manager, deploy it, and verify telemetry/enforcement before the five-minute old-key grace period ends. Then confirm the old key receives 401. For suspected compromise, call `POST /api/v1/agents/{agent_id}/revoke-key` first and keep the agent disabled until a reviewed re-provisioning path is ready.

### JWT signing secret

Only one symmetric signing secret is supported. Rotating `JWT_SECRET_KEY` invalidates all access and refresh JWT validation, so schedule a user sign-out event:

1. Announce/approve the session reset and stop new login traffic if consistency is required.
2. Generate and store the new secret version.
3. Deploy it atomically to every API replica and restart them.
4. Revoke or delete outstanding refresh-session records according to the incident/data-retention decision.
5. Require login again and monitor authentication errors.

Do not run replicas with different JWT secrets during the transition.

### API-key pepper

There is no dual-pepper verification. Changing `API_KEY_PEPPER` immediately makes every stored agent-key hash unverifiable. Use a maintenance window: deploy the new pepper consistently, have organization administrators rotate/re-provision every agent key under the new pepper, update each agent secret, and test it before reopening enforcement traffic. For a planned zero-downtime pepper rotation, implement and test dual-pepper support before attempting the change.

### Admin and OAuth credentials

Rotate `ADMIN_API_KEY` atomically across every process that consumes it and remove the prior secret version. Rotate `GOOGLE_CLIENT_SECRET` in Google Cloud, update the secret manager, deploy, test the full state/PKCE login flow, and revoke the old provider credential. Provider revocation is the first step after suspected exposure.

## Security incident operations

### Triage

1. Assign an incident commander and start an external incident log with UTC timestamps.
2. Record affected environment, organizations, agents, users, release commit, Alembic revision, request IDs, and suspected exposure window.
3. Classify whether the event is an agent action, credential compromise, cross-tenant exposure, service compromise, dependency outage, or false positive.
4. Preserve relevant API/edge/database/worker logs and snapshots. Restrict evidence access and hash exported files.

### Containment

- Revoke affected agent keys and suspend agents through application controls where available.
- Revoke user sessions or rotate the JWT secret for broad session compromise.
- Disable open registration/OAuth login if identity abuse is suspected.
- Restrict ingress/egress and isolate affected workloads or data stores at the infrastructure layer.
- Do not rely on sandbox profiles or response recommendations to perform external containment; they are not runtime controls.
- Prefer narrowly scoped containment. Record every credential, route, organization, and time range affected.

### Investigation and recovery

- Verify audit and attestation hash chains with independent tooling before treating them as reliable evidence; the repository does not yet ship a supported verifier.
- Query primary SQL records by organization and request/session/action identifiers. Treat experimental secondary stores as potentially incomplete.
- Identify enforcement bypasses, stale keys, refresh-session reuse, unusual 401/403/5xx patterns, outbox backlog, and data exports.
- Patch or reconfigure in an isolated environment, run the full CI/test suite, restore or migrate data as required, rotate exposed credentials, and reopen traffic gradually with enhanced monitoring.

### Closure

Document root cause, timeline, affected tenants/data, decisions, evidence, recovery measurements, notification obligations, and corrective owners/dates. Add regression tests for the exact failure and rehearse the revised procedure. Do not close solely because alerts stopped.

## Routine drills

At a defined cadence, restore a backup, rotate one agent key, test agent revocation, test refresh-token replay rejection, exercise Redis failure behavior, run a migration round-trip on a clone, verify cross-tenant denial, and conduct a tabletop incident. Record results and missed recovery objectives as tracked work.
