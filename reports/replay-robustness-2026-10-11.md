# Agentyc runtime replay robustness review

**Review date:** 2026-10-11  
**Scope:** in-process replay and telemetry handling only  
**Network:** none; socket/DNS/process audit guards were installed and no target blocked event was observed  
**Production changes:** none; only the bounded audit harness and reports were added

## Executive summary

The replay feature is a data-return path rather than a tool-execution engine. A
telemetry envelope is validated, its `payload` is stored as SQL JSON, and the
replay endpoints read rows and serialize them through response models. The
replay functions do not dispatch tool calls, invoke the SDK, run shell
commands, or call the integration workers.

The source review found two high-priority defensive gaps:

1. Trace payloads are accepted as arbitrary nested `dict[str, Any]` values and
   are stored and returned without secret redaction.
2. There is no application-level size, nesting, node, or response cap for
   telemetry payloads. Deep or very large JSON can therefore consume parser,
   validation, database-serialization, and response resources.

The required 2,000-case run completed against the locked backend runtime in a
fresh in-memory SQLite database. It found secret disclosures, deep-input
parser/serialization failures, and response-validation failures for corrupt
stored rows. The exact run is recorded in
`reports/trace-robustness-results.txt`; `--fail-on-findings` returned 1 as
designed. No package installation or network access was used during the
runtime run.

## Replay path map

| Stage | Implementation | Robustness boundary |
| --- | --- | --- |
| Trace envelope | `backend/app/schemas.py:198-206` (`TelemetryEventCreate`) | UUID, short session/event strings, literal severity, and score ranges are constrained. `payload` is only constrained to be a mapping; nested values and their sizes are unrestricted. |
| Capture route | `backend/app/api/routers/telemetry.py:24-74` (`create_event`) | Pydantic validation happens before the route. The route copies the validated model into `TelemetryEvent`, updates the behavior baseline, queues an outbox record, and flushes/commits. No sanitizer is called. |
| Capture-time interpretation | `backend/app/services/behavior.py:16-53` (`update_behavior_baseline`) | The payload is read as data for the `tool_name`, `action`, and `resource` baseline fields and anomaly score. These values are converted to strings and compared; they are not dispatched as operations. |
| SQL storage | `backend/app/models.py:202-226` (`TelemetryEvent`) | `payload` is a SQLAlchemy `JSON` column. The database is the serialization boundary; it does not enforce a recursive shape, depth, or byte budget. |
| Incident storage | `backend/app/models.py:229-278` (`Incident`) | `evidence` is a JSON mapping and `response_actions` is a JSON list at the ORM type level, but existing rows can still contain JSON values of the wrong shape. |
| Read serialization | `backend/app/schemas.py:209-221` (`TelemetryEventRead`) and `:254-268` (`IncidentRead`) | Response validation expects a mapping for payload/evidence and a list of strings for response actions. A corrupt persisted value can become an unhandled response-validation error. |
| Incident replay | `backend/app/api/routers/incidents.py:154-172` (`replay_incident`) | Tenant-scoped `SELECT` operations build an incident object and timeline. It does not interpret payload fields. |
| Session replay | `backend/app/api/routers/incidents.py:176-186` (`replay_session`) | Tenant-scoped, ordered `SELECT` over a session. It does not interpret payload fields or execute them. |
| SDK capture | `sdk/python/agent_sentinel/client.py:29-78` (`_request`/`record_event`) | `json.dumps` sends the caller's payload as supplied. There is no client-side redaction before transmission. |
| UI replay | `frontend/src/pages/Replay.tsx:46-110` | The UI renders incident metadata and timeline data. The review found no replay-to-tool dispatch in this path. |

At capture time, `create_event` queues `telemetry.created` through
`backend/app/services/outbox.py:10-27`. The worker code in
`backend/app/tasks.py:350-425` can later send that outbox event to optional
OpenSearch/Neo4j integrations. That is a capture-time asynchronous delivery
boundary, not an action performed by either replay endpoint; the audit did not
start workers or integrations.

## Test design and bounded run

`scripts/trace-robustness.py` generates a fixed seed corpus plus deterministic
mutations. It covers:

- empty, truncated, invalid-UTF-8, inserted-byte, and trailing-data JSON;
- unknown envelope fields and nested extra fields;
- null, array, scalar, boolean, invalid UUID/session, non-finite-number, and
  surrogate values;
- nesting depths 32, 128, 256, 512, 900, and 1,100;
- 4 KiB, 256 KiB, and 512 KiB strings plus wide arrays;
- escaped Unicode/control characters and duplicate object keys;
- secret-shaped payloads and tool-call-shaped shell/HTTP arguments;
- malformed legacy telemetry, incident evidence/actions, and raw stored JSON.

The run was capped at 2,000 cases, 1 MiB per raw candidate, 1,500 nesting
levels, 30,000 parsed nodes, 512 MiB address space, 30 CPU seconds, 60 wall
seconds, and 250 ms per case. Cases are rollback-only against a fresh
`sqlite://` database when dependencies are present. Mutation artifacts are
written only under `/tmp/omnirush`.

The runtime produced 1,204 capture/legacy-storage successes, 575 malformed
JSON rejections, and 165 schema rejections. It also recorded 28 JSON parser
recursion failures, 9 deep-response serialization failures, and 34 unpaired
surrogate response/validation failures. Corrupt stored rows produced 271
incident and 150 session payload type failures, plus 104 incident action-list
failures and 26 nested action-string failures. The corpus exercised every
requested mutation family; duplicate-key accounting observed two duplicate
members in the seed duplicate-key case.

## Findings

### R-001 — High — secrets are persisted and replayed without redaction

**Evidence:** `TelemetryEventCreate.payload` accepts arbitrary values at
`backend/app/schemas.py:204`; `create_event` stores `payload.model_dump()` at
`backend/app/api/routers/telemetry.py:24-74`; `TelemetryEvent.payload` is JSON at
`backend/app/models.py:216`; replay returns it through
`TelemetryEventRead` at `backend/app/schemas.py:209-221`. The SDK serializes the
same caller-provided mapping directly at
`sdk/python/agent_sentinel/client.py:49-78`. No capture/replay sanitizer was
found for API keys, bearer tokens, passwords, authorization headers, or
secret-like nested values.

**Dynamic confirmation:** synthetic canaries appeared in 180 capture-storage
observations, 180 capture responses, 48 validation-error responses, 238
incident replay responses, 218 session replay responses, and the SDK wire
payload. The SDK control explicitly reported
`sdk_serialization_preserves_synthetic_secrets: True`.

**Impact:** A trace containing a credential remains in SQL, API responses,
streaming output, replay views, and any downstream outbox indexing performed by
workers. The replay boundary is tenant-scoped, but tenant scoping is not
redaction.

**Suggested fix:** Add one reviewed, recursive redaction/normalization policy
at the capture boundary and apply it before behavior analysis, SQL storage, and
all response/indexing paths. Match case-insensitive secret key names and common
credential formats, preserve only an explicit safe representation where
needed, and ensure validation errors never echo secret input. Add regression
cases for nested mappings, lists, duplicate keys, and error responses.

`# AUDIT-FIX backend/app/schemas.py:204-206; backend/app/api/routers/telemetry.py:24-74; sdk/python/agent_sentinel/client.py:49-78`

### R-002 — High — unbounded payload depth and size permit resource exhaustion

**Evidence:** The only capture limits visible in
`backend/app/schemas.py:198-206` apply to envelope strings, scores, and the
top-level payload type. The nested payload has no byte, string, array, object,
depth, or node limit. `backend/app/models.py:216` stores the complete JSON and
`backend/app/api/routers/incidents.py:124-186` returns complete timelines. The
streaming route also serializes full event payloads in
`backend/app/api/routers/streaming.py:18-48`.

**Impact:** Large strings and wide arrays increase request parsing, Pydantic,
SQL serialization, and response memory. Deep nesting can trigger Python JSON
recursion failures or disproportionate CPU before application validation. A
large session can produce an unbounded replay response even if each row is
individually acceptable.

**Dynamic confirmation:** depth-1,100 inputs produced 28
`json_parse/RecursionError` findings, and depth-256 inputs produced 9
`capture_response/ValueError` serialization findings. The target did not crash
the harness process, but it raised uncaught target exceptions that would be
HTTP-500 candidates.

**Suggested fix:** Enforce a request-body byte limit before JSON parsing; add a
recursive bounded validator/normalizer with independent limits for depth,
nodes, strings, arrays, and total serialized bytes; cap or paginate replay and
stream responses; and reject a session/timeline that exceeds a documented
budget. Keep the limits shared by HTTP capture, SDK capture, legacy import, and
replay serialization.

`# AUDIT-FIX backend/app/schemas.py:204-206; backend/app/api/routers/incidents.py:124-186; backend/app/api/routers/streaming.py:18-48`

### R-003 — Medium — corrupt persisted JSON can turn replay into an HTTP 500

**Evidence:** `IncidentRead` requires `evidence: dict[str, Any]` and
`response_actions: list[str]` at `backend/app/schemas.py:254-268`; telemetry
replay requires `payload: dict[str, Any]` at `:209-221`. The replay functions
construct these models directly at
`backend/app/api/routers/incidents.py:154-186`. Older or manually corrupted
JSON rows can legally exist at the SQL JSON serialization layer with a scalar,
null, or array in those columns. The route does not catch a response-model
validation error, quarantine the row, or return a controlled replay error.

**Impact:** One malformed row can make an incident/session replay unavailable
and can produce a server error rather than a clean, bounded diagnostic. The
read-only query does not partially mutate the database, but a failing response
can still cause repeated expensive retries.

**Dynamic confirmation:** replay recorded 271 incident and 150 session
`payload` dictionary validation failures, 104 incident `response_actions` list
failures, and 26 nested action string failures.

**Suggested fix:** Validate on write and at migration boundaries, then handle
legacy rows explicitly during replay: return a typed 4xx/5xx diagnostic with a
stable error code, skip/quarantine the bad event while preserving row identity,
and cap error details. Do not include raw malformed values or secrets in the
error body.

`# AUDIT-FIX backend/app/schemas.py:209-221; backend/app/schemas.py:254-268; backend/app/api/routers/incidents.py:154-186`

### R-004 — Medium — duplicate JSON keys are silently last-value-wins

**Evidence:** The trace path relies on the standard JSON decoder before
Pydantic validation, and no duplicate-key rejection/canonicalization is present
in the capture or replay path. Python's default object parser retains the last
member for a duplicate key. The audit corpus included top-level and nested
duplicates and counted two duplicate members in the seed case.

**Impact:** Different collectors, gateways, log pipelines, or forensic tools
can display a different value from the value persisted by the API. This is
especially risky for `tool_name`, `decision`, authorization metadata, and
secret fields.

**Suggested fix:** Reject duplicate keys at the first JSON boundary, or parse
with a duplicate-detecting hook and record a controlled validation error. Use a
single canonical parser for SDK, HTTP, import, and replay inputs.

`# AUDIT-FIX backend/app/schemas.py:198-206; backend/app/api/routers/telemetry.py:24-74`

### R-005 — Medium — unpaired Unicode surrogates cause response failures

**Evidence:** The trace decoder accepts escaped surrogate code points inside
the unconstrained `Any` payload. No recursive Unicode normalization or
validation is present before storage or response serialization.

**Impact:** An escaped `\\ud800` value reached the capture and replay response
paths and raised `UnicodeEncodeError`, turning a malformed-but-storable trace
into an HTTP-500 candidate.

**Dynamic confirmation:** the run recorded 19 capture response failures, one
capture validation-response failure, 8 incident replay failures, and 6 session
replay failures for this family.

**Suggested fix:** Reject or safely normalize unpaired surrogates at the shared
JSON boundary; use an explicit UTF-8-safe error response and ensure redaction
and diagnostics do not re-emit the invalid code point.

`# AUDIT-FIX backend/app/schemas.py:204-206; backend/app/schemas.py:209-221; backend/app/api/routers/incidents.py:154-186`

### R-006 — Low — non-standard numeric values lack an explicit policy

**Evidence:** `payload` is `Any`, while Python's JSON decoder accepts `NaN` and
`Infinity` by default. The replay response is serialized by FastAPI/Starlette
after the row is loaded. There is no explicit finite-number policy in the
telemetry schema.

**Impact:** A trace can be accepted or stored by one layer and fail later at
capture/replay response serialization, yielding an avoidable server error or
different representations across storage and clients.

**Dynamic result:** the three seed non-standard-number cases did not produce a
target failure in this run. They remain a policy gap because acceptance relies
on permissive Python JSON behavior rather than an explicit trace contract.

**Suggested fix:** Reject non-finite numbers recursively at capture and import;
use strict JSON serialization for all trace responses; and add a controlled
error path for legacy rows containing non-standard values.

`# AUDIT-FIX backend/app/schemas.py:204-206; backend/app/schemas.py:209-221`

## Malformed input and partial-state assessment

- Truncated and malformed request JSON is expected to be rejected before
  `create_event` runs, and the envelope schema rejects wrong top-level types.
  The bounded harness rejected 575 malformed candidates without
  attempting storage.
- Unknown envelope fields are ignored by the default Pydantic model behavior;
  nested payload fields remain data and are not executed.
- `create_event` performs its baseline/outbox work in the same SQLAlchemy
  session and rolls back its idempotency race on `IntegrityError`. Replay uses
  reads only. The dynamic rollback probe reported zero leftover telemetry rows,
  and the cross-tenant incident/session checks returned 404/empty results.
- Deep nesting, oversized fields, corrupt stored types, and non-finite values
  were exercised in the production dependency environment. The run recorded
  the parser, encoding, and response-model exceptions listed above.

## Side-effect assessment

**Result: no replay side-effect path was found in source review, and the
dynamic side-effect controls passed.**

`replay_incident` and `replay_session` perform tenant-filtered database reads
and response-model serialization. A payload such as
`{"tool_name":"shell.execute","arguments":{"command":"touch ..."}}`
is returned as data; no function in either replay route invokes a shell,
HTTP client, SDK method, MCP executor, Celery task, OpenSearch client, or Neo4j
driver. The harness contains process/socket audit guards and an SQL non-SELECT
guard for this invariant. The control probe passed with zero blocked network,
process, file-write, or replay-write attempts, and replay returned the
shell/HTTP-shaped arguments as data.

The separate capture-time outbox path is an intentional asynchronous side
effect boundary. It is not replay-triggered, but it should remain excluded from
any future replay implementation and should receive its own payload-redaction
and size limits before indexing.

## Remediation priority

1. **High:** implement recursive secret redaction and bounded payload
   normalization before storage and before every replay/index/stream response.
2. **High:** enforce HTTP/request, per-field, per-row, and per-replay resource
   budgets before parsing or materializing untrusted JSON.
3. **Medium:** add controlled handling/quarantine for corrupt persisted rows and
   reject duplicate/non-finite JSON values consistently.
4. **Verification:** keep the runtime branch in CI with the full 2,000-case
   budget and require the side-effect/rollback controls to pass.

No application or deployment code was changed during this review. The
`# AUDIT-FIX` markers above identify the larger production changes that should
be made in a separately scoped hardening change.
