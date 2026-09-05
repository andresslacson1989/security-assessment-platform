# Execution Lifecycle Foundation Plan

Status: DESIGN BASELINE — implementation not yet complete.

This plan is the implementation contract for the next coherent lifecycle
section. It is subordinate to Contracts 01, 03, 04, 08, and 09 and is linked
to `docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`. It deliberately does not
repair, rewrite, or reinterpret an existing migration ledger. Migration v10
must execute only after the registered v1–v9 history passes its existing
fail-closed verification.

## 1. Current evidence and boundary

The current repository has:

- durable requests, decisions, runs, and dispatch intents;
- canonical execution/result states and state-aware reason codes;
- process IDs and process-group IDs on `execution_runs`;
- in-memory supervisor mappings and partial POSIX identity evidence;
- an orchestrator path that is not transactionally linked to an approved
  durable execution run;
- installer/observation subprocesses that are not scan-owned;
- no durable process-ownership record, launch-uncertain state, recovery attempt
  record, retry schedule, worker-generation attachment, or operator escalation.

The next implementation MUST preserve this distinction:

```text
canonical execution state       separate process-ownership state
REQUESTED / STARTING / ...      NO_EXTERNAL_PROCESS / ...
```

Process-ownership values MUST NOT replace canonical execution states, result
states, or assurance states in database rows, API responses, SSE events, or
audit records.

## 2. Migration v10 foundation

Register one migration after the current v9 entry in
`backend/app/core/migration_registry.py`:

- migration ID: `execution-process-ownership-and-recovery`;
- previous version: `9`;
- target schema version: `10`;
- SQLite and PostgreSQL apply artifacts, manifests, checksums, verifiers, and
  registry checksums must be generated and checked in using the existing
  migration-artifact workflow;
- the forward migration must preflight duplicate, orphaned, cross-tenant, and
  ambiguous execution rows and fail closed;
- existing rows must not be silently classified as no-process or governed;
  legacy rows receive an explicit `UNKNOWN`/reconciliation-required outcome
  until an operator-approved migration policy establishes their state;
- SQLite and PostgreSQL verifiers must enforce equivalent composite tenant
  constraints, nullability, indexes, and allowed-value checks.

### 2.1 `execution_process_ownership`

Create one row per durable execution run with:

- `execution_id` and `organization_id` as the tenant-bound composite key and
  foreign key to `execution_runs`;
- `ownership_state` with exactly `UNKNOWN`, `NO_EXTERNAL_PROCESS`,
  `EXTERNAL_PROCESS_GOVERNED`, `LAUNCH_UNCERTAIN`, `RECOVERY_BLOCKED`, or
  `TERMINAL`;
- `container_type` with exactly `POSIX_SESSION`, `WINDOWS_JOB`,
  `PROCESS_SET`, or `NONE`;
- `container_identity` containing an opaque, non-secret, platform-specific
  identity reference; raw PID alone is not an identity;
- `root_process_id` and `root_process_start_token`, both nullable diagnostic
  fields that never authorize termination independently;
- `process_group_id`, `session_id`, and `worker_generation`, nullable only
  where the selected platform/container does not provide that field;
- `launch_commit_state` with `NOT_ATTEMPTED`, `COMMITTED`, or `UNCERTAIN`;
- `no_process_proof` and `identity_attestation` as sanitized structured JSON
  or equivalent immutable digests, with no credentials or command secrets;
- `created_at`, `launched_at`, `last_verified_at`, `terminalized_at`, and
  `updated_at` timestamps;
- correlation and audit references sufficient to join every transition to the
  execution run and tenant.

The table MUST enforce one ownership row per `(execution_id,
organization_id)`. Ownership transitions MUST be performed in the same
transactional authority/dispatch lock order as execution settlement.

### 2.2 `execution_recovery_attempts`

Create append-only recovery-attempt evidence with:

- a generated attempt ID;
- `execution_id`, `organization_id`, and correlation ID;
- worker identity and worker generation;
- attempt number with a database check for non-negative values;
- `status` from `REQUESTED`, `IN_PROGRESS`, `CONFIRMED_TERMINATED`,
  `DEFERRED`, `FAILED`, `ESCALATED`, or `EXHAUSTED`;
- typed cancellation status and canonical reason code;
- `requested_at`, `started_at`, `completed_at`, and `next_retry_at`;
- bounded `error_code`/sanitized diagnostic fields;
- escalation level and operator-visible health reference;
- uniqueness/single-flight protection for one active attempt per execution and
  worker ownership rules for cross-worker recovery.

Recovery attempts are evidence, not a replacement for the canonical run
state. They MUST be tenant constrained, append-only or immutably versioned,
and auditable.

## 3. Typed authoritative execution context

Add `backend/app/core/execution_context.py` with a frozen, extra-forbidden
typed context. It MUST contain:

- durable `execution_id` and `request_id`;
- `organization_id`, `project_id`, `asset_id`, `target_id`;
- approved decision ID and request fingerprint;
- target policy version and operation-policy revision;
- tool ID, operation family, canonical operation options digest, and exact
  command digest;
- worker identity and worker generation/lease identity;
- approval/session binding, expiry, revocation check reference;
- resource and account-impact budgets;
- credential scope digest and provider boundary, never credential values;
- correlation ID and audit context;
- an issued authority token object that cannot be constructed by a caller.

The context constructor MUST be verifier-issued from the durable approved
decision. Callers MUST NOT construct a governed context from a scan ID,
request body, environment variable, or arbitrary string. Validation MUST
reject missing, stale, revoked, cross-tenant, cross-project, target-mismatched,
policy-mismatched, command-mismatched, and worker-mismatched contexts.

`ContextVar` may carry a validated context inside one synchronous/asynchronous
call tree for convenience, but it MUST NOT issue authority, replace explicit
context parameters at the governed process boundary, or survive as the sole
binding across child tasks or worker restarts.

## 4. Governed and non-scan process APIs

Update these files as one interface change:

- `backend/app/core/process_supervisor.py`: governed launch accepts the typed
  context and a run-level container handle; terminal confirmation is returned
  only for the matching container. A PID-only function is diagnostic-only and
  cannot settle a durable execution.
- `backend/app/core/binary_resolver.py`: `safe_execute_subprocess` requires
  the governed context for scan-reachable execution and forwards it unchanged.
- `backend/app/adapters/base_adapter.py`: `execute_command` requires or
  receives the explicit validated context; it rejects an explicit ID that
  differs from the validated context and does not use ambient state as
  authority.
- `backend/app/engines/base.py` and each engine entry point: carry the typed
  context explicitly; child tasks inherit a run supervisor handle, not a raw
  string.
- `backend/app/core/orchestrator.py`: obtain the durable execution run from
  the execution service and never equate `ScanJob.id` with `execution_id`
  without a durable binding.
- installer and observation modules: use a separate immutable
  `NonScanProcessCapability` that contains operation purpose, worker identity,
  installation/observation scope, expiry, and a prohibition on scan
  terminalization. It cannot satisfy a governed scan context.

Every scan-reachable call to `process_supervisor.execute`,
`safe_execute_subprocess`, or `execute_command` MUST be enumerated and either
pass the governed context or be rejected by the static enforcement test.

## 5. Launch handshake and state transitions

The execution service MUST perform the following transactionally:

1. lock and revalidate the request, decision, tenant, target seal, expiry,
   revocation, worker lease, budgets, and policy;
2. create/update the ownership row as `UNKNOWN` and
   `launch_commit_state=NOT_ATTEMPTED`;
3. create the platform-owned container before process creation;
4. launch the process inside that container and capture its platform identity;
5. persist the identity and atomically commit `EXTERNAL_PROCESS_GOVERNED`
   before reporting `RUNNING`;
6. if no external process is selected, persist a verifier-backed
   `NO_EXTERNAL_PROCESS` proof before the run can use no-process cancellation;
7. if any step after process creation cannot be committed or verified, persist
   `LAUNCH_UNCERTAIN`/`RECOVERY_BLOCKED` and do not terminalize the run.

Normal completion MUST verify container emptiness before ownership becomes
`TERMINAL`. A root exit with descendants remaining is not completion.

## 6. Cancellation and recovery coordinator

Add or designate one execution-service coordinator responsible for:

- creating a durable cancellation/revocation request;
- acquiring the execution authority/recovery single-flight lease;
- asking the run container supervisor to terminate;
- awaiting the task owner and all bounded supervisor operations;
- writing recovery attempt evidence and retry/backoff/escalation;
- atomically settling dispatch and run with final revocation/expiry predicates,
  worker/process identity checks, and canonical state/reason validation.

No API route, orchestrator callback, engine, or outer asyncio cancellation
handler may independently write a terminal execution state. A timeout or
detached database thread MUST remain tracked and MUST NOT perform an
unobserved late mutation after shutdown.

## 7. Acceptance evidence required before implementation closure

- migration v10 clean SQLite apply/verify on a fresh database;
- migration v10 PostgreSQL apply/verify and row-lock concurrency tests;
- static inventory proving every scan-reachable subprocess call is classified;
- typed-context negative tests for every binding listed above;
- POSIX process-container tests for normal exit, root exit with descendants,
  multiple children, PID reuse, identity failure, and restart attachment;
- Windows Job Object tests for root exit, descendant survival, job emptiness,
  handle ownership, and reuse safety;
- one-coordinator tests for async cancellation, ignored task cancellation,
  revocation-vs-finish ordering, duplicate settlement, and shutdown;
- recovery retry/backoff/escalation and operator-health tests;
- full regression on a clean supported database;
- protected shared database remains untouched when its migration identity is
  inconsistent;
- exact CI status, runtime evidence, and auditor approval mapped row-by-row to
  `docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`.

Until all evidence exists, the matrix and this plan remain OPEN and the
implementation MUST NOT be described as contract-complete.
