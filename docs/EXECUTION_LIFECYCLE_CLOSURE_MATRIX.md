# Execution Lifecycle Closure Matrix

Status: OPEN — the Section B implementation rework has current local evidence,
but independent acceptance and several platform/runtime gates remain incomplete.

This matrix is the authoritative implementation checklist for the execution-
lifecycle hardening work. It supplements Contracts 04 and 08; it does not
weaken or replace their requirements. A row is complete only when the listed
implementation invariant and evidence both exist in the repository and have
been independently reviewed.

## Scope and non-negotiable invariants

- Every scan-reachable external process launch is bound to the durable,
  tenant-scoped execution run that authorized it. A legacy scan identifier,
  ambient context, optional argument, or registry absence is not an authority
  substitute.
- Native/in-process work, governed external work, and unknown/restart state
  are explicit states. `NOT_FOUND` is never a no-process proof by itself.
- One execution run owns one OS-level process container, or an equivalently
  complete set of process identities whose registration, termination, and
  emptiness confirmation are atomic with the run lifecycle.
- Process termination and durable terminal settlement have one coordinator.
  No caller may publish a terminal state before the coordinator confirms all
  process and task obligations.
- Authority-loss recovery is durable, retryable, bounded, tenant-scoped,
  auditable, and operator-visible. In-memory status is supplemental only.
- Installation and capability-observation processes are explicitly classified
  as non-scan operations and cannot be mistaken for scan-owned processes.

## Gap matrix

| Area | Required implementation outcome | Required evidence | Current status |
| --- | --- | --- | --- |
| Typed durable identity | A typed execution context binds `execution_id`, organization, worker, approved decision, target seal, operation policy, and exact command. Governed launch APIs reject missing or mismatched context. | Unit and integration tests for missing context, cross-tenant context, explicit-ID mismatch, and command/decision mismatch. Static inventory of scan-reachable process calls. | OPEN |
| Complete launch coverage | Capability discovery, adapters, direct helpers, and child tasks either receive the same governed context or are explicitly non-scan operations with a separate capability. | Call-site inventory, CI enforcement test, and cancellation test during discovery and each engine family. | OPEN |
| Run-level process ownership | A run cannot overwrite an earlier member. POSIX uses a bounded post-Popen stabilization handshake followed by a fresh complete member-identity snapshot with PID, PGID, SID, and start-token checks; root-exit recovery is allowed only when the attested snapshot remains exact and the final container-emptiness proof succeeds, otherwise it is recovery-blocked. A committed governed row is downgraded atomically to `RECOVERY_BLOCKED` without rebuilding its identity. Windows governed execution is explicitly fail-closed until a real Job Object or equivalent kernel-owned container exists. Non-scan launches remain separately classified and cannot authorize or terminalize scans; unconfirmed Windows termination remains uncertain. Termination confirms container emptiness. | POSIX production-path late-descendant, root-exit/multi-child positive recovery tests; fresh member-identity and membership-race negative tests; committed-to-recovery database transition, tamper, replay, and concurrency tests; explicit Windows recovery fail-closed test; platform-specific non-scan uncertainty handling; future Windows Job Object evidence remains required before Windows assurance. | OPEN |
| Durable restart attachment | Launch identity and worker ownership needed for recovery are durably recorded without storing a raw PID as authority. A restarted worker must attach only after independent identity and tenant validation. Valid complete attestations remain attached for `LAUNCH_UNCERTAIN` and `RECOVERY_BLOCKED`; incomplete or tampered identity remains blocked. A post-commit recovery primitive preserves the committed launch state and consumes the persisted attestation. | Restart test with a surviving child/group, valid uncertain/recovery loader states, production-path governed-to-recovery transition, invalid worker generation, PID/PGID/SID reuse, incomplete/tampered attestation, concurrency/replay, and operator-visible recovery escalation. | OPEN |
| Single cancellation coordinator | One coordinator owns cancellation request, task shutdown, process termination, authority revocation, and terminal settlement. Async cancellation cannot race a background execution thread. | Ignored-cancellation, timeout, duplicate-request, revocation-vs-finish, and exact idempotence tests. | OPEN |
| Durable recovery | Recovery attempts, status, bounded retry/backoff, next attempt, and escalation are persisted by execution ID and organization. Timed-out work cannot silently mutate after lifecycle shutdown. | SQLite clean-database tests and PostgreSQL row-lock/concurrency tests; health/audit endpoint evidence. | OPEN |
| Contract and operational proof | Contracts 04/08 and traceability documentation describe the same state machine, platform threat model, and evidence boundary. Protected migration failures remain fail-closed and require operator reconciliation. | Contract consistency tests, clean tree, synchronized remote, CI results, runtime evidence, and auditor acceptance. | OPEN |

## Required state model

The implementation MUST distinguish these states at the run/process boundary:

- `NO_EXTERNAL_PROCESS`: an explicit durable record proves that no external
  process was created for the run.
- `EXTERNAL_PROCESS_GOVERNED`: a durable launch handshake records the owned
  process container and its verified identity.
- `LAUNCH_UNCERTAIN`: process creation may have occurred and a complete
  durable identity/attestation was captured, but the launch or termination
  handshake is unresolved; the run is not terminalizable.
- `RECOVERY_BLOCKED`: authority was lost, termination was not confirmed, or
  the post-launch identity is incomplete/invalid; retry and escalation are
  required, and no attestation may be fabricated.
- `TERMINAL`: the coordinator has confirmed task/process obligations and
  durably settled the run and dispatch records.

`NOT_FOUND`, a null PID, a stopped task, or a missing in-memory mapping MUST
NOT be translated to `NO_EXTERNAL_PROCESS` without the corresponding durable
proof.

## Section B implementation checkpoint (not acceptance)

The current candidate closes the production handoff and durable settlement
gaps identified by the independent auditor, while deliberately leaving the
matrix open for independent acceptance. The current working-tree closure
candidate also makes authoritative queue quarantine state and its original
sanitized failure evidence one integrity-bound record; it does not treat an
expiring operational marker or a stream entry alone as the safety state.

The production Redis worker in `run_worker.py` now calls only the public
`ScanOrchestrator.execute_dispatched_scan()` handoff after message
consumption. The handoff reloads the tenant, parent authorization, selected
operation, child request/decision/run, dispatch, session, expiry, token
revocation, worker identity/generation, and snapshot-completeness bindings
before entering the local bounded executor. A revoked, expired, consumed,
cross-tenant, incomplete, or otherwise mismatched child is rejected before
native or external scan work begins.

The worker-owned lifecycle now has explicit durable no-process and exact
process-identity paths. `ProcessSupervisor` claims the durable execution
authority before governed validation and process creation, records explicit
`NO_EXTERNAL_PROCESS` evidence for pre-`Popen` rejection/cancellation, and
keeps the worker thread responsible for late settlement after caller
cancellation. POSIX completion checks now require both the owned process group
and captured session to be empty. The post-`Popen` launch handshake waits for
a bounded stable complete member snapshot before persisting the attestation,
so startup descendants created after the first identity sample are included;
failure to settle remains `LAUNCH_UNCERTAIN`. Cancellation and observation
recovery use the persisted `ProcessIdentity`; a missing in-memory mapping or
a raw PID is not sufficient.
If the launch row has already committed as `EXTERNAL_PROCESS_GOVERNED`, a
post-launch termination or ownership failure uses a dedicated atomic database
transition to `RECOVERY_BLOCKED`. That transition verifies the durable tenant,
worker, generation, correlation, and attestation fences, changes only the
ownership state and timestamp, and ignores caller-supplied replacement
identity. `record_launch_uncertain()` performs no stale ownership pre-read: the
database lock re-evaluates the current state, and a concurrent committed row is
handled by the dedicated downgrade primitive. Complete post-launch identity is
persisted as `LAUNCH_UNCERTAIN`; incomplete or invalid identity is persisted as
`RECOVERY_BLOCKED`. `settle_recovery_execution()` accepts either uncertain state
only after a separate recovery lease owner/token/generation and
supervisor-confirmed termination. The original process worker identity and
generation remain the immutable process proof and are not required to equal the
recovery coordinator identity.
When a committed governed process is still externally owned but its exact
identity-bound cancellation is unconfirmed, the observer records a durable
`DEFERRED` or bounded `EXHAUSTED` recovery outcome, immutable attempt evidence,
the bounded error/outcome, and (when retryable) `next_retry_at`. The ownership
state remains `EXTERNAL_PROCESS_GOVERNED`; candidate enumeration suppresses
in-progress, exhausted, and not-yet-due deferred work. A later exact
supervisor-confirmed result uses the post-revocation settlement fence and may
terminalize only after the persisted identity and original worker binding are
revalidated.
`DatabaseManager.settle_execution_after_confirmed_termination()` performs the
post-revocation transition only after authority invalidity, tenant, identity,
dispatch, run, and recovery fences have all been validated. SQLite and
PostgreSQL execute the durable mutation within their existing transaction
boundaries; no schema or migration change is part of this checkpoint. Terminal
replay remains gated by the complete durable proof tuple: terminal run and
dispatch projections, tenant/worker bindings, process ownership proof,
recovery projection and latest confirmed attempt where applicable, and both
claim digests. Missing or inconsistent inputs fail closed before executor
entry.

The observation/reaper path does not infer a process from positive
`NO_EXTERNAL_PROCESS` evidence and defers `STARTING`/`UNKNOWN` ownership when
the persisted identity cannot be reloaded. The launch inventory and worker
runtime tests exercise the actual worker entry point and reject direct private
executor bypasses. These are implementation claims only; the acceptance gate
still requires the evidence listed below and independent auditor review.

Authoritative Redis execution messages now carry an explicit
`AUTHORITATIVE_EXECUTION` classification; diagnostic compatibility messages
must carry `LEGACY_DIAGNOSTIC`. Missing, malformed, conflicting, credential-
credential-bearing, or otherwise unsupported wire fields are rejected before
handler entry and cannot enter an implicit legacy acknowledgement path. The presence
of a credential field is rejected for every legacy diagnostic value, including
empty or malformed values; credential handoffs require the complete
authoritative authorization request and typed binding and are never downgraded
to a legacy diagnostic message. Quarantine
evidence is an exact allowlisted representation with a failure digest and a
top-level quarantine-state digest. State publication, failure-event
publication, and any explicit acknowledgement are fail-closed durable Redis
transactions; acknowledgement uses a compare-and-swap Lua transaction that
checks the exact state and requires a successful `XACK` before deleting the
quarantine state. The queue primitive accepts only a typed tenant-bound
operator assertion; it does not authenticate arbitrary actor strings. The
quarantine acknowledgement API uses the existing bearer/JWT, role, scope,
tenant, and durable-revocation boundary to issue that internal capability;
the opaque in-process handoff is not a second authentication system and its
session binding is not independently enforced by the queue state comparison.
Route-level replay and concurrency vectors are covered separately.

Current implementation files are limited to the audited execution boundary:
`backend/app/core/db.py`, `backend/app/core/execution_service.py`,
`backend/app/core/observation_service.py`, `backend/app/core/orchestrator.py`,
`backend/app/core/process_supervisor.py`, `backend/app/core/auth.py`,
`run_worker.py`, and the execution identity/lifecycle invariant in
`docker-compose.yml`, plus the authoritative
queue quarantine implementation in `backend/app/core/queue.py`, with the
corresponding launch, authority, cancellation, observation, process, and
orchestrator, queue, and replay tests. Contracts, migrations, `AGENTS.md`, the protected
database, `.ci/`, and `.project-temp/` are not part of this rework.

The required acceptance evidence is now recorded in the dated Section B
addendum. The matrix remains open because the worker-generation deployment
binding, independent live Redis/PostgreSQL evidence for the current candidate,
broader OS-level PID-reuse/membership-race evidence, Windows kernel-container
implementation (or Windows assurance approval of the current fail-closed
state), Redis 7-compatible live transport execution, managed-tool runtime
evidence, and independent auditor acceptance are not all closed by local
tests. The local Redis attempt reached a real Redis 5.0.14.1 service but was
not counted because `XAUTOCLAIM` is unavailable there; the supported CI
service remains Redis 7.

## Acceptance gate

The lifecycle section is accepted only when every row is marked complete with
repository evidence, focused tests execute successfully on a clean supported
database, PostgreSQL concurrency coverage is recorded, the protected shared
database has not been altered, and the independent auditor confirms that no
contract requirement remains open. Until then, the overall lifecycle status
remains `REWORK / IN PROGRESS`.
