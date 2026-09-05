# Execution Lifecycle Closure Matrix

Status: OPEN — implementation and independent acceptance are incomplete.

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
| Run-level process ownership | A run cannot overwrite an earlier member. POSIX uses a verified launch session/process container; Windows uses a Job Object or equivalent kernel-owned container. Termination confirms container emptiness. | POSIX root-exit/descendant and multi-child tests; Windows Job Object tests; PID reuse and membership-race tests. | OPEN |
| Durable restart attachment | Launch identity and worker ownership needed for recovery are durably recorded without storing a raw PID as authority. A restarted worker must attach only after independent identity and tenant validation. | Restart test with a surviving child/group, invalid worker generation, PID reuse, and operator-visible recovery escalation. | OPEN |
| Single cancellation coordinator | One coordinator owns cancellation request, task shutdown, process termination, authority revocation, and terminal settlement. Async cancellation cannot race a background execution thread. | Ignored-cancellation, timeout, duplicate-request, revocation-vs-finish, and exact idempotence tests. | OPEN |
| Durable recovery | Recovery attempts, status, bounded retry/backoff, next attempt, and escalation are persisted by execution ID and organization. Timed-out work cannot silently mutate after lifecycle shutdown. | SQLite clean-database tests and PostgreSQL row-lock/concurrency tests; health/audit endpoint evidence. | OPEN |
| Contract and operational proof | Contracts 04/08 and traceability documentation describe the same state machine, platform threat model, and evidence boundary. Protected migration failures remain fail-closed and require operator reconciliation. | Contract consistency tests, clean tree, synchronized remote, CI results, runtime evidence, and auditor acceptance. | OPEN |

## Required state model

The implementation MUST distinguish these states at the run/process boundary:

- `NO_EXTERNAL_PROCESS`: an explicit durable record proves that no external
  process was created for the run.
- `EXTERNAL_PROCESS_GOVERNED`: a durable launch handshake records the owned
  process container and its verified identity.
- `LAUNCH_UNCERTAIN`: process creation may have occurred but the durable
  handshake or identity proof is incomplete; the run is not terminalizable.
- `RECOVERY_BLOCKED`: authority was lost or termination was not confirmed;
  retry and escalation are required.
- `TERMINAL`: the coordinator has confirmed task/process obligations and
  durably settled the run and dispatch records.

`NOT_FOUND`, a null PID, a stopped task, or a missing in-memory mapping MUST
NOT be translated to `NO_EXTERNAL_PROCESS` without the corresponding durable
proof.

## Acceptance gate

The lifecycle section is accepted only when every row is marked complete with
repository evidence, focused tests execute successfully on a clean supported
database, PostgreSQL concurrency coverage is recorded, the protected shared
database has not been altered, and the independent auditor confirms that no
contract requirement remains open. Until then, the overall lifecycle status
remains `REWORK / IN PROGRESS`.
