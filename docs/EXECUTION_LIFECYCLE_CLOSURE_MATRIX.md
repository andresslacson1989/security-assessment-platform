# Execution Lifecycle Closure Matrix

Status: OPEN — the exact application/test source used for the current Section B
runtime and CI evidence is commit
`031cda1f93fd0e7cebf6ec50452da43dc7bf980f` on
`security/nmap-installer-closure`, with authoritative GitHub Actions evidence
in run `34685317236`. This document records that source's final evidence
publication; historical baseline and pre-publication candidate records remain
below. Independent auditor acceptance and the remaining lifecycle criteria are
still open.

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
| Run-level process ownership | A run cannot overwrite an earlier member. POSIX uses a bounded post-Popen stabilization handshake followed by a fresh complete member-identity snapshot with PID, PGID, SID, and start-token checks; root-exit recovery is allowed only when the attested snapshot remains exact and the final container-emptiness proof succeeds, otherwise it is recovery-blocked. A committed governed row is downgraded atomically to `RECOVERY_BLOCKED` without rebuilding its identity. Windows governed execution uses a native Job Object: the root is created suspended, atomically associated through `PROC_THREAD_ATTRIBUTE_JOB_LIST`, durably attested before resume, and governed by `KILL_ON_JOB_CLOSE`; live cancellation/recovery uses the exact process-local attested job, verifies every current member, and never falls back to a raw PID. Worker loss intentionally destroys the container and blocks durable reattachment; same-name recreation is not the original job. Non-scan launches remain separately classified and cannot authorize or terminalize scans; unconfirmed termination remains uncertain. Termination confirms container emptiness. | POSIX production-path late-descendant, root-exit/multi-child positive recovery tests; fresh member-identity and membership-race negative tests; committed-to-recovery database transition, tamper, replay, and concurrency tests; Windows atomic Job Object assignment, descendant termination, worker-crash `KILL_ON_JOB_CLOSE`, same-name non-reattachment, exact-member recovery, cancellation, and durable settlement tests; platform-specific non-scan uncertainty handling; accepted-baseline GitHub Windows assurance evidence is recorded in historical run `34659175863`, job `103457915354`; current published GitHub Windows assurance evidence is recorded in run `34685317236`, job `103531200228`; independent auditor acceptance remains required. | OPEN |
| Durable restart attachment | Launch identity and worker ownership needed for recovery are durably recorded without storing a raw PID as authority. A restarted POSIX worker may attach only after independent identity and tenant validation. Windows does not perform durable named-object reattachment after worker loss: the `KILL_ON_JOB_CLOSE` lifecycle destroys the original container, the loader returns an operator-visible recovery-unavailable result, and a same-name object cannot satisfy the persisted attestation. Valid complete POSIX attestations remain attachable for `LAUNCH_UNCERTAIN` and `RECOVERY_BLOCKED`; incomplete or tampered identity remains blocked. A post-commit recovery primitive preserves the committed launch state and consumes the persisted attestation only after exact termination proof. | Restart test with a surviving POSIX child/group, valid uncertain/recovery loader states, production-path governed-to-recovery transition, invalid worker generation, PID/PGID/SID reuse, incomplete/tampered identity, native Windows worker-crash kill-on-close and same-name negative, exact local-member recovery, concurrency/replay, and operator-visible recovery escalation. | OPEN |
| Single cancellation coordinator | One coordinator owns cancellation request, task shutdown, process termination, authority revocation, and terminal settlement. Async cancellation cannot race a background execution thread. | Ignored-cancellation, timeout, duplicate-request, revocation-vs-finish, and exact idempotence tests. | OPEN |
| Durable recovery | Recovery attempts, status, bounded retry/backoff, next attempt, and escalation are persisted by execution ID and organization. Timed-out work cannot silently mutate after lifecycle shutdown. | SQLite clean-database tests and PostgreSQL row-lock/concurrency tests; health/audit endpoint evidence. | CT108 exact-source authenticated recovery-health and restart evidence recorded; implementation and independent acceptance remain OPEN |
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

The accepted implementation baseline is the grouped GitHub-first commit
`66d609bb9c1a9ce83b44d50868d3d8ecac471e27` on
`security/nmap-installer-closure`. It contains the production process-boundary
and root-exit recovery correction described by this matrix. The matrix remains
open because implementation evidence, platform/deployment evidence, and
independent acceptance are separate gates. The current follow-up adds only a
deterministic readiness-marker wait to the existing Windows non-scan assurance
test; it does not alter the production supervisor or contract semantics.

The accepted baseline also makes authoritative queue quarantine state and its
original sanitized failure evidence one integrity-bound record; it does not
treat an expiring operational marker or a stream entry alone as the safety
state.

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

The Windows governed path now has a native kernel-owned process container.
`WindowsJobProcess` creates the root with `CreateProcessW` while suspended and
uses the extended-startup `PROC_THREAD_ATTRIBUTE_JOB_LIST` assignment so the
root is associated with the named Job Object before it can execute. The Job
Object permits only the required `KILL_ON_JOB_CLOSE` limit; the implementation
captures and verifies the root PID/start token, exact initial membership, tenant
and worker-generation binding, and attestation digest before resuming the
root. Descendants remain in the same container, and cancellation/recovery
terminates the exact process-local attested Job Object and requires a
zero-member proof. The process-local binding is mandatory for assurance; the
loader does not reopen a named object after worker loss. A worker crash closes
the last owned handle, kills members, and releases the named object. A later
same-name object is therefore a new empty or unrelated container and cannot
satisfy the old digest binding. `reopen=True` is retained only for diagnostic
native inspection. The implementation does not use `taskkill`, PID-tree
reconstruction, or a PID-only fallback. The final operating-system launch
boundary still has an unavoidable check-to-kernel timing window, so the
control is described as minimized TOCTOU exposure rather than mathematically
race-free.
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
If the exact persisted process identity cannot be reloaded for an
`EXTERNAL_PROCESS_GOVERNED` execution, the observer records a durable
identity-unavailable `DEFERRED` or bounded `EXHAUSTED` recovery outcome with
retry/error/attempt/audit evidence and leaves the run and ownership
non-terminal. It does not invoke the supervisor, infer `NO_EXTERNAL_PROCESS`,
or accept a caller-supplied replacement identity. The condition is exposed by
the tenant-scoped recovery-health projection and remains eligible for a later
retry; settlement requires a newly validated exact identity.
The same durable identity-unavailable outcome applies to an active
`UNKNOWN` ownership row when authority is revoked, expired, or otherwise lost
after dispatch may have begun and no process identity can be independently
reloaded. The observer preserves `UNKNOWN` and its existing launch state,
does not fabricate `NO_EXTERNAL_PROCESS`, does not invoke the supervisor, and
records tenant-bound retry/error/attempt/audit evidence through the same
bounded `DEFERRED`/`EXHAUSTED` projection. Deferred `UNKNOWN` work is
re-enumerated only when its retry is due; exhaustion remains non-terminal and
operator-visible. The explicit `REQUESTED`/`PENDING` pre-dispatch proof path
remains separate and may terminalize only from positive durable evidence.
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

Current implementation files for this candidate are limited to the audited
execution boundary and its Windows assurance path:
`backend/app/core/db.py`, `backend/app/core/execution_context.py`,
`backend/app/core/execution_service.py`,
`backend/app/core/observation_service.py`,
`backend/app/core/process_supervisor.py`,
`backend/app/core/scan_execution_authority.py`,
`backend/app/core/windows_job.py`,
`backend/tests/test_execution_context_contract.py`,
`backend/tests/test_execution_launch_inventory.py`,
`tests/security/test_container_hardening.py`,
`tests/security/test_execution_decision_authority.py`,
`tests/security/test_process_launch_boundary.py`, and
`.github/workflows/contract-verification.yml`. Contracts, migrations,
`AGENTS.md`, the protected database, `.ci/`, and `.project-temp/` remain outside
the delivery scope unless separately authorized.

The accepted baseline has historical GitHub Actions evidence in run
`34659175863`, including the Windows Job Object assurance job
`103457915354`. The bounded follow-up implementation candidate
`285094882dca0108ad7a32eee2c230f668202956` and its successful run
`34666036688` are also historical pre-publication records. The current
published closure commit is
`031cda1f93fd0e7cebf6ec50452da43dc7bf980f` (parent
`cb563414a1721a780ed0d0184ed8e9ee6c6dbcd8`, tree
`0a43ef6b895f059a991173122bd220ac37140579`) and its exact GitHub Actions
evidence is run `34685317236`; all six required jobs passed. The exact-source
CT108 build, deployment, runtime, persistence, and 26-tool evidence for that
published commit is recorded in the final section below. The matrix remains
open because broader independent OS-level process/restart evidence, durable
cancellation/recovery/tenant-isolation proof beyond the recorded vectors, and
independent auditor acceptance are not closed by local tests, deployment
smoke checks, or a green CI run alone.
The local Redis attempt reached Redis 5.0.14.1 but was not counted because
`XAUTOCLAIM` is unavailable there; the supported CI service remains Redis 7.

## Acceptance gate

The lifecycle section is accepted only when every row is marked complete with
repository evidence, focused tests execute successfully on a clean supported
database, PostgreSQL concurrency coverage is recorded, the protected shared
database has not been altered, and the independent auditor confirms that no
contract requirement remains open. Until then, the overall lifecycle status
remains `REWORK / IN PROGRESS`.

## 2026-09-12 historical pre-publication bounded runtime-candidate evidence update

The following is a historical, pre-publication observation. The previous
2ff8dde reconciliation left deployment binding, managed-tool runtime evidence,
and graceful worker shutdown unverified. A real CT108 deployment of that
bounded source candidate supplied implementation/platform observations at the
time, without changing the acceptance state of any row. It is not current
runtime provenance for published commit `031cda1`; that evidence is recorded
in the final section below.

| Matrix area | New evidence | Status when collected |
| --- | --- | --- |
| Buildable production candidate | CT 108 Docker 29.1.3 legacy-builder build completed after the demonstrated platform-default and Trivy compiler-parallelism corrections; image `sha256:f9bf37685c7f5660faf12fc31dc0a5a814ba45ceafbbfd985652651c8895eae9` | Evidence added; exact GitHub publication still required |
| Typed durable worker identity | API and worker received the same non-empty provisioned identity/generation; redacted environment-entry hashes and application getter hashes matched across both containers | Evidence added; independent auditor review still required |
| Complete launch coverage | Existing production launch inventory remains the authoritative static evidence; no new direct launch path was introduced | Previously verified; final publication/CI gate still required |
| Durable restart attachment | Worker stopped and restarted with a new PID while Redis pending count remained zero; no scan was run | Evidence added; broader restart proof and auditor review still required |
| Single cancellation coordinator | No cancellation implementation changed in this bounded pass; existing coordinator evidence remains applicable | Open pending full acceptance |
| Durable recovery | PostgreSQL readiness, Redis readiness, and worker queue-group readiness were observed; authenticated recovery-health endpoint could not be exercised because the supplied `admin/admin` credentials returned HTTP 401 | Partially evidenced; authenticated recovery proof remains open |
| Contract and operational proof | Source, test, and dated evidence updates are grouped for the next GitHub-first publication; GitLab remains mirror-only | Open pending exact published SHA, six CI jobs, and independent auditor acceptance |

The candidate API returned HTTP 200 with `HEALTHY`; PostgreSQL 16 returned
`pg_isready` accepting connections; Redis 7 returned `PONG`; and the
`cyberassess-workers` stream group reported zero pending messages. The API and
worker ran the same candidate image under the existing Compose project and the
existing persistent data bind. Docker's standard `docker stop -t 30`
terminated the worker with exit code 0 after the SIGTERM handler correction.

This historical update did not claim that its temporary image was the final
GitHub candidate. The exact published-source build and deployment are now
recorded below. Docker Compose network separation remains a network boundary
and is not dynamic destination-level egress enforcement.

## 2026-09-12 historical pre-final-source authenticated recovery and active-handler evidence

This entry records the account-recovery and active-handler observations made
before the exact published-source deployment. It supersedes only the earlier
authentication blocker recorded in the historical runtime-candidate update
above. The prior observation that
`admin/admin` returned HTTP 401 remains historically accurate for the time it
was collected; CT108 was subsequently recovered through a narrow, explicitly
authorized account operation. The image and worker PIDs in this entry are
historical and are not the final source-provenance record.

- The exact target was CT108 (`192.168.99.66`), PostgreSQL `16.15`, database
  `cyberassess`, with one active `ADMIN` account named `admin` in
  `org-7f0c365a`.
- The user explicitly authorized resetting that demo administrator credential.
  The operation matched the existing user identity, role, and active state and
  updated exactly one `users.hashed_password` row in one transaction. It did
  not reset the database, recreate the account, change the schema, or touch
  scan, finding, execution, or test-history rows.
- Before/after persistence counts were `users=1`, `scans=0`, `findings=0`,
  `finding_occurrences=0`, `execution_requests=0`, and `execution_runs=0`.
  Audit-event count increased only from `6` to `9` as the authenticated
  verification calls produced normal successful-login audit events. Raw
  credentials and password hashes were not recorded.
- The authenticated runtime checks returned HTTP `200` for login, `/me`, and
  `/api/system/executions/recovery/health`. The recovery response was bound to
  `org-7f0c365a` and contained an empty recovery list.
- The worker restarted from PID `2206036` to `2231656` on the same exact image
  digest. PostgreSQL readiness, Redis `PONG`, and zero pending/zero lag for
  the `cyberassess-workers` stream group held before and after restart.
- The active-handler assurance test
  `backend/tests/test_execution_launch_inventory.py::test_worker_signals_during_active_handler_finish_work_then_exit`
  invokes SIGINT and SIGTERM during the public worker handoff, proves the
  active handoff completes, prevents a second consume cycle, and verifies
  queue cleanup.
- The post-change disposable local lifecycle suite completed with `96 passed,
  46 skipped, 1 warning`; the database-backend suite completed with `36
  passed, 1 warning`. Full paths and hashes are retained in
  `.project-temp/section-b-recovery-closure-20260912/runtime-auth-recovery.md`.
- The full substantive local regression completed with `954 passed, 85
  skipped, 1 deselected, 15 warnings`; the single deselection is the preserved
  historical `.ci` worktree-inventory assertion and is not counted as a pass.
- The protected repository SQLite database remained unchanged at
  `10285056` bytes, mtime `2026-09-04T23:24:42.6548237Z`, SHA-256
  `7a5a019389f69574b7bae31c355efeeed47fbe9f203e2c2a65c946e21cba6ecc`.

This historical operational recovery did not close the lifecycle section. The
exact-SHA GitHub publication, current GitHub Actions jobs, and final runtime
evidence are recorded below. GitLab mirror verification remains deferred until
the GitHub-first and independent-auditor gates are satisfied. Docker Compose
network separation remains a network boundary and is not dynamic
destination-level egress enforcement.

## 2026-09-12 final published application source, exact CT108 runtime, and authoritative CI evidence

The exact application/test source used for the current Section B runtime and CI
evidence is commit
`031cda1f93fd0e7cebf6ec50452da43dc7bf980f` on
`security/nmap-installer-closure`, parent
`cb563414a1721a780ed0d0184ed8e9ee6c6dbcd8`, tree
`0a43ef6b895f059a991173122bd220ac37140579` ([GitHub commit](https://github.com/andresslacson1989/security-assessment-platform/commit/031cda1f93fd0e7cebf6ec50452da43dc7bf980f)).
The exact source archive `security-assessment-platform-031cda1f.tar` was
`6,318,080` bytes with SHA-256
`32066405c11f07e4b94d17c1b43136bfd0bff54035aa54843828db1b687ead25`; the
archive transferred to CT108 matched that size and digest; the extracted
source was verified against that archive. No source or contract files were changed by this
corrective documentation commit.

The exact source was built on CT108 as Linux/amd64 image
`ghcr.io/andresslacson1989/security-assessment-platform:section-b-final-031cda1`
with image ID/RepoDigest
`sha256:a66b873c679d1f3873c3c093d70e0ac3f05ee907aff5ff082c4517f35a55c4e1`,
created `2026-09-12T09:54:32.364976258Z`, size `751654768` bytes. Image labels
bind the revision to `031cda1f93fd0e7cebf6ec50452da43dc7bf980f`, the source
archive digest above, and
`github.com/andresslacson1989/security-assessment-platform`. The retained
build log is
`/opt/cyberassess/.codex-deploy-section-b-final-031cda1/build-031cda1-legacy.log`
on CT108 and its project-local copy is
`.project-temp/section-b-recovery-closure-20260912/final-source-031cda1/ct108-build-031cda1.log`;
both are `28,667` bytes with SHA-256
`19c7bcbe7eda35cd9a5b25950f8045b08fda06869b87b277d792b8a692fdbbd6`.

Only the API and worker application services were recreated from the exact
image. The API container is
`3b281c1f48a9c12fcf501aaa6c40ba162ded7175db6537c0818c951ad780fb03`, created
`2026-09-12T09:55:36.987748198Z`, running and healthy, with command
`["python", "run_platform.py"]`. The worker container is
`3902a58854a0c4efb3eb8fc9807ea344d30fd8e036210a165ac512282d9bc75c`, created
`2026-09-12T09:55:36.98279058Z`, running, with command
`["python", "/app/run_worker.py"]`. Both use the exact image, run as
`cyberassess`, use a read-only root filesystem, drop all capabilities, and
enable `no-new-privileges`. PostgreSQL and Redis were not recreated: the
existing PostgreSQL container is
`e88c23415c583d99de289c173e7f3a7ceb280596e4fec5aebdb387d11f374bf0`, using
`postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685`,
created `2026-09-08T16:13:05.320938141Z`; Redis is
`8e73e9c2a7c7e10d966f314e50ad2c9f03525f2607b9cf9465e07e8cdecda104`, using
`redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf`,
created `2026-09-08T16:03:01.114442821Z`. PostgreSQL accepted connections,
Redis returned `PONG`, and the `cyberassess-workers` group reported pending
`0` and lag `0`.

The exact-runtime API health check returned HTTP `200` with status `HEALTHY`,
version `14.3.0`, storage `OK`, `scans_stored=0`, `total_scans_stored=0`, and
`registered_engines_count=5`. Authenticated checks returned HTTP `200` for
login, `/api/auth/me` as `admin`/`ADMIN` in `org-7f0c365a`, and the
tenant-scoped recovery-health endpoint with `recovery=[]`. The worker was
orderly restarted from PID `2268860` to `2269163`; stop and start both exited
`0`, and the restarted worker retained the exact image identity. No scan,
provider credential injection, or unrestricted external scanning was
performed.

The exact-runtime disposable inventory probe reported `FLEET_COUNT=26` with
IDs `amass`, `bandit`, `checkov`, `dockle`, `ffuf`, `gitleaks`, `grype`,
`gtfobins`, `httpx`, `hydra`, `katana`, `kube-bench`, `metasploit`, `nmap`,
`nuclei`, `osv-scanner`, `prowler`, `retire`, `schemathesis`, `semgrep`,
`sqlmap`, `sslyze`, `subfinder`, `syft`, `trivy`, and `trufflehog`. The probe
used `--network none`, a read-only filesystem, all capability drops, and
disposable project-local tmpfs mounts; it performed no scan or network access.

The explicitly authorized CT108 account-only operation is recorded without
raw credentials or hashes: one existing active `admin` administrator row in
PostgreSQL database `cyberassess` was updated, with no full database reset,
schema change, account creation, or history deletion. Current counts are
`users=1`, `scans=0`, `findings=0`, `finding_occurrences=0`,
`execution_requests=0`, `execution_runs=0`, and `audit_events=10`; the audit
increase consists of successful verification logins. The protected local
SQLite database remains outside delivery scope and its unchanged fingerprint
is `10285056` bytes, mtime
`2026-09-04T23:24:42.6548237Z`, SHA-256
`7a5a019389f69574b7bae31c355efeeed47fbe9f203e2c2a65c946e21cba6ecc`.

Authoritative GitHub Actions evidence is run
`34685317236` ([run](https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34685317236))
for exact SHA `031cda1f93fd0e7cebf6ec50452da43dc7bf980f`. All six jobs passed:

| Job | Job ID | Result |
| --- | --- | --- |
| Windows Job Object assurance | `103531200228` | 19 passed, 0 skipped |
| PostgreSQL 16 schema assurance | `103531200272` | 29 passed, 0 skipped |
| Hardened production image verification | `103531200286` | passed |
| Compile backend | `103531200317` | passed |
| Focused contract verification | `103531200328` | 341 passed, 11 skipped |
| Full repository verification | `103531200341` | 1026 passed, 14 skipped, 15 warnings |

Retained artifact archive digests are: focused
`sha256:1b06e56eca45f63c37f0f1594a1e6b0a12255c2fab7da10607ad5fd3b49f27c5`,
full `sha256:1274378bc6a7744183b474316ab8a80025c7f77329c2b435e1ecee35ab5f54bd`,
PostgreSQL `sha256:c8a2d9ddbac261e97a9999634efd36d2493cf6ebf59ef97035f91789fd5ac0f2`,
and Windows `sha256:3a31edfb4708d4010eb8ee99b09667d9267902f665fdb94fe3deea29ef093417`.
The downloaded log/XML and skip-classifier hashes are retained under
`.project-temp/section-b-recovery-closure-20260912/github-34685317236/` and
are enumerated in the dated evidence record. The full-suite classifier
records 14 skips: three managed-tool-unavailable, ten
Windows/platform-covered, and one provenance-blocked historical fixture;
these remain skips, not passes. Warnings include the upload-artifact Node.js
24 migration notice and Python deprecation warnings.

GitLab was not updated: its read-only remote currently returns HTTP `530`, and
the mirror remains deferred until GitHub-first publication and independent
auditor acceptance. Docker Compose network segmentation remains a container
network boundary, not dynamic destination-level egress enforcement. This
matrix remains `OPEN` pending the auditor's independent acceptance and the
unresolved lifecycle criteria above.
