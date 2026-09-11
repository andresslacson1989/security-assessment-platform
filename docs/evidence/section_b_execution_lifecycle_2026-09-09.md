# Section B Execution-Lifecycle Evidence — 2026-09-11

Status: implementation evidence recorded for the current Section B rework
candidate; independent acceptance remains open.

This addendum records the durable approval-to-dispatch and cancellation-
coordination implementation pass, including the subsequent authority-to-launch
preflight, exact identity settlement rework, PostgreSQL settlement correction,
explicit deployment identity/generation binding, process-session emptiness
checking, zombie-member handling, explicit recovery blocking when root
ownership is no longer independently provable, and the native Windows Job
Object execution path. The previously published baseline remains
`0a76593045e9d9957bfa1c601d36b2d19b77ee4c`. The current working-tree candidate
is based on the grouped local parent
`2ce759f95639dd2dcd90e74485244d3213b721d9` and is not yet assigned a delivery
SHA; no commit or CI result is claimed for the uncommitted Windows
implementation. Earlier local commits remain retained as historical
predecessor evidence, not as the current candidate. The current worktree also
retains the previously implemented authoritative-versus-legacy
queue classification, strict failure evidence and quarantine-state schemas,
exact evidence digests, atomic quarantine publication, and compare-and-swap
recovery acknowledgement. These local changes are not represented by the
published baseline.
It is evidence for the Section B review and does not claim that the
execution-lifecycle closure matrix is accepted.

## Contract-closure state and call graph

The bounded production path is:

```text
ExecutionDecisionCapability
  -> ProcessSupervisor.execute()
     -> Popen()
        -> capture stable complete process identity
           -> record_posix_launch()
              -> EXTERNAL_PROCESS_GOVERNED
           -> bounded communicate / cancellation / timeout
              -> confirmed termination -> ordinary governed settlement
              -> unconfirmed termination -> record_launch_uncertain()
     -> atomic ownership transition under the database lock
        -> complete identity: LAUNCH_UNCERTAIN
        -> incomplete/invalid identity: RECOVERY_BLOCKED
        -> committed current row: atomic committed-to-recovery downgrade
  -> BackendObservationService._reap_execution_authority_once()
     -> claim recovery lease (owner/token/generation)
     -> reload exact durable process identity
     -> ProcessSupervisor.cancel_execution(exact identity)
     -> confirmed termination -> settle_recovery_execution(recovery lease)
     -> unconfirmed/missing identity -> deferred or exhausted, non-terminal
```

The process worker binding is the durable `execution_runs.worker_identity` and
`worker_generation` tuple. The recovery lease binding is the mutable
`execution_recovery_state.owner`, `lease_token`, and `worker_generation` tuple
plus its immutable recovery attempt. These are intentionally separate: the
recovery coordinator may differ from the worker that created the process, but
it cannot replace the persisted process identity or its original attestation.
An incomplete identity never receives a fabricated attestation and remains
`RECOVERY_BLOCKED`; the observer cannot terminalize it through a missing-PID or
`NOT_FOUND` inference.

On Windows, the governed branch replaces POSIX process-group/session identity
with a named kernel Job Object and a typed `WindowsJobAttestation`. The root is
created suspended through `CreateProcessW` with the extended-startup
`PROC_THREAD_ATTRIBUTE_JOB_LIST` assignment, so the process is in the Job
Object before resumption. The Job Object is restricted to
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; the attestation binds the job name,
nonce, execution, tenant, worker identity/generation, root PID/start token,
exact initial membership, expiry, verification result, and canonical digest.
The durable launch record is written while the root remains suspended, then
the root is resumed. Recovery uses the process-local attestation-to-handle
binding and verifies every currently reported member in that exact kernel
object. It never reopens a named object after worker loss: `KILL_ON_JOB_CLOSE`
terminates the members and releases the named object, while a same-name object
created later is a new container and is rejected. `reopen=True` remains a
diagnostic-only native observation facility and cannot verify or register a
durable attestation. A zero-member proof is required for terminal settlement.
This reduces the check-to-launch exposure but cannot make the final
operating-system transition mathematically race-free.

## Scope

The implementation binds approved scan dispatch to the real orchestrator,
retains the distinction between queue acceptance and process creation, and
uses an atomic tenant-scoped Redis publication identity for exact approval
replays. The production worker no longer calls the private scan executor
directly; after Redis consumption it invokes the public
`execute_dispatched_scan()` handoff with the local bounded executor.

Before that executor is entered, the handoff validates the durable parent and
every selected child binding: tenant and scan identity, operation selection,
request/decision/run identity joins, authorization and approval state, session
JTI and revocation, expiry, snapshot completeness, worker identity/generation,
and dispatch state. This prevents a revoked or expired child decision from
reaching native work that might not later call an external adapter.

Scan cancellation and direct execution-request revocation use the same
`ExecutionCancellationCoordinator`. The coordinator revokes authority before
exact execution-identity cancellation, joins an owning task when one is
available, and reloads the durable process identity when a worker restart is
recoverable. POSIX recovery may use its complete persisted session/group
identity; Windows recovery after worker loss is intentionally bounded because
the Job Object is destroyed with the worker handle and the loader refuses
same-name reattachment. Both paths preserve a recoverable state for
`NOT_FOUND`, `FAILED`, missing mappings, or an unjoined task. Positive
`NO_EXTERNAL_PROCESS` evidence is settled through a durable no-process path
and is never inferred from a missing PID. Only the durable
`EXECUTION_CANCELLED_BEFORE_DISPATCH` transition is accepted as the
pre-dispatch no-process proof.

The post-revocation settlement primitive validates all authority, tenant,
identity, dispatch, run, and recovery fences before its first write and records
an auditable termination-proof digest. A current, still-valid authorization
cannot use that primitive as a replacement for the ordinary authority-held
finish path. No schema or migration change is part of this section.
The current corrective implementation adds a separate committed-launch
downgrade: a locked `EXTERNAL_PROCESS_GOVERNED` row can become
`RECOVERY_BLOCKED` only after durable worker, generation, tenant, correlation,
and attestation validation, and the transition updates no persisted identity
field. The recovery settlement primitive now accepts that preserved
`COMMITTED` launch state and emits its terminal proof from the persisted
attestation after a recovery lease. The current corrective pass also makes
the uncertainty callback state-driven under the database lock, so it cannot
make a stale get-then-write decision. Complete post-launch identity is
`LAUNCH_UNCERTAIN`; incomplete or invalid post-launch identity is
`RECOVERY_BLOCKED`. Recovery lease owner and generation are distinct from the
original durable process worker identity and generation, and the observer uses
that separate lease to settle only after exact supervisor confirmation.

The queue closure candidate makes the wire classification explicit. Production
execution intents are `AUTHORITATIVE_EXECUTION`; diagnostic compatibility
messages are `LEGACY_DIAGNOSTIC`. A missing, malformed, conflicting, unknown,
non-string, or credential-bearing message field is rejected before handler
entry and cannot fall through to legacy acknowledgement. Failure evidence is
allowlisted and canonicalized without caller-payload passthrough. Quarantine
state stores the canonical evidence, its digest, a top-level state digest, and
the validated tenant/request relationship. Quarantine state, operational
marker, failure event, and the optional bounded acknowledgement are governed
by fail-closed Redis transactions. A credential field is rejected in every
legacy diagnostic wire shape, including empty and malformed values, before
decryption, handler entry, or ACK. Explicit recovery requires a typed,
tenant-bound operator assertion; the queue primitive itself does not
authenticate an arbitrary actor string. The acknowledgement transaction uses
an exact state compare and requires a successful `XACK` before deleting the
durable quarantine record. The queue's session-binding field is an opaque
authenticated-service handoff and is not independently enforced by the queue
state comparison.

The cumulative Section B candidate includes changes in the following audited
implementation and test files:

- `backend/app/core/db.py`
- `backend/app/core/execution_service.py`
- `backend/app/core/observation_service.py`
- `backend/app/core/orchestrator.py`
- `backend/app/core/process_supervisor.py`
- `backend/app/core/queue.py`
- `backend/app/core/auth.py`
- `docker-compose.yml`
- `backend/tests/test_execution_launch_inventory.py`
- `run_worker.py`
- `tests/security/test_execution_cancellation_coordinator.py`
- `tests/security/test_execution_decision_authority.py`
- `tests/security/test_process_launch_boundary.py`
- `tests/security/test_database_backend.py`
- `tests/test_observation_service.py`
- `tests/test_orchestrator.py`
- `tests/security/test_credential_handoff.py`
- `tests/security/test_execution_quarantine_api.py`
- `tests/test_adapters.py`
- `tests/test_e13_process_isolation.py`
- `tests/security/test_code_sast_assurance.py`
- `tests/security/test_nmap_assurance.py`

The current uncommitted Windows Job Object assurance increment additionally
changes:

- `backend/app/core/execution_context.py`
- `backend/app/core/scan_execution_authority.py`
- `backend/app/core/windows_job.py`
- `backend/tests/test_execution_context_contract.py`
- `tests/security/test_container_hardening.py`
- `.github/workflows/contract-verification.yml`

The current Section B candidate also adds a fail-closed deployment binding:
production execution identity and generation now require explicit environment
configuration, and the enterprise Compose API and worker services require the
same provisioned values. Development/test mode retains its deterministic local
fallback so isolated unit tests do not become deployment configuration tests.
Non-scan contexts are revalidated against that binding at the process-launch
boundary. If an enterprise egress rejection is already active, the supervisor
returns the egress rejection before identity diagnostics; otherwise a missing
or mismatched deployment binding is rejected before process creation. Windows
governed execution now has the verified-in-code Job Object implementation
described above, but its assurance remains conditional on the independent
Windows CI run and auditor review recorded below. Every Windows launch,
including installer and observation launches, uses `WindowsJobProcess` and a
typed attestation. Non-scan launches retain their separate
non-authoritative capability, and termination or recovery that cannot prove
the process container is surfaced as
`PROCESS_TERMINATION_UNCONFIRMED`/`LAUNCH_UNCERTAIN`; it is never reported as a
confirmed completion or scan authorization.

The evidence below separates the previously published baseline from the
current working-tree implementation candidate. The final delivery commit and
its GitHub run are reported in the Section B review message after the grouped
publication; this addendum does not infer a commit SHA before that publication.

Contracts, migrations, `AGENTS.md`, the protected database, `.ci/`, and
`.project-temp/` remain outside the candidate delivery scope.

No migration or runtime database change is part of this section.

## Current local verification

The prior baseline checks below are retained as historical evidence for
`0e56c766ca96b046a5392d5e92e48dd02122c4f3`. The current published CI
verification applies to `0a76593045e9d9957bfa1c601d36b2d19b77ee4c`; the
unpublished queue-quarantine closure candidate is tested locally and is not
represented by that CI run. Every disposable SQLite database was created under the
project-local `.project-temp/` tree; the protected runtime database was not
used.

- Focused contract command against the previously published `0e56c766`
  baseline, including the worker handoff, authority,
  cancellation, observation, process, and launch-inventory tests:
  **1 failed, 250 passed, 40 skipped**, exit code **1**. The failed test is
  the preserved historical worktree-inventory assertion; its recorded `.ci/`
  inventory is 1709 entries while the preserved untracked tree currently has
  3038. It is not an application defect, but it remains a failed test in that
  exact command and is not presented as a pass.
- Full local repository suite from a fresh unique disposable SQLite path,
  excluding only that preserved historical worktree snapshot assertion:
  **881 passed, 78 skipped, 1 deselected, 15 warnings**.
- Historical full repository suite for the pre-correction unpublished
  candidate from a fresh
  unique disposable SQLite path, excluding the preserved historical fixture
  and worktree snapshot assertion: **888 passed, 84 skipped, 2 deselected, 14
  warnings**, exit code **0**. This is historical evidence, not current
  candidate evidence. Windows process-tree termination vectors remain
  platform-gated; explicit Windows recovery rejection and non-scan uncertainty
  behavior are tested separately. The excluded inventory assertion remains a
  known local failure because the preserved `.ci/` tree is larger than its
  historical snapshot.
- Historical full repository suite after the corrective process, restart-loader,
  queue, credential, quarantine-API, and recovery-settlement changes, from a
  fresh unique disposable SQLite path and excluding the same two preserved
  historical assertions: **911 passed, 86 skipped, 2 deselected, 15
  warnings**, exit code **0**. This is historical evidence, not current
  candidate evidence. The two additional process vectors are
  POSIX-only and are skipped on this Windows host; they are required to execute
  in Linux CI.
- Historical corrective lifecycle, credential, quarantine route, and recovery
  settlement vectors after the governed-to-recovery state-machine fix,
  explicit legacy credential-field presence rejection, tenant-admin scope
  correction, and persisted member-snapshot validation: **105 passed, 6
  skipped, 1 warning**, exit code **0**, against a project-local disposable
  database. The six skips are POSIX-only process vectors on this Windows host.
  This is historical focused local evidence only; it is not current candidate
  or GitHub Actions evidence.
- Local PostgreSQL and Redis integration could not be rerun because Docker is
  unavailable on this host and no approved local service URLs were provided.
  The authoritative PostgreSQL evidence for this baseline is the successful
  GitHub Actions PostgreSQL 16 job recorded below; no local substitute is
  claimed.
- The preceding queue/quarantine closure command against the unpublished
  pre-corrective working tree, with an explicit disposable SQLite path and
  project-local pytest base: **73 passed, 38 skipped**, exit code **0**. This verifies explicit wire
  classification, strict unknown/non-string/credential-bearing evidence
  rejection, malformed binding rejection, atomic quarantine publication,
  durable original-failure evidence and both evidence/state digest bindings,
  no credential persistence, compare-and-swap acknowledgement, and tamper
  rejection.
- The current credential-hand-off subset adds three locally executed legacy
  wire vectors (empty, malformed, and non-empty credential-field values); all
  three reject before decryption, handler entry, and ACK.
- Current process-boundary command against the unpublished working tree, with
  an explicit disposable SQLite path and project-local pytest base: **13
  passed, 6 skipped**, exit code **0**. This verifies the bounded post-Popen
  stabilization handshake, fresh complete POSIX member-identity snapshot
  requirement, positive root-exit recovery, root/session/process-group
  vectors, membership race behavior, and explicit Windows fail-closed
  recovery. The six skips are the Windows-inapplicable POSIX vectors,
  including the two new late-descendant production-path vectors; they are not
  reported as Windows passes.
- Current affected-path compatibility regression after the Windows policy and
  queue-envelope fixture updates: **17 passed, 8 skipped**, exit code **0**.
  The skips are platform-inapplicable POSIX process-tree assertions and are
  separate from the explicit Windows fail-closed tests.
- Combined local authority, queue, replay, and process regression against the
  unpublished working tree, with a unique project-local SQLite database and
  project-local pytest base: **90 passed, 44 skipped**, exit code
  **0**. The live Redis vector remains environment-gated and was not claimed
  as a pass locally. The additional skips are the two POSIX-only late-
  descendant vectors; Docker is unavailable on this host.
- Quarantine API/authentication route tests against a disposable SQLite
  database: **4 passed**, exit code **0**. This covers unauthenticated,
  expired, revoked, non-admin/missing-scope, wrong-tenant, wrong-request,
  replay, and concurrent acknowledgement behavior through the existing JWT,
  role, scope, and durable revocation boundary.
- The current API/auth route set additionally executes the explicit tenant
  `ADMIN` token with `scopes=[]` vector and rejects it with **403**; explicit
  token scopes are now bounded grants rather than being widened to role
  defaults during token decode. The queue's opaque in-process operator
  capability remains a typed handoff after HTTP authentication, not a second
  authentication boundary; existing wrong-type construction rejection is
  retained.
- Historical corrective Section B vectors before the current recovery
  rework, after the atomic uncertainty,
  recovery-lease separation, synthetic-authentication boundary, strict timeout,
  and post-`Popen()` persistence changes: **8 passed**, exit code **0**. This
  includes the atomic no-stale-read vector, production observer/reaper path
  with a distinct recovery lease identity, complete-versus-incomplete identity
  vectors, and strict no-output timeout semantics. The complete affected-path
  rerun remains required after the final documentation and regression changes.
  Command: `python -m pytest -q -p no:cacheprovider
  tests/security/test_execution_decision_authority.py
  tests/security/test_process_launch_boundary.py
  tests/security/test_auth_admin_boundaries.py
  tests/test_observation_service.py tests/test_adapters.py` with
  `CYBERASSESS_DB_PATH` and `--basetemp` under the unique
  `.project-temp/section-b-corrective-focused-final-2/` directory. This is
  historical evidence for the predecessor candidate.
- Historical recovery-correction vectors from
  `2545a62acbfb2c3e4978ccac9919b7f56688ad48`: **3 passed**, exit code **0**.
  This covers deferred complete-identity `UNCERTAIN` provenance followed by
  confirmed settlement, durable retry scheduling and later exact settlement
  for an unconfirmed `EXTERNAL_PROCESS_GOVERNED` process, and per-candidate
  observer isolation. The exact command used project-local disposable storage
  under `.project-temp/section-b-recovery-correction-focused-6/`. This is
  local evidence only; it is not GitHub Actions evidence.
- Historical complete affected-path suite for the predecessor worktree, using a fresh
  disposable SQLite database and project-local pytest base, passed **191
  tests**, with **6** Windows-inapplicable POSIX skips and exit code **0**.
  The exact isolated paths were under
  `.project-temp/section-b-recovery-correction-affected-final/`. This is local
  evidence only; it is not current candidate or GitHub Actions evidence.
- Historical full repository suite for the predecessor worktree, excluding only the two
  preserved historical Section A snapshot assertions, passed **917 tests**,
  with **87** skips, **2** intentional deselections, **14** warnings, and exit
  code **0**. The exact isolated paths were under
  `.project-temp/section-b-recovery-correction-full-final/`. The deselected
  assertions remain documented historical evidence checks, not hidden failures.
- Historical missing-identity DAL and production-observer vectors for the
  predecessor at `4bda29980c9c242d6305f718cfccd3d031ceee65`: **2
  passed**, exit code **0**, with disposable storage under
  `.project-temp/section-b-missing-identity-focused/`. This is local evidence
  only; it is not GitHub Actions evidence.
- Historical complete affected-path suite for the same predecessor: **193 passed**,
  **6** Windows-inapplicable POSIX skips, exit code **0**, with isolated paths
  under `.project-temp/section-b-missing-identity-affected-final-3/`.
- Historical full repository suite for the same predecessor, excluding only the two
  preserved historical Section A snapshot assertions: **919 passed, 87
  skipped, 2 deselected, 14 warnings**, exit code **0**, with isolated paths
  under `.project-temp/section-b-missing-identity-full-final/`.
- Independent auditor verification of the prior committed `4bda299` candidate
  reported **198 focused passes and 6 platform skips**; its full run reported
  **918 passed, 87 skipped, 1 preserved historical Section A worktree-inventory
  failure, and 15 warnings**. Excluding that preserved failure yields 917
  passing tests. Those results are independently verified evidence for the
  prior candidate, not a substitute for the current local run above.
- Current grouped UNKNOWN/external-missing-identity correction vectors: **9
  passed**,
  **96 deselected**, exit code **0**, with disposable storage under
  `.project-temp/section-b-unknown-combinations-focused/`. This covers the
  external-process regression across `REQUESTED`, `STARTING`, and `RUNNING`,
  direct DAL acceptance for `UNKNOWN` with `NOT_ATTEMPTED` and `UNCERTAIN`
  launch states, invalid ownership/launch-pair rejection, durable
  observer retry/health evidence, due-retry re-enumeration, bounded
  exhaustion, tenant isolation, and non-terminal preservation.
- Current affected-path regression after the grouped correction: **104 passed**,
  **96 deselected**, **1 preserved historical/environment fixture failure**,
  exit code **1**, under
  `.project-temp/section-b-unknown-affected-suite/`. The preserved failure is
  `test_http_api_approval_returns_503_and_correlation_header`, which reaches
  authentication using a disposable module database lacking the unrelated
  `revoked_tokens` table; no recovery test failed. This is not represented as
  a passing suite or as a correction to authentication/schema behavior.
- Independent full local repository suite for exact candidate
  `aa819b68cf636903b2e5b6126d16a4abb88b6dff`: **927 passed, 87 skipped, 1
  failed, 14 warnings**, exit code **1**. The sole failure is
  `tests/security/test_contract_fleet_consistency.py::test_worktree_inventory_snapshot_matches_documented_git_serialization`:
  the preserved historical snapshot records **1709** `.ci` entries while the
  preserved untracked `.ci` tree contains **3038**. This failure remains
  explicit and is not converted into a pass or silently excluded. The local
  full-suite result is not GitHub Actions evidence.
- The live Redis transport vector was attempted with the declared `redis` and
  `hiredis` packages installed only under `.project-temp/`. Dependency
  construction succeeded and the project-local Redis service was reachable,
  but the installed service is Redis **5.0.14.1** and rejects the required
  `XAUTOCLAIM` command. This is an **unverified/failed environment gate**, not
  a pass; the deployment workflow's Redis 7 service remains the authoritative
  compatible runtime target. The service was stopped and port 6380 was
  verified closed afterward.
- The previously published Section B focused command at `0a76593`, with an
  explicit disposable SQLite path, was **112 passed, 42 skipped**, exit code
  **0** for the real dispatch, decision-authority, process-boundary, and
  terminal-replay files. The supported POSIX vectors execute in Linux CI;
  their Windows skips are platform skips, not passes.
- A prior exploratory invocation without `CYBERASSESS_DB_PATH` exited with
  code **2** during module collection on the protected database's existing
  migration-ledger mismatch; no test body ran. A subsequent exploratory
  invocation exited with code **1** because the new test was temporarily
  inserted inside an existing parameterized test and raised `NameError`.
  Both conditions were corrected before the final pre-publication run. The
  protected database fingerprint was rechecked unchanged after the first
  invocation; neither exploratory command is acceptance evidence.
- POSIX fresh-supervisor restart-attachment proof in a newly named disposable
  container using a container-local source copy: **1 passed, 9 deselected**.
  The proof captured the root/session/start-token identity, rejected a forged
  start token while the root and child were alive, and terminated the exact
  persisted tree. The disposable container was removed afterward.
- Python compilation of `backend/app` and `run_worker.py`: passed.
- AST parsing of all 12 changed code/test files: passed.
- `git diff --check`: passed.
- Contract 04 and Contract 08 mirror checks from the existing assurance suite:
  byte-identical.

An earlier full-suite attempt reused a non-empty temporary database and
produced ten idempotency/tenant fixture collisions. That run is not treated
as application evidence. The unique-path rerun above completed without those
collisions. The preserved historical worktree snapshot assertion remains
excluded because its recorded `.ci/` inventory is stale; that user-owned
evidence tree was not changed or removed.

The current Windows host cannot execute the POSIX proof natively. The
container-local proof remains the available local POSIX evidence; the native
Windows Job Object vectors are recorded separately below. Non-scan Windows
launches remain non-authoritative, but unconfirmed termination is explicitly
reported as uncertain. The local session-emptiness assertion is therefore
recorded as an environment skip, not as a Windows pass. The Windows governed
path is not counted as independently accepted until the dedicated Windows CI
job and auditor review are complete.

## Current Windows Job Object implementation evidence

The current Windows host executed the native Job Object implementation in the
working tree. The focused run used an isolated project-local database,
temporary directory, Python bytecode directory, and pytest base directory
under `.project-temp/section-b-windows-native-final-20260911-001/`. Its exact
selection covered the strict Windows attestation contract, launch inventory,
native Job Object atomic assignment and descendant termination, diagnostic
named-object collision/inspection, exact local surviving-member recovery,
worker-crash no-reattachment, all-Windows non-scan launch handling,
supervisor cancellation, and the production-path durable settlement vectors:

```text
19 passed, 0 skipped, exit code 0
```

The JUnit report is retained at:

- `.project-temp/section-b-windows-native-final-20260911-001/windows.xml`

The workflow contract and launch-inventory regression run used
`.project-temp/section-b-windows-ci-20260911-002/` and completed with:

```text
21 passed, exit code 0
```

These are local implementation and workflow-definition results. The
authoritative workflow now contains a dedicated `windows-job-object-assurance`
job on `windows-2022`; it has not yet run for the current uncommitted
candidate, so no GitHub Windows result is claimed here. The local interpreter
was Python 3.13, while the workflow is pinned to Python 3.11; that supported
runtime difference remains an explicit CI verification item.

After the cancellation compatibility correction, the focused cancellation
regression run covered the existing process-isolation unknown-ID behavior, the
Windows attested cancellation vector, and the explicit Windows recovery-block
vector for a live unbound PID:

```text
3 passed, 26 deselected, exit code 0
```

Its JUnit report is retained at
`.project-temp/section-b-cancellation-regression-20260911-004/reports/cancellation.xml`.
The resulting status distinction is deliberate: a dead, untracked PID is
`NOT_FOUND`, while a live PID without the required attested execution binding
is `RECOVERY_BLOCKED`.

The implementation uses the atomic Windows startup `JOB_LIST` association and
a suspended root rather than a post-launch `AssignProcessToJobObject` race.
The repository therefore records the native kernel-container control as
implemented in code and locally exercised, while retaining the distinction
between minimized TOCTOU exposure and a mathematically race-free guarantee.

## GitHub Actions verification

The current code baseline was published first to GitHub as:

```text
commit: 0a76593045e9d9957bfa1c601d36b2d19b77ee4c
ref:    security/nmap-installer-closure
run:    34547535485
url:    https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34547535485
```

The required GitHub Actions workflow completed successfully for that exact
commit. The independently inspected job records were:

| Job | Job ID | Result | Evidence |
| --- | ---: | --- | --- |
| Compile backend | 103103291272 | success | backend compilation completed |
| Focused contract verification | 103103291248 | success | focused contract suite and skip policy completed |
| Full repository verification | 103103291396 | success | full repository suite and skip classification completed |
| PostgreSQL 16 schema assurance | 103103291118 | success | PostgreSQL schema assurance completed |
| Hardened production image verification | 103103291265 | success | hardened image and health smoke checks completed |

The workflow itself enforces project-local CI roots, report directories,
pytest temporary directories, and disposable database paths under the checked
out repository for its compile, focused, full, and PostgreSQL jobs. The
PostgreSQL job used an authenticated disposable `postgres:16-alpine` service,
waited for readiness, ran the schema assurance suite, and rejected any
dependency-gated skip. These CI facts apply to the published `0a76593` base;
the unpublished queue-quarantine refinement has not been published or run in
GitHub Actions.

The run's retained, non-expired artifacts are:

| Artifact | Artifact ID | Digest |
| --- | ---: | --- |
| `focused-contract-evidence-34547535485` | 10179614874 | `sha256:33f199b4b5fe5156cbe3c3f691668c83d50adb2ce8341379ce5c20f8594530d9` |
| `full-repository-evidence-34547535485` | 10179652547 | `sha256:b783011d76d7428ae6b8929d1fcc254dff03e89365ec07a2a3b80dab18c3f975` |
| `postgres-schema-evidence-34547535485` | 10179588150 | `sha256:628083558d4f627a8c760d91b5ae59f9f282aa3d2f5d817cb02a9e9d3ef87cd` |

The immediately preceding documentation/session-containment commit
`350bd541e7c1dd52edaea713f9b7f9a20b2df88a` had one focused-job failure. The
failure was isolated to the new Linux session vector treating terminated
zombie entries as live members. The corrective commit
`5cf443711e74bde9be7a7f028b4b87e2477d7ad1` excludes `Z`/`X` process states,
and the successful run above is the authoritative verification for the
corrected implementation.

The GitHub result is CI evidence for the exact code baseline. It does not
close the independent platform and deployment gates listed in this addendum.

There is no GitHub Actions run for the current committed local candidate
`aa819b68cf636903b2e5b6126d16a4abb88b6dff`. The
required jobs
`compile-backend`, `focused-contract-verification`,
`full-repository-verification`, and `postgres-schema-assurance` remain defined
in `.github/workflows/contract-verification.yml`, but their results for the
current candidate are **UNVERIFIED** until the GitHub-first publication gate
is completed and the exact commit run is independently inspected. A GitHub
pass from the prior SHA cannot be used as evidence for this candidate.

The GitHub full-suite skip classification was:

```text
DEPENDENCY_DEFERRED_TO_POSTGRES_JOB          29
ENVIRONMENT_UNAVAILABLE_MANAGED_TOOL          3
PROVENANCE_BLOCKED_ESCALATION_REQUIRED        1
```

The three managed-tool skips were one unavailable managed Nmap binary and two
Subfinder v2.6.5 runtime vectors. The one provenance skip is the historical
`a1c4fc4` fixture whose committed v1 artifact mismatch remains an explicit
escalation condition. These are classified skips, not passes.

The downloaded evidence files from the earlier `34297542097` run remain
retained under the pre-existing, project-local
`.project-temp/section-b-gh-evidence-34297542097/` directory.
Their SHA-256 digests are:

| Evidence file | SHA-256 |
| --- | --- |
| `focused-contract-evidence-34297542097/focused-contract.log` | `2137CE2989D1295AB767505850B15112AFD074066A2D3B88CB0DDA4E85C804C7` |
| `focused-contract-evidence-34297542097/focused-contract.xml` | `7B8B8AE3D63A7323B777E18010914EBEC090E1C05D1F838F35D1B1C358D09C87` |
| `full-repository-evidence-34297542097/full-suite-skip-classification.txt` | `073B7C6C8D519AD14754D0B08651F22A3A3EB48C4B2E696B5E0CF232DDACCA75` |
| `full-repository-evidence-34297542097/full-suite.log` | `A70CB3B515E22142674625EBC37BCFAAC9B653D2E15FA66878F7B1D882851655` |
| `full-repository-evidence-34297542097/full-suite.xml` | `8FF0E301DB2561716201FE1EA3010C9DF16D0478A4C7E6179EE9C1689719E7F0` |
| `postgres-schema-evidence-34297542097/postgres-suite.log` | `8D5B76D2447599B6926821F19A8F782B7CDD325F8E3DF593740671C9959C7566` |
| `postgres-schema-evidence-34297542097/postgres-suite.xml` | `1DFAA350474244C429A2599D7AE9F9A650CA7C6B1C444F4175A8C55A4F1638A4` |

GitHub Actions reported one non-blocking Node.js 20 deprecation annotation for
the artifact-upload action. It did not change any job result.

The focused and full local counts above deliberately exclude the historical
`test_worktree_inventory_snapshot_matches_documented_git_serialization`
assertion. That assertion compares the preserved untracked `.ci/` evidence
tree with its 2026-09-08 snapshot; the current local `.ci/` tree contains
additional preserved test artifacts and therefore reports the evidence
mismatch (`1709` recorded CI entries versus `3038` observed during the run).
The `.ci/` tree was not deleted, relocated, or staged. A clean GitHub checkout
does not contain that untracked tree and is the authoritative environment for
the corresponding CI result.

The latest complete local regression for the current working candidate, with
only that historical artifact-snapshot assertion deselected, completed with
**949 passed, 84 skipped, 1 deselected, 15 warnings**, exit code **0**. The
four formerly obsolete Windows-only skip vectors were active in this run and
passed. The JUnit report is retained at:

- `.project-temp/section-b-full-regression-20260911-003/full-suite.xml`

The 84 skips were explicitly classified as environment/dependency or
platform capability conditions: 37 isolated-PostgreSQL assurance skips, 29
isolated-PostgreSQL integration skips, one live-Redis assurance skip, two
managed Subfinder availability skips, one managed Nmap availability skip,
one historical provenance fixture skip, and the remaining POSIX/symlink
platform skips. No obsolete Windows Job Object skip remained. This is local
evidence only; the historical `.ci/` snapshot assertion was the sole
deselected test and the current candidate has not yet been published to or
verified by GitHub Actions.

The preceding local candidate run remains retained as historical evidence at
`.project-temp/section-b-full-no-inventory-20260911-001/` with its original
937-pass count; it is not the latest candidate result.

An unfiltered run was performed before the final cancellation compatibility
correction and reported two failures: the preserved `.ci/` snapshot mismatch
described above and the Windows PID-only status assertion. The latter was
corrected, and the targeted cancellation rerun plus the complete scoped
regression then passed. No unfiltered full-suite pass is claimed because the
preserved artifact-snapshot assertion remains a known mismatch; the user-owned
`.ci/` evidence tree was not changed.

## Protected database evidence

The exact authorized read-only fingerprint check for `data/cyberassess.db`
reported:

```text
length: 10285056
mtime_utc: 2026-09-04T23:24:42.6548237Z
sha256: 7a5a019389f69574b7bae31c355efeeed47fbe9f203e2c2a65c946e21cba6ecc
```

The file was not modified, staged, committed, mirrored, archived, or used as
the test database. All SQLite tests used project-local disposable paths under
`.project-temp/`; the PostgreSQL suite used a separate disposable container.

## Runtime and deployment limitations

- No real security scan or unrestricted external target activity was run.
- The local POSIX proof is process-container evidence only; it does not prove
  PID-reuse or every membership-race permutation. The native Windows vectors
  below are local implementation evidence and do not replace the independent
  Windows CI execution or auditor acceptance required for Windows assurance.
- `CYBERASSESS_WORKER_GENERATION` and `CYBERASSESS_WORKER_IDENTITY` are
  deployment-configured. The enterprise Compose definition requires the same
  explicit values for the API and worker services, and the process boundary
  revalidates non-scan contexts against the active deployment binding. A
  production deployment must still provision and verify those values;
  otherwise the durable launch fence is expected to reject the mismatch. This
  remains an explicit runtime verification item, not a claim of deployment
  assurance.
- Managed Nmap and Subfinder runtime/artifact evidence remains environment
  dependent and is not established by this Section B lifecycle pass.
- Docker Compose network separation is not destination-level egress
  enforcement; the existing enterprise egress limitation remains documented.

## Delivery and remaining gates

The current published Section B baseline is the grouped GitHub-first
publication at `0a76593045e9d9957bfa1c601d36b2d19b77ee4c` on
`security/nmap-installer-closure`, with the successful run and job records
above. The strict queue and process-boundary changes documented as the current
candidate remain unpublished pending independent auditor acceptance. GitLab
was intentionally not promoted for this auditor-bounded pass. This evidence
update does not change the implementation or lifecycle acceptance status.
`AGENTS.md`, the pre-existing `.ci/` evidence tree, and other pre-existing
`.project-temp/` artifacts remain outside the staged delivery scope. Their
presence means the working directory is not a policy-clean tree for GitLab
promotion; no GitLab publication is permitted until that policy condition is
resolved without deleting or relocating those artifacts.

The following evidence remains required before lifecycle acceptance:

- Independent review of the current worker preflight and settlement diff,
  including the absence of direct worker bypasses.
- Deployment evidence for a shared, explicitly provisioned worker generation
  between approval and worker processes.
- Independent OS-level process-container, restart-attachment, PID-reuse,
  membership-race, and Windows Job Object evidence beyond the local POSIX and
  local Windows vectors.
- Managed Nmap/Subfinder runtime and artifact-provenance evidence where the
  environment permits it.
- Independent auditor review of the exact published commit, test artifacts,
  runtime evidence, database fingerprint, and unresolved limitations.

Until those gates are complete, `docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`
must remain `OPEN` / `REWORK / IN PROGRESS`.
