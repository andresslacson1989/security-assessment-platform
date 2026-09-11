# Section B Execution-Lifecycle Evidence — 2026-09-11

Status: implementation evidence recorded for the current Section B rework
candidate; independent acceptance remains open.

This addendum records the durable approval-to-dispatch and cancellation-
coordination implementation pass, including the subsequent authority-to-launch
preflight, exact identity settlement rework, PostgreSQL settlement correction,
explicit deployment identity/generation binding, process-session emptiness
checking, zombie-member handling, and explicit recovery blocking when root
ownership is no longer independently provable at the
current published code baseline `0a76593045e9d9957bfa1c601d36b2d19b77ee4c`.
The current unpublished closure candidate additionally enforces explicit
authoritative-versus-legacy queue classification, strict failure evidence and
quarantine-state schemas, exact evidence digests, atomic quarantine
publication, and compare-and-swap recovery acknowledgement. Those local
changes are recorded below and are not represented by the published baseline.
It is evidence for the Section B review and does not claim that the
execution-lifecycle closure matrix is accepted.

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
available, reloads the durable process identity after a worker restart, and
preserves a recoverable state for `NOT_FOUND`, `FAILED`, missing mappings, or
an unjoined task. Positive `NO_EXTERNAL_PROCESS` evidence is settled through a
durable no-process path and is never inferred from a missing PID. Only the
durable `EXECUTION_CANCELLED_BEFORE_DISPATCH` transition is accepted as the
pre-dispatch no-process proof.

The post-revocation settlement primitive validates all authority, tenant,
identity, dispatch, run, and recovery fences before its first write and records
an auditable termination-proof digest. A current, still-valid authorization
cannot use that primitive as a replacement for the ordinary authority-held
finish path. No schema or migration change is part of this section.

The queue closure candidate makes the wire classification explicit. Production
execution intents are `AUTHORITATIVE_EXECUTION`; diagnostic compatibility
messages are `LEGACY_DIAGNOSTIC`. A missing, malformed, conflicting, unknown,
non-string, or credential-bearing message field is rejected before handler
entry and cannot fall through to legacy acknowledgement. Failure evidence is
allowlisted and canonicalized without caller-payload passthrough. Quarantine
state stores the canonical evidence, its digest, a top-level state digest, and
the validated tenant/request relationship. Quarantine state, operational
marker, failure event, and the optional bounded acknowledgement are governed
by fail-closed Redis transactions. Explicit recovery requires a typed,
tenant-bound operator assertion; the queue primitive itself does not
authenticate an arbitrary actor string. The acknowledgement transaction uses
an exact state compare and requires a successful `XACK` before deleting the
durable quarantine record.

The changed implementation files in this candidate are:

- `backend/app/core/db.py`
- `backend/app/core/execution_service.py`
- `backend/app/core/observation_service.py`
- `backend/app/core/orchestrator.py`
- `backend/app/core/process_supervisor.py`
- `backend/app/core/queue.py`
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
- `tests/test_adapters.py`
- `tests/test_e13_process_isolation.py`
- `tests/security/test_code_sast_assurance.py`
- `tests/security/test_nmap_assurance.py`

The current Section B candidate also adds a fail-closed deployment binding:
production execution identity and generation now require explicit environment
configuration, and the enterprise Compose API and worker services require the
same provisioned values. Development/test mode retains its deterministic local
fallback so isolated unit tests do not become deployment configuration tests.
Non-scan contexts are revalidated against that binding at the process-launch
boundary. If an enterprise egress rejection is already active, the supervisor
returns the egress rejection before identity diagnostics; otherwise a missing
or mismatched deployment binding is rejected before process creation. Windows
governed execution remains unsupported until a verified Job Object or
equivalent kernel-owned containment implementation exists. Non-scan launches
retain their separate non-authoritative capability, but Windows termination or
recovery that cannot prove the process container is surfaced as
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
- Current full repository suite for this unpublished candidate from a fresh
  unique disposable SQLite path, excluding only that same preserved historical
  worktree snapshot assertion: **886 passed, 85 skipped, 1 deselected, 14
  warnings**, exit code **0**. Windows process-tree termination vectors remain
  platform-gated; explicit Windows recovery rejection and non-scan uncertainty
  behavior are tested separately. The excluded inventory assertion remains a
  known local failure because the preserved `.ci/` tree is larger than its
  historical snapshot.
- Local PostgreSQL and Redis integration could not be rerun because Docker is
  unavailable on this host and no approved local service URLs were provided.
  The authoritative PostgreSQL evidence for this baseline is the successful
  GitHub Actions PostgreSQL 16 job recorded below; no local substitute is
  claimed.
- Current queue/quarantine closure command against the unpublished working
  tree, with an explicit disposable SQLite path and project-local pytest base:
  **71 passed, 38 skipped**, exit code **0**. This verifies explicit wire
  classification, strict unknown/non-string/credential-bearing evidence
  rejection, malformed binding rejection, atomic quarantine publication,
  durable original-failure evidence and both evidence/state digest bindings,
  no credential persistence, compare-and-swap acknowledgement, and tamper
  rejection.
- Current process-boundary command against the unpublished working tree, with
  an explicit disposable SQLite path and project-local pytest base: **13
  passed, 4 skipped**, exit code **0**. This verifies the fresh complete
  POSIX member-identity snapshot requirement, root/session/process-group
  vectors, membership race behavior, explicit Windows fail-closed recovery,
  and explicit Windows fail-closed recovery behavior. The four skips are the
  existing Windows-inapplicable POSIX vectors; they are not reported as
  Windows passes.
- Current affected-path compatibility regression after the Windows policy and
  queue-envelope fixture updates: **17 passed, 8 skipped**, exit code **0**.
  The skips are platform-inapplicable POSIX process-tree assertions and are
  separate from the explicit Windows fail-closed tests.
- Combined local authority, queue, replay, and process regression against the
  unpublished working tree, with a unique project-local SQLite database and
  project-local pytest base: **84 passed, 42 skipped, 1 warning**, exit code
  **0**. The live Redis vector remains environment-gated and was not claimed
  locally because Docker/service availability is absent.
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
container-local proof is the available local OS-level evidence; Windows
governed external execution remains fail-closed until its Job Object
implementation and independent platform evidence exist. Non-scan Windows
launches remain non-authoritative, but unconfirmed termination is explicitly
reported as uncertain. The local session-emptiness assertion is therefore
recorded as an environment skip, not as a Windows pass.

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
  PID-reuse or every membership-race permutation, and it does not provide the
  missing Windows Job Object evidence. The explicit Windows recovery test
  verifies only fail-closed behavior, not Windows containment assurance.
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
  membership-race, and Windows fail-closed evidence beyond the local POSIX
  vector.
- Managed Nmap/Subfinder runtime and artifact-provenance evidence where the
  environment permits it.
- Independent auditor review of the exact published commit, test artifacts,
  runtime evidence, database fingerprint, and unresolved limitations.

Until those gates are complete, `docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`
must remain `OPEN` / `REWORK / IN PROGRESS`.
