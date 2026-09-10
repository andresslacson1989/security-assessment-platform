# Section B Execution-Lifecycle Evidence — 2026-09-11

Status: implementation evidence recorded for the current Section B rework
candidate; independent acceptance remains open.

This addendum records the durable approval-to-dispatch and cancellation-
coordination implementation pass, including the subsequent authority-to-launch
preflight, exact identity settlement rework, and the PostgreSQL settlement
correction at code baseline `0e56c766ca96b046a5392d5e92e48dd02122c4f3`.
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

The changed implementation files in this candidate are:

- `backend/app/core/db.py`
- `backend/app/core/execution_service.py`
- `backend/app/core/observation_service.py`
- `backend/app/core/orchestrator.py`
- `backend/app/core/process_supervisor.py`
- `backend/tests/test_execution_launch_inventory.py`
- `run_worker.py`
- `tests/security/test_execution_cancellation_coordinator.py`
- `tests/security/test_execution_decision_authority.py`
- `tests/security/test_process_launch_boundary.py`
- `tests/test_observation_service.py`
- `tests/test_orchestrator.py`

The two documentation files in this addendum are the only evidence updates.
Contracts, migrations, `AGENTS.md`, the protected database, `.ci/`, and
`.project-temp/` remain outside the candidate delivery scope.

No migration or runtime database change is part of this section.

## Current local verification

The following checks were executed against code baseline
`0e56c766ca96b046a5392d5e92e48dd02122c4f3`. Every disposable SQLite database
was created under the project-local `.project-temp/` tree; the runtime
database was not used.

- Focused contract command, including the worker handoff, authority,
  cancellation, observation, process, and launch-inventory tests:
  **250 passed, 40 skipped**. The command also encountered the preserved
  historical worktree-inventory assertion; that assertion is the known
  user-owned `.ci/` evidence mismatch documented below and is not an
  application failure.
- Full local repository suite from a fresh unique disposable SQLite path,
  excluding only that preserved historical worktree snapshot assertion:
  **881 passed, 78 skipped, 1 deselected, 15 warnings**.
- Local PostgreSQL and Redis integration could not be rerun because Docker is
  unavailable on this host and no approved local service URLs were provided.
  The authoritative PostgreSQL evidence for this baseline is the successful
  GitHub Actions PostgreSQL 16 job recorded below; no local substitute is
  claimed.
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
governed execution remains fail-closed until its Job Object implementation and
independent platform evidence exist.

## GitHub Actions verification

The current code baseline was published first to GitHub as:

```text
commit: 0e56c766ca96b046a5392d5e92e48dd02122c4f3
ref:    security/nmap-installer-closure
run:    34532439910
url:    https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34532439910
```

The required GitHub Actions workflow completed successfully for that exact
commit. The independently inspected job records were:

| Job | Job ID | Result | Evidence |
| --- | ---: | --- | --- |
| Compile backend | 103056157028 | success | backend compilation completed |
| Focused contract verification | 103056156862 | success | focused contract suite and skip policy completed |
| Full repository verification | 103056157116 | success | full repository suite and skip classification completed |
| PostgreSQL 16 schema assurance | 103056156938 | success | PostgreSQL schema assurance completed |
| Hardened production image verification | 103056156569 | success | hardened image and health smoke checks completed |

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
  missing Windows Job Object evidence.
- `CYBERASSESS_WORKER_GENERATION` is deployment-configured. The current
  Compose definition does not itself demonstrate that the API approval process
  and the separate worker process receive the same generation value. A
  production deployment must provision and verify that binding; otherwise the
  durable launch fence is expected to reject the mismatch. This remains an
  explicit runtime verification item, not a claim of deployment assurance.
- Managed Nmap and Subfinder runtime/artifact evidence remains environment
  dependent and is not established by this Section B lifecycle pass.
- Docker Compose network separation is not destination-level egress
  enforcement; the existing enterprise egress limitation remains documented.

## Delivery and remaining gates

The previously accepted baseline implementation was delivered as one grouped
GitHub-first publication in `af65432c6ceae7e2b925e92b1b3ef9678ad46763`.
The current Section B rework candidate is the grouped delivery scope for this
section. Its exact commit, GitHub ref, GitHub Actions results, and any
GitLab-mirror result must be recorded in the final delivery report before the
section can be considered for independent acceptance. This evidence update
does not change the implementation or lifecycle acceptance status.
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
