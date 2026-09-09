# Section B Execution-Lifecycle Evidence — 2026-09-09

Status: implementation evidence recorded; independent acceptance remains open.

This addendum records the durable approval-to-dispatch and cancellation-
coordination implementation pass. It is evidence for the Section B review and
does not claim that the execution-lifecycle closure matrix is accepted.

## Scope

The implementation binds approved scan dispatch to the real orchestrator,
retains the distinction between queue acceptance and process creation, and
uses an atomic tenant-scoped Redis publication identity for exact approval
replays. Scan cancellation and direct execution-request revocation use the
same `ExecutionCancellationCoordinator`. The coordinator revokes authority
before exact execution-identity cancellation, joins an owning task when one is
available, verifies the durable child run, and preserves a recoverable state
for `NOT_FOUND`, `FAILED`, missing mappings, or an unjoined task. Only the
durable `EXECUTION_CANCELLED_BEFORE_DISPATCH` transition is accepted as a
no-process proof.

No migration or runtime database change is part of this section.

## Local verification

The following checks completed successfully:

- Focused execution/authority/API/security set: **275 passed, 1 documented
  platform skip, 7 warnings**. The new cancellation-coordinator vectors were
  included.
- Full local repository suite: **820 passed, 39 platform/dependency skips,
  14 warnings**.
- Real PostgreSQL 16 integration suite against a newly created disposable
  loopback `_ci` database: **29 passed**. The container was removed after the
  run.
- Python compilation of the backend and changed lifecycle test module: passed.
- `git diff --check`: passed.
- Mirrored Contract 04 copies: byte-identical.
- Mirrored Contract 08 copies: byte-identical.

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

## Delivery and remaining gates

The section changes are intended for one grouped GitHub-first publication.
`AGENTS.md`, the pre-existing `.ci/` evidence tree, and other pre-existing
`.project-temp/` artifacts remain outside the staged delivery scope. Their
presence means the working directory is not a policy-clean tree for GitLab
promotion; no GitLab publication is permitted until that policy condition is
resolved without deleting or relocating those artifacts.

The following evidence remains required before lifecycle acceptance:

- GitHub clean-checkout execution of all required jobs, including the focused
  cancellation test and the workflow's skip guards.
- Independent OS-level process-container, restart-attachment, PID-reuse,
  membership-race, and Windows fail-closed evidence.
- Managed Nmap/Subfinder runtime and artifact-provenance evidence where the
  environment permits it.
- Independent auditor review of the exact published commit, test artifacts,
  runtime evidence, database fingerprint, and unresolved limitations.

Until those gates are complete, `docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`
must remain `OPEN` / `REWORK / IN PROGRESS`.
