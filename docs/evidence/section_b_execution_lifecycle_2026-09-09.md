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

## GitHub Actions verification

The grouped implementation commit was published first to GitHub as:

```text
commit: af65432c6ceae7e2b925e92b1b3ef9678ad46763
ref:    security/nmap-installer-closure
run:    34297542097
url:    https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34297542097
```

The required GitHub Actions workflow completed successfully for that exact
commit. The independently inspected job records were:

| Job | Job ID | Result | Evidence |
| --- | ---: | --- | --- |
| Compile backend | 102297309995 | success | backend compilation completed |
| Focused contract verification | 102297310227 | success | 193 passed, 1 allowlisted historical-provenance skip |
| Full repository verification | 102297310077 | success | 827 passed, 33 classified skips, 14 warnings |
| PostgreSQL 16 schema assurance | 102297310156 | success | 29 passed, 0 skipped |
| Hardened production image verification | 102297309878 | success | hardened image and health smoke checks completed |

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

The downloaded GitHub evidence files were retained under the pre-existing,
project-local `.project-temp/section-b-gh-evidence-34297542097/` directory.
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

## Delivery and remaining gates

The implementation changes were delivered as one grouped GitHub-first
publication in `af65432c6ceae7e2b925e92b1b3ef9678ad46763`. This documentation
update records the subsequent verification evidence and does not change the
implementation or the lifecycle acceptance status.
`AGENTS.md`, the pre-existing `.ci/` evidence tree, and other pre-existing
`.project-temp/` artifacts remain outside the staged delivery scope. Their
presence means the working directory is not a policy-clean tree for GitLab
promotion; no GitLab publication is permitted until that policy condition is
resolved without deleting or relocating those artifacts.

The following evidence remains required before lifecycle acceptance:

- Independent OS-level process-container, restart-attachment, PID-reuse,
  membership-race, and Windows fail-closed evidence.
- Managed Nmap/Subfinder runtime and artifact-provenance evidence where the
  environment permits it.
- Independent auditor review of the exact published commit, test artifacts,
  runtime evidence, database fingerprint, and unresolved limitations.

Until those gates are complete, `docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`
must remain `OPEN` / `REWORK / IN PROGRESS`.
