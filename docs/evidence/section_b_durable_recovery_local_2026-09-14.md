# Section B durable-recovery local evidence — 2026-09-14

## Scope

This record covers the uncommitted Section B durable-write/recovery candidate
on branch `security/nmap-installer-closure` at base commit
`49f9cc19589a203c87e55d272f9bc4c0a086c3aa`. It is local evidence only. It
does not claim GitHub Actions execution, deployment verification, PostgreSQL
assurance, GitLab mirror status, or independent auditor acceptance.

## Contract binding

Contract 08 §6.1.2 requires database operations which outlive an async timeout
to remain tracked and not cause an unobserved late mutation. Contract 04's
recovery-health boundary requires authenticated, tenant-scoped operator
visibility without exposing process identity as authority.

## Implementation under test

- `backend/app/core/observation_service.py`
  - durable-write identity and request-fingerprint conflict detection;
  - an owned `concurrent.futures.Future` isolated from cancellable async
    waiters;
  - bounded shutdown that never cancels a running database call;
  - restart fencing while an owned durable write or cancellation-resistant
    recovery worker remains unresolved;
  - recovery from the durable database projection after an unavailable event
    loop callback.
  - exact supervisor cancellation ownership on the durable-identity production
    path, keyed by execution, tenant, process-proof fingerprint, recovery
    generation, and lease/attempt fingerprint; late supervisor completion
    cannot terminalize a timed-out recovery callback. Legacy compatibility
    doubles without the durable identity API remain future-owned and
    conservative, but are explicitly non-attested.
  - a shared execution-plus-organization pending-operation gate that consumes
    completed supervisor futures before uncertain lease claim or governed
    supervisor submission; an unfinished exact cancellation leaves the
    retryable durable projection unchanged and blocks a second lease, attempt,
    or invocation.
- `tests/test_observation_service.py`
  - timeout, caller cancellation, bounded shutdown, late failure, identical
    join, conflicting-payload rejection, fresh-lifecycle reconciliation,
    cancellation-resistant worker, and closed-loop callback vectors.
  - governed and uncertain duplicate-cadence fencing, including retry only
    after the original supervisor future is consumed.
- `tests/security/test_execution_quarantine_api.py`
  - real authenticated observer-created and supervisor-timeout
    recovery-health route vectors.

## Local execution

All test outputs and disposable databases were redirected beneath the
project-local `.project-temp` directory. `PYTHONPATH` targeted `backend`, byte
code generation was disabled, and `CYBERASSESS_DB_PATH` pointed to a disposable
SQLite path for each suite.

| Command scope | Result | Qualification |
| --- | --- | --- |
| `python -m pytest -p no:cacheprovider -q tests/test_observation_service.py -k "supervisor_timeout_remains_owned or supervisor_timeout_does_not_overlap or uncertain_supervisor_timeout_does_not_claim_second_recovery_lease or late_supervisor_result or late_supervisor_failure"` | `5 passed, 31 deselected in 17.63s` | Exact-supervisor ownership vectors cover governed and uncertain branches; the uncertain vector proves no second recovery lease/attempt/invocation while the first future is blocked and retry only after consumption. Disposable SQLite. |
| `python -m pytest -p no:cacheprovider -q tests/test_observation_service.py` | `36 passed in 47.87s` | Full local disposable SQLite observer suite after the pending-operation gate. |
| `python -m pytest -p no:cacheprovider -q tests/security/test_execution_quarantine_api.py` | `6 passed, 1 warning in 13.13s` | Warning is the external Starlette/TestClient `httpx` deprecation; it is not a skipped test or a pass/fail suppression. |
| `python -m pytest -p no:cacheprovider -q tests/security/test_execution_quarantine_api.py::test_recovery_health_exposes_supervisor_timeout_from_production_observer` | `1 passed, 1 warning in 6.00s` | Final focused production-observer route proof with a scheduling-safe timeout budget; the warning is the external Starlette/TestClient `httpx` deprecation. |
| `python -m pytest -p no:cacheprovider -q tests/security/test_execution_quarantine_api.py` | `7 passed, 1 warning in 17.58s` | Full route suite after the pending-operation gate; the warning is the external Starlette/TestClient `httpx` deprecation. The response does not expose `attempt_number`, so no route assertion was added. |
| Exact 15 observer/route nodes listed in `.github/workflows/contract-verification.yml` | `15 passed, 1 warning in 27.19s` | Local execution of every Section B observer/route workflow node, including the uncertain lease-fencing vector, using disposable SQLite; the warning is the external Starlette/TestClient `httpx` deprecation. |
| Earlier combined `python -m pytest -p no:cacheprovider -q tests/security/test_execution_quarantine_api.py` plus six non-inventory contract-consistency nodes | `12 passed, 1 warning in 16.77s` | Historical combined result before the final timeout-budget correction. The warning is the external Starlette/TestClient `httpx` deprecation. The contract nodes cover 26-tool preservation, provider/database delivery policy, historical Section A validation, mutation rejection, and contract-mirror scope. The final route suite and exact observer nodes were rerun separately after the correction. |
| `python -m pytest -p no:cacheprovider -q backend/tests/test_execution_launch_inventory.py tests/security/test_execution_decision_authority.py tests/security/test_execution_cancellation_coordinator.py tests/security/test_real_dispatch_authority_assurance.py` | `159 passed, 41 skipped in 197.47s` | Local disposable execution after the pending-operation gate. The 41 platform/dependency-gated vectors are skipped, not treated as passing evidence. |

`tests/security/test_contract_fleet_consistency.py` produced six passing checks
and one known failure: the historical worktree inventory expects 1,709 `.ci`
entries while the current read-only `.ci` tree contains 3,038. This record does
not treat that result as a contract pass or repair it; `.ci`, its inventory
snapshot, and ignore rules are outside this Section B scope.

At the final local Section B source audit, the read-only `.ci` porcelain
inventory remained exactly 3,038 entries. Its path SHA-256 was
`c0307dd79db3d48d05ae753b5de9bafcbb14b3a15b8f5d831afc4c13d1a6984c` and its
state-plus-path SHA-256 was
`25f7e934dc03cc6493e005a99145f56c94f8411c3061587e80139b927e1fd67c`.

## Runtime database preservation

The repository runtime database was not used by these tests. Before the
focused validation, `data/cyberassess.db` had SHA-256
`7A5A019389F69574B7BAE31C355EFEEED47FBE9F203E2C2A65C946E21CBA6ECC` and UTC
modification time `2026-09-04T23:24:42.6548237Z`. It remained outside test and
delivery scope. One initial contract-consistency invocation was stopped after
it reached import-time migration-ledger validation without a disposable
database path; the same SHA-256, modification time, and file length were
observed afterward. All subsequent database-backed validation used a distinct
disposable path under `.project-temp`.

## Observer background-operation source audit

| Operation class | Actual work handle | Timeout and shutdown ownership | Durable/process effect | Second-cadence behavior |
| --- | --- | --- | --- | --- |
| Capability/toolbox refresh | Current observer lifecycle task | `refresh_once` uses a single-flight lock and bounded async wait; normal lifecycle cancellation owns the task. | Observational only; it does not settle a run. | Concurrent ticks return without overlapping refresh. |
| Recovery-candidate, process-identity, ownership, and run reads | `asyncio.to_thread` waiter only | Bounded read-only waits may outlive their waiter, but cannot create a process action or durable mutation. | Read-only. | A later cadence may reread authoritative durable state. |
| Durable database mutation | `_DURABLE_WRITE_EXECUTOR` `concurrent.futures.Future` in `_pending_durable_writes` | Timeout/cancellation/shutdown leave the actual future owned; restart is fenced until completion. | Existing tenant/lease/proof compare-and-swap mutation. | Identical calls join; conflicting payload fingerprints reject. |
| Exact supervisor cancellation (durable-identity path) | `_SUPERVISOR_CANCELLATION_EXECUTOR` `concurrent.futures.Future` in `_pending_supervisor_cancellations` | Timeout/cancellation/shutdown leave the actual future owned and never cancel a started process operation; restart is fenced until completion. | May inspect/terminate only the exact attested process identity; callback cannot settle a timed-out recovery. | The shared execution-plus-organization gate reconciles completed futures before an uncertain lease claim or governed supervisor submission. An unfinished future leaves the retryable durable projection unchanged and blocks a second lease, attempt, or invocation; a later cadence may retry after completion is consumed. Identical binding joins; changed proof, tenant, generation, lease, or attempt fingerprint rejects. Legacy compatibility doubles without durable identity remain owned but non-attested. |
| Lifecycle and cancellation-resistant recovery tasks | `_task`, `_stopping_lifecycle_task`, and `_recovery_workers` | Bounded await; unresolved task remains tracked and blocks same-instance restart. | Lifecycle coordination only; not used to own thread-backed database or supervisor work. | Restart remains fenced while unresolved. |

## Remaining acceptance gaps

- focused GitHub Actions and full repository verification for the exact
  candidate commit;
- actual PostgreSQL row-lock/concurrency assurance;
- deployed, authenticated recovery-health evidence with a non-empty recovery
  queue;
- clean delivery scope and the known `.ci` inventory discrepancy;
- GitHub-first publication, required GitHub Actions jobs, exact-SHA GitLab
  mirror verification, and independent auditor acceptance.

## Current corrective closure checkpoint

The following local commands were executed after the pending-operation gate and
test changes. Each command used `PYTHONDONTWRITEBYTECODE=1`, a
`PYTHONPYCACHEPREFIX` beneath
`E:\web apps\security-assessment-platform\.project-temp\section-b-supervisor-ownership-20260914\pycache`,
`--basetemp` beneath the same project-local run directory, and a disposable
`CYBERASSESS_DB_PATH`; none targeted `data/cyberassess.db`.

| Evidence command | Result | Project-local output |
| --- | --- | --- |
| Focused supervisor vectors, including governed and uncertain overlap | `5 passed, 31 deselected in 17.63s` | `.project-temp/section-b-supervisor-ownership-20260914/targeted-2.log` |
| Full observer suite | `36 passed in 47.87s` | `.project-temp/section-b-supervisor-ownership-20260914/observer-full.log` |
| Full authenticated recovery-health/quarantine route suite | `7 passed, 1 warning in 17.58s` | `.project-temp/section-b-supervisor-ownership-20260914/route-full.log`; warning is the external Starlette/TestClient `httpx` deprecation |
| Exact observer/route workflow node set after adding the uncertain vector | `15 passed, 1 warning in 27.19s` | `.project-temp/section-b-supervisor-ownership-20260914/workflow-observer.log`; warning is the external Starlette/TestClient `httpx` deprecation |
| Broader execution/security regression suites | `159 passed, 41 skipped in 197.47s` | `.project-temp/section-b-supervisor-ownership-20260914/broader.log`; all skips are explicit platform/dependency-gated skips and are not counted as passes |
| `python -m pytest -p no:cacheprovider -q --basetemp=<project-local> tests/security/test_contract_fleet_consistency.py::<seven explicitly selected nodes>` | `6 passed, 1 failed in 11.03s` | The sole failure is the known historical `.ci` inventory assertion (`1709` expected versus `3038` current read-only status entries). Git also emitted existing project-local generated-tree path-length warnings; this pass did not alter `.ci` or repair the snapshot. |
| `python -m compileall -q backend tests` | exit `0` | Non-fatal output: `Can't list 'backend\\.pytest_cache'`; bytecode/cache output was directed beneath the project-local run directory. |
| `git diff --check` | exit `0` | Git emitted only existing LF/CRLF normalization warnings for tracked working-copy files; no whitespace error was reported. |

The seven contract-fleet nodes were executed with
`CYBERASSESS_DB_PATH=E:\web apps\security-assessment-platform\.project-temp\section-b-supervisor-ownership-20260914\contract-consistency.sqlite3`
and this exact command shape from the repository root (the disposable
database and pytest base directory were beneath the same project-local run
directory):

```text
python -m pytest -p no:cacheprovider -q --basetemp=.project-temp/section-b-supervisor-ownership-20260914/contract-consistency-pytest \
  tests/security/test_contract_fleet_consistency.py::test_registry_manifest_and_installers_preserve_complete_26_tool_fleet \
  tests/security/test_contract_fleet_consistency.py::test_contract_05_provider_authority_and_database_delivery_policy \
  tests/security/test_contract_fleet_consistency.py::test_worktree_inventory_snapshot_matches_documented_git_serialization \
  tests/security/test_contract_fleet_consistency.py::test_section_a_delivery_candidate_manifest_covers_captured_non_ci_snapshot \
  tests/security/test_contract_fleet_consistency.py::test_historical_snapshot_transition_rejects_unsupported_or_forbidden_changes \
  tests/security/test_contract_fleet_consistency.py::test_manifest_string_locator_mutation_is_rejected \
  tests/security/test_contract_fleet_consistency.py::test_authoritative_contract_mirrors_and_scope_match_26_tool_fleet
```

The machine-readable final-state record is
`.project-temp/section-b-supervisor-ownership-20260914/final-state-v2.log`.
The final local source/worktree checkpoint for this pass recorded the
protected database fingerprint as SHA-256
`7A5A019389F69574B7BAE31C355EFEEED47FBE9F203E2C2A65C946E21CBA6ECC`, UTC
mtime `2026-09-04T23:24:42.6548237Z`, and length `10285056` bytes. The
read-only `.ci` inventory remained 3,038 untracked entries with path digest
`c0307dd79db3d48d05ae753b5de9bafcbb14b3a15b8f5d831afc4c13d1a6984c` and
state-plus-path digest
`25f7e934dc03cc6493e005a99145f56c94f8411c3061587e80139b927e1fd67c`; the
historical contract-fleet expectation remains 1,709, so its one known
inventory check failure is recorded rather than repaired. No file under `.ci`
was modified, moved, or deleted.
