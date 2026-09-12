# Section B Execution-Lifecycle Follow-up — 2026-09-12

Status: implementation evidence update; independent acceptance remains open.

This dated follow-up records the current Section B verification pass. It does
not rewrite or supersede the historical record in
`docs/evidence/section_b_execution_lifecycle_2026-09-09.md`; that document
continues to preserve the evidence and limitations known at that time.

## Authority and scope

The accepted implementation baseline is commit
`66d609bb9c1a9ce83b44d50868d3d8ecac471e27` on
`security/nmap-installer-closure`, with tree
`99f2333f2e27886188b1b331ee694bb4f353b5cc`. GitHub is the authoritative
publication and GitHub Actions is the authoritative CI provider. The same
baseline commit is present on the governed GitLab mirror, but GitLab is not an
acceptance gate.

The current Section B follow-up is deliberately bounded to:

1. correcting a readiness-marker race in the Windows non-scan process-boundary
   assurance test; and
2. reconciling current lifecycle and traceability documentation with the
   accepted baseline and the evidence recorded here.

The production process supervisor, worker handoff, execution authority,
database schema, tool registry, installer registry, and contract semantics are
unchanged by the follow-up implementation. No tool was removed or disabled.

The authoritative contract clauses reviewed for this pass are:

- Contract 03, §1.1.3 and §3: service-owned authority, durable process
  ownership, recovery, and centralized process supervision;
- Contract 04, §§1.1.1, 1.3, 1.3.1, 1.5.1, and 1.5.2: authentication-side-effect
  isolation, scan dispatch, durable history, capability status, and the
  backend-owned observation lifecycle; and
- Contract 08, §§6.1.2, 6.1.3, and 6.6: authentication/observation vectors,
  persistence vectors, and production-boundary cross-cutting vectors.

## Implementation correction

`tests/security/test_process_launch_boundary.py` previously treated marker
existence as proof that the child PID had been completely written. On Windows,
`Path.write_text()` can expose the file between truncation and completion of
the write. The test now waits for a parseable UTF-8 PID for both the timeout
and cancellation readiness markers. This removes a test-observation race; it
does not weaken the process boundary, cancellation, Job Object, or
post-launch-uncertainty assertions.

The failed pre-correction full run established the cause: the only test
failure was
`test_windows_non_scan_timeout_output_cancellation_and_exception_are_typed`,
which attempted to parse an empty marker. The resulting unjoined-task log was
a consequence of the assertion aborting before the test could cancel and join
the child; it was not evidence of an accepted process-supervisor result.

## Local verification ledger

All successful and valid test runs, databases, temporary directories, logs,
and JUnit reports below are under the project-local
`.project-temp/section-b-execution-closure-20260912/` root. Two failed
diagnostic invocations initially omitted the disposable database variable;
their import-time migration guard reached `data/cyberassess.db` and stopped
before test collection or application work. The protected file was
fingerprinted immediately after each invocation and its length, timestamp,
and SHA-256 were unchanged. Those accidental guard checks are recorded as
protected-path inspection evidence, not as successful test runs.

| Evidence | Result | SHA-256 |
| --- | --- | --- |
| `focused-contract-no-inventory-rerun-001/focused-contract-no-inventory.log` | 300 passed, 47 skipped, 1 historical `.ci` inventory assertion deselected | `8fb70f92cc0571c3e21fd0ddf5b7636949e78eb5dda7760cdb313eb45591974e` |
| `focused-contract-no-inventory-rerun-001/focused-contract-no-inventory.xml` | JUnit for the focused run above | `8364508f8cf7a7fa512df8d1990daeabbffedc1a534209962e6635926b633be7` |
| `windows-cancellation-vector-002/windows-cancellation-vector.log` | Corrected Windows vector: 1 passed | `e3394a0ed6077b9921d4082399e794bbc985d592e71dab2a411da65acf14b895` |
| `windows-cancellation-vector-repeat-001/repeat-summary.log` | Corrected Windows vector: 3 consecutive isolated passes | `da7f95d3b459a39a38dfb9a7d6df2a3ffd45453652db72014a4cb8ac9a3116fe` |
| `process-boundary-final-002/process-boundary-final.log` | Final staged-candidate process-boundary run: 22 passed, 8 skipped | `26AE5F0CF18B1FED943C25A8BE1118E4891CF6965B4FF765540A5E7883AB13D4` |
| `full-regression-no-inventory-002/full-regression-no-inventory.log` | 950 passed, 85 skipped, 1 historical `.ci` inventory assertion deselected | `3e92a4e9348b355d8fe562253124d4979b07095bca94f80b11048e2b23b9239d` |
| `full-regression-no-inventory-002/full-regression-no-inventory.xml` | JUnit for the full run above | `5d8110d6d0019ad12c943324f44f43fe17f2c93e1764603d759d9e3c7bc9ee95` |
| `full-regression-no-inventory-002/skip-classification.txt` | 85 explicit skip reasons | `cd8adcf7e15ee628f5cf1e4db875f49c37db050ba70f4d1d210745e6a63f85f7` |
| `focused-contract-final-001/focused-contract-final.log` | Post-documentation focused run: 300 passed, 47 skipped, 1 historical `.ci` inventory assertion deselected | `6136001fba82962e06a4b6b14f78c6ddc33944f07eeeb5686b0ac2876b992b66` |
| `focused-contract-final-001/focused-contract-final.xml` | JUnit for the post-documentation focused run | `eac62392616b41e480490023808ee57ba4472f06ac904c6e32f7f1564cef2e71` |
| `launch-inventory-final-002/launch-inventory.log` | Checked-in launch inventory: 12 passed | `99d25c0fedf5aed7d21afff50f489f71aa4ecba42c04a40dcadfb3c6c54dfdf0` |
| `launch-inventory-final-003/production-launch-ast-inventory.txt` | 131 production files inspected; 73 classified launch calls; direct `Popen` and `subprocess.run` paths confined to the supervisor | `18d09b0c9f67f2bf38af4d3af9bd7cd301c93e1a979dca2748eb0134f7d0ca02` |

The deselected inventory assertion is
`test_worktree_inventory_snapshot_matches_documented_git_serialization`.
It compares the preserved untracked `.ci/` evidence tree with an older
recorded count. The current tree has accumulated additional artifacts. The
`.ci/` tree was not deleted, relocated, or staged; a clean CI checkout does
not contain this untracked worktree artifact. This is a local worktree-evidence
condition, not a product pass or a reason to rewrite the historical snapshot.

The 85 local skips are not passes. They are explicitly attributable to
missing isolated PostgreSQL assurance configuration (37), missing isolated
PostgreSQL integration configuration (29), POSIX-only process vectors on
Windows (7), Windows symlink privilege constraints (4), unavailable managed
Subfinder v2.6.5 (2), one unavailable symlink fixture (1), one unavailable Unix
session fixture (1), unavailable live Redis Streams configuration (1), the
historical v1 provenance fixture mismatch (1), and unavailable managed Nmap
(1). The complete classification is retained in
`full-regression-no-inventory-002/skip-classification.txt`.

The suite also reports pre-existing warning-only test hygiene observations in
the acceptance-scenario mocks and a pytest cache warning in one diagnostic
run. They do not alter the pass/fail result, but they are not represented as
zero-warning evidence.

`python -m compileall -q backend/app backend/tests run_worker.py run_platform.py`
completed with exit code 0 and no compiler output. Its bytecode output was
redirected to a project-local `PYTHONPYCACHEPREFIX` under the evidence root.

## Production launch inventory and lifecycle mapping

The AST inventory and `backend/tests/test_execution_launch_inventory.py`
confirm the following current production boundary:

- the only production `subprocess.Popen` call is
  `backend/app/core/process_supervisor.py:1910`;
- the only production `subprocess.run` calls are the bounded process-identity
  observations in `backend/app/core/process_supervisor.py`;
- Windows process creation is confined to `CreateProcessW` in
  `backend/app/core/windows_job.py`;
- adapters route through `BaseToolAdapter` and the supervisor, while installer
  and observation work uses the separately issued non-scan context;
- scan workers use the single public
  `ScanOrchestrator.execute_dispatched_scan()` handoff; and
- no production direct `os.system`, `os.popen`, or asyncio subprocess launch
  was identified by the inventory.

| Lifecycle matrix row | Implementation and exact repository evidence | Current evidence category | Remaining gate |
| --- | --- | --- | --- |
| Typed durable identity | `backend/app/core/execution_context.py`, `execution_service.py`, `execution_decision.py`, `scan_execution_authority.py`; `backend/tests/test_execution_context_contract.py`, `backend/tests/test_execution_launch_inventory.py`, and execution-decision tests | configured, unit-tested, locally executed, CI-executed on accepted baseline | independent auditor review of the complete current delivery |
| Complete launch coverage | `backend/tests/test_execution_launch_inventory.py`; adapter/base-adapter, installer, engine, worker, and supervisor call sites | statically inventoried, locally executed, CI-executed on accepted baseline | independent production-path review and current exact-commit CI |
| Run-level process ownership | `backend/app/core/process_supervisor.py`, `windows_job.py`, `execution_service.py`, `db.py`; process-boundary and decision-authority vectors | locally executed and CI-executed on accepted baseline; Windows vector rechecked locally | broader independent OS/deployment evidence and auditor acceptance |
| Durable restart attachment | `execution_service.py`, `observation_service.py`, `windows_job.py`; restart, tamper, replay, and recovery tests | unit-tested and locally executed; supported-platform CI evidence on accepted baseline | shared worker deployment evidence and independent restart/platform evidence |
| Single cancellation coordinator | `execution_service.py`, `orchestrator.py`, `observation_service.py`; cancellation-coordinator and API vectors | locally executed and CI-executed on accepted baseline | current exact-commit CI plus independent review |
| Durable recovery | `db.py`, `execution_service.py`, `observation_service.py`; SQLite recovery vectors and PostgreSQL workflow definition | SQLite locally executed; PostgreSQL CI-executed on accepted baseline | current-candidate PostgreSQL/Redis runtime evidence and deployment proof |
| Contract and operational proof | Contracts 03/04/08, lifecycle matrix, traceability matrix, this follow-up, GitHub workflow | documentation reconciled; focused/full local evidence; accepted-baseline CI evidence | exact follow-up GitHub run and independent auditor acceptance |

Rows remain `OPEN` in the authoritative lifecycle matrix unless both the
implementation and the required independent/platform evidence are complete.

## CI, runtime, and mirror boundary

The accepted baseline GitHub Actions run is
[34659175863](https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34659175863)
for the exact accepted SHA. Its required compile, focused, full, PostgreSQL,
Windows Job Object, and hardened-container jobs succeeded. That result is
baseline evidence; the grouped follow-up delivery requires a fresh GitHub run
for its own exact SHA before it can be accepted.

The current repository does not provide independent deployment evidence that
the enterprise API and worker have been started with the same explicitly
provisioned `CYBERASSESS_WORKER_IDENTITY` and
`CYBERASSESS_WORKER_GENERATION`. The Compose file requires those values, but a
required environment declaration is not runtime proof. This gate remains
`UNVERIFIED`.

Managed Nmap and Subfinder runtime evidence is unavailable in the current
local environment. The skips above are retained as unavailable/unverified;
no runtime result or provenance claim is fabricated.

Docker Compose network separation remains a container-network boundary, not
dynamic destination-level egress enforcement. Provider egress governance is
therefore not claimed complete by this evidence.

No GitLab operation was performed during this follow-up. GitLab promotion is
blocked until the new grouped commit has passed the GitHub-first publication
and independent-auditor gates.

## Protected database and worktree state

The explicitly authorized read-only fingerprint of
`data/cyberassess.db` remains:

- length: `10285056` bytes;
- last-write UTC: `2026-09-04T23:24:42.6548237Z`; and
- SHA-256: `7a5a019389f69574b7bae31c355efeeed47fbe9f203e2c2a65c946e21cba6ecc`.

All valid test and migration runs used separate project-local disposable
database paths. The two failed import-time diagnostics described above
reached the protected path only to hit its migration-identity guard; no write
was observed, and the immediately repeated fingerprint was unchanged. The
protected database was not staged, committed, mirrored, archived, or used as
a test fixture.

The delivery scope contains only the bounded test correction and current
traceability documentation. The worktree as a whole is not clean because the
pre-existing modified `AGENTS.md` and untracked `.ci/`, `.project-temp/`,
`v/`, and GitLab mirror-evidence artifacts are preserved and excluded from the
delivery scope. They must not be deleted or staged to manufacture a clean
status.

## Acceptance status

This follow-up improves the evidence quality and removes the demonstrated
Windows assurance-test race. It does not close the lifecycle matrix. The
remaining open criteria are deployment worker binding, current exact-commit
GitHub CI, independent platform/restart/Redis/PostgreSQL evidence where not
available, managed-tool runtime evidence, clean delivery scope, and auditor
acceptance.
