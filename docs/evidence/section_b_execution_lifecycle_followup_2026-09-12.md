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

The implementation and evidence candidate under review is commit
`285094882dca0108ad7a32eee2c230f668202956` on the same branch, with tree
`32cde38c6b003ee5ec7d6c35b17acd480ffe72db` and parent
`66d609bb9c1a9ce83b44d50868d3d8ecac471e27`. The GitHub branch ref resolves to
that exact candidate. The candidate contains the bounded Windows assurance-test
correction; the current document-only reconciliation records evidence
associated with that candidate. It does not change the production process
supervisor or execution contract. This reconciliation is delivered as a child
commit and does not alter the implementation or evidence run being reconciled.

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
| Typed durable identity | `backend/app/core/execution_context.py`, `execution_service.py`, `execution_decision.py`, `scan_execution_authority.py`; `backend/tests/test_execution_context_contract.py`, `backend/tests/test_execution_launch_inventory.py`, and execution-decision tests | configured, unit-tested, locally executed, and executed in current candidate run `34666036688` | independent auditor review of the complete current delivery |
| Complete launch coverage | `backend/tests/test_execution_launch_inventory.py`; adapter/base-adapter, installer, engine, worker, and supervisor call sites | statically inventoried, locally executed, and executed in current candidate run `34666036688` | independent production-path review and auditor acceptance |
| Run-level process ownership | `backend/app/core/process_supervisor.py`, `windows_job.py`, `execution_service.py`, `db.py`; process-boundary and decision-authority vectors | locally executed; current candidate Windows, full, and focused jobs passed in run `34666036688` | broader independent OS/deployment evidence and auditor acceptance |
| Durable restart attachment | `execution_service.py`, `observation_service.py`, `windows_job.py`; restart, tamper, replay, and recovery tests | unit-tested and locally executed; supported-platform evidence re-executed in current candidate run `34666036688` | shared worker deployment evidence and independent restart/platform evidence |
| Single cancellation coordinator | `execution_service.py`, `orchestrator.py`, `observation_service.py`; cancellation-coordinator and API vectors | locally executed and executed in current candidate run `34666036688` | independent review and auditor acceptance |
| Durable recovery | `db.py`, `execution_service.py`, `observation_service.py`; SQLite recovery vectors and PostgreSQL workflow definition | SQLite locally executed; PostgreSQL and Redis service readiness/suite evidence recorded in current candidate run `34666036688` | current-candidate deployment binding, broader independent runtime evidence, and auditor acceptance |
| Contract and operational proof | Contracts 03/04/08, lifecycle matrix, traceability matrix, this follow-up, GitHub workflow | documentation reconciled; focused/full local evidence and current-candidate CI evidence recorded below | current-candidate deployment/runtime gaps and independent auditor acceptance |

Rows remain `OPEN` in the authoritative lifecycle matrix unless both the
implementation and the required independent/platform evidence are complete.

## CI, runtime, and mirror boundary

The accepted baseline GitHub Actions run remains
[34659175863](https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34659175863)
historical evidence for the exact accepted baseline SHA. Its required compile,
focused, full, PostgreSQL, Windows Job Object, and hardened-container jobs
succeeded.

The current candidate was independently verified in GitHub Actions run
[34666036688](https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34666036688)
for exact SHA
`285094882dca0108ad7a32eee2c230f668202956`. The run was created at
`2026-09-12T01:51:27Z` and completed successfully at
`2026-09-12T02:00:50Z`. All six required jobs passed:

| Job | Job ID | Runner | UTC execution window | Result |
| --- | --- | --- | --- | --- |
| Compile backend | `103477994687` | `1000005352` | `2026-09-12T01:51:30Z`–`2026-09-12T01:51:49Z` | passed |
| Focused contract verification | `103477994674` | `1000005350` | `2026-09-12T01:51:30Z`–`2026-09-12T01:53:16Z` | passed; 337 passed, 11 skipped |
| Full repository verification | `103477994668` | `1000005351` | `2026-09-12T01:51:30Z`–`2026-09-12T02:00:49Z` | passed; 1022 passed, 14 skipped, 14 warnings |
| PostgreSQL 16 schema assurance | `103477994744` | `1000005354` | `2026-09-12T01:51:30Z`–`2026-09-12T01:52:45Z` | passed; 29 passed |
| Windows Job Object assurance | `103477994643` | `1000005349` | `2026-09-12T01:51:30Z`–`2026-09-12T01:52:19Z` | passed; 19 passed |
| Hardened production image verification | `103477994649` | `1000005353` | `2026-09-12T01:51:30Z`–`2026-09-12T01:58:28Z` | passed |

The retained workflow log at
`.project-temp/section-b-evidence-reconcile-20260912/github-34666036688/workflow-run.log`
has SHA-256
`975cc5caebd2c37d911b738bf5f9b42fdd7b5f83ead9dbc4ba23113b67742efb`. It
records checkout of the exact candidate, project-local CI paths, Redis
`7.2-alpine` and PostgreSQL `16-alpine` service startup, service readiness
checks, focused/full suite execution, report generation, and evidence upload.
The GitHub API artifact archive digests are:

| Artifact | Archive SHA-256 |
| --- | --- |
| `windows-job-object-evidence-34666036688` | `cdccffb5903fe642ce3679bffaf1c4bfc31a7e6958eb7dfee63b6086b0812942` |
| `postgres-schema-evidence-34666036688` | `ccf8c466071e9506eab66aeea6e508e7976f039611ebc670aa8016ecb63da843` |
| `full-repository-evidence-34666036688` | `1cd380aa192e4d52e176505d69451e1b2d66fa477f58cee28ddf1d58a929ee1c` |
| `focused-contract-evidence-34666036688` | `c13551c7dcb256239eb23b225738142831f28f934858b50a98848078bfeb440f` |

The downloaded evidence is retained below
`.project-temp/section-b-execution-closure-20260912/github-34666036688/`.
The API artifact manifest has SHA-256
`6d8cccc7991f32abcd8a8a7db5f4f16d4213ee69ff91dc283dcee00d8266ffc8`.
Retained extracted-file hashes are:

| Retained file | SHA-256 |
| --- | --- |
| `focused-contract-evidence-34666036688/focused-contract.log` | `158d028e483419f3324ecaecd906429f2d69412262e41cfebf81b85e82a66289` |
| `focused-contract-evidence-34666036688/focused-contract.xml` | `665e9aa3e2cfbc188b2a5717af2609ccc2abf3df4968a2a5d40d167517167614` |
| `full-repository-evidence-34666036688/full-suite.log` | `5d387d084d5557be0885ea02f514a981be0e5a1f56e767ed7fa51b0b965b2ae5` |
| `full-repository-evidence-34666036688/full-suite.xml` | `6ccd3a956742e73569941b262ad0bdc210d913d441b4a05d2b064d385deeb222` |
| `full-repository-evidence-34666036688/full-suite-skip-classification.txt` | `fe9bcdb7b4dbe76ca538738236f9969766d91c0a834328a24f835264e0f18555` |
| `postgres-schema-evidence-34666036688/postgres-suite.log` | `7156cb8d783fc6ddcbaf13006c70b321a5c5b894f963f759e41d81543e7e0fa3` |
| `postgres-schema-evidence-34666036688/postgres-suite.xml` | `e93b19e441e60ccae06e990523cbfa6f04becacbaf9a17f209feba8af63db53e` |
| `windows-job-object-evidence-34666036688/windows-job-object.log` | `bdcaa14e726500b8a08004082a030a84af9ccd7ffabd54e804966d063e9a57ec` |
| `windows-job-object-evidence-34666036688/windows-job-object.xml` | `a2ac04537179dfa006aa6eddd09940165bd567b09826a842caec3436b99641a3` |

The full-suite skip classifier reports exactly 14 skips, retained as
unavailable, platform-covered, or provenance-blocked rather than counted as
passes:

| Classification | Count | Evidence-supported reason |
| --- | --- | --- |
| `ENVIRONMENT_UNAVAILABLE_MANAGED_TOOL` | 1 | managed Nmap binary is not present on the CI development machine |
| `PLATFORM_CAPABILITY_UNAVAILABLE_WINDOWS_ASSURANCE_COVERED` | 6 | Windows kernel Job Object vectors are covered by the native Windows assurance job |
| `ENVIRONMENT_UNAVAILABLE_MANAGED_TOOL` | 2 | approved managed Subfinder v2.6.5 is not installed on the CI development machine |
| `PLATFORM_CAPABILITY_UNAVAILABLE_WINDOWS_ASSURANCE_COVERED` | 1 | Windows Job Object lifecycle is covered by the native assurance job |
| `PLATFORM_CAPABILITY_UNAVAILABLE_WINDOWS_ASSURANCE_COVERED` | 3 | Windows kernel is required |
| `PROVENANCE_BLOCKED_ESCALATION_REQUIRED` | 1 | historical `a1c4fc4` fixture is blocked by a committed v1 artifact mismatch |

The current candidate's local process-boundary evidence is 22 passed and 8
skipped; the focused local suite is 300 passed, 47 skipped, and one preserved
`.ci` inventory assertion deselected; the full local suite is 950 passed, 85
skipped, and one preserved `.ci` inventory assertion deselected. The exact
26-tool registry assurance passed three tests against a disposable project-local
database. A direct run of `tests/security/test_contract_fleet_consistency.py`
also exposed the preserved historical `.ci` inventory assertion: its snapshot
expects 1,709 entries while the intentionally retained local `.ci` tree
contains 3,038. With only that historical inventory assertion deselected, the
six substantive contract/fleet checks passed. No `.ci` artifact was deleted or
modified to obtain that result. These local results supplement, but do not
replace, the current-candidate GitHub evidence above.

The current repository does not provide independent deployment evidence that
the enterprise API and worker have been started with the same explicitly
provisioned `CYBERASSESS_WORKER_IDENTITY` and
`CYBERASSESS_WORKER_GENERATION`. The Compose file requires those values, but a
required environment declaration is not runtime proof. This gate remains
`UNVERIFIED`.

The authorized CT 108 observation supplies managed-tool evidence for the old
deployed checkout only, not for the current candidate. CT 108 was running with
healthy API, worker, PostgreSQL 16, and Redis 7 containers, and the API health
endpoint returned HTTP 200 with `HEALTHY`. However, the deployed checkout was
detached at commit `5195389044400d923f84230f4e835fd1d7fadfc5`, not the current
candidate, and the deployed Compose/runtime environment and both live API and
worker containers lacked `CYBERASSESS_WORKER_IDENTITY` and
`CYBERASSESS_WORKER_GENERATION`. The current repository Compose file requires
both values for the enterprise API and worker. The same image ID was observed
for the old API and worker, but that does not establish current-candidate
deployment or shared worker binding.

The old deployed runtime reported Nmap 7.95 and Subfinder v2.6.5. Their
executable hashes matched their valid trust-record executable hashes:

| Tool | Executable SHA-256 | Trust executable SHA-256 | Artifact SHA-256 | Provenance evidence |
| --- | --- | --- | --- | --- |
| Nmap | `a351773b8a62ce2044bbf4678f53b5b1da665eaceafff7bf0776b5e879e2e44f` | same | `e14ab530e47b5afd88f1c8a2bac7f89cd8fe6b478e22d255c5b9bddb7a1c5778` | `upstream_provenance_verified=False` |
| Subfinder | `c6bac401399eb67842c37776447574a676f4c33af1f6ce0d32f4752da542d554` | same | `19320e575c4fb422b1d2f9e4800b624eb5b5215e526db506cb73dd2de5907` | no upstream-provenance claim |

The CT 108 runtime logs are retained below
`.project-temp/section-b-evidence-reconcile-20260912/runtime-ct108/`:

- `ct108-runtime-verification.log`, SHA-256
  `16c08a901736b155ed41961eecbf4225b5195267944b67eb0a99964ee6706c23`;
- `ct108-managed-tool-verification-002.log`, SHA-256
  `79c57f772aee410692cbf460513892637a9904ff5198577ed5647bb76dd58a1c`.

No scan was run. The local environment's Docker daemon was unavailable, so no
local runtime claim is substituted for the authorized CT observation. The
managed-tool skips above remain applicable to the current candidate, and no
current-candidate tool provenance claim is fabricated.

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

The source implementation candidate's delivery scope contained the bounded
test correction and its three documentation records. The current child
reconciliation changes only `docs/evidence/section_b_execution_lifecycle_followup_2026-09-12.md`,
`docs/EXECUTION_LIFECYCLE_CLOSURE_MATRIX.md`, and
`docs/SECURITY_INVARIANT_TRACEABILITY.md`. The worktree as a whole is not clean
because the pre-existing modified `AGENTS.md` and untracked `.ci/`,
`.project-temp/`, `v/`, and GitLab mirror-evidence artifacts are preserved and
excluded from the delivery scope. They must not be deleted or staged to
manufacture a clean status.

## Acceptance status

This follow-up improves the evidence quality, removes the demonstrated Windows
assurance-test race, and records successful current-candidate GitHub CI. It
does not close the lifecycle matrix. Rows 35–41 remain `OPEN`. Remaining gates
include deployment of the current candidate with explicitly shared worker
identity/generation, broader independent OS-level and restart evidence,
current-candidate managed-tool runtime/provenance evidence, and independent
auditor acceptance. The delivery scope itself is clean; the global worktree
intentionally retains pre-existing user-owned changes and artifacts outside
the delivery scope.
