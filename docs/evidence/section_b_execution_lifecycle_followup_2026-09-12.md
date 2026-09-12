# Section B Execution-Lifecycle Follow-up — 2026-09-12

Status: published exact-source evidence update; independent acceptance remains open.

This dated follow-up preserves the historical Section B verification record
and appends the current published exact-source evidence. It does not rewrite
or supersede the historical record in
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

The former implementation and evidence candidate was commit
`285094882dca0108ad7a32eee2c230f668202956` on the same branch, with tree
`32cde38c6b003ee5ec7d6c35b17acd480ffe72db` and parent
`66d609bb9c1a9ce83b44d50868d3d8ecac471e27`. The GitHub branch ref resolves to
that exact candidate. The candidate contains the bounded Windows assurance-test
correction; the historical document-only reconciliation records evidence
associated with that candidate. It does not change the production process
supervisor or execution contract. The current published closure commit and
exact-source runtime evidence are recorded in the final section below.

The historical pre-publication Section B follow-up was deliberately bounded to:

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
| Typed durable identity | `backend/app/core/execution_context.py`, `execution_service.py`, `execution_decision.py`, `scan_execution_authority.py`; `backend/tests/test_execution_context_contract.py`, `backend/tests/test_execution_launch_inventory.py`, and execution-decision tests | configured, unit-tested, locally executed, and executed in historical pre-publication candidate run `34666036688` | independent auditor review of the complete current delivery |
| Complete launch coverage | `backend/tests/test_execution_launch_inventory.py`; adapter/base-adapter, installer, engine, worker, and supervisor call sites | statically inventoried, locally executed, and executed in historical pre-publication candidate run `34666036688` | independent production-path review and auditor acceptance |
| Run-level process ownership | `backend/app/core/process_supervisor.py`, `windows_job.py`, `execution_service.py`, `db.py`; process-boundary and decision-authority vectors | locally executed; historical candidate Windows, full, and focused jobs passed in run `34666036688` | broader independent OS/deployment evidence and auditor acceptance |
| Durable restart attachment | `execution_service.py`, `observation_service.py`, `windows_job.py`; restart, tamper, replay, and recovery tests | unit-tested and locally executed; supported-platform evidence re-executed in historical pre-publication candidate run `34666036688` | shared worker deployment evidence and independent restart/platform evidence |
| Single cancellation coordinator | `execution_service.py`, `orchestrator.py`, `observation_service.py`; cancellation-coordinator and API vectors | locally executed and executed in historical pre-publication candidate run `34666036688` | independent review and auditor acceptance |
| Durable recovery | `db.py`, `execution_service.py`, `observation_service.py`; SQLite recovery vectors and PostgreSQL workflow definition | SQLite locally executed; PostgreSQL and Redis service readiness/suite evidence recorded in historical pre-publication candidate run `34666036688` | exact-source deployment evidence, broader independent runtime evidence, and auditor acceptance |
| Contract and operational proof | Contracts 03/04/08, lifecycle matrix, traceability matrix, this follow-up, GitHub workflow | historical documentation reconciliation; current published evidence is recorded below | exact-source deployment/runtime review and independent auditor acceptance |

Rows remain `OPEN` in the authoritative lifecycle matrix unless both the
implementation and the required independent/platform evidence are complete.

## Historical pre-publication CI, runtime, and mirror boundary

The accepted baseline GitHub Actions run remains
[34659175863](https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34659175863)
historical evidence for the exact accepted baseline SHA. Its required compile,
focused, full, PostgreSQL, Windows Job Object, and hardened-container jobs
succeeded.

The former pre-publication candidate was independently verified in GitHub Actions run
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

The historical pre-publication candidate's local process-boundary evidence is 22 passed and 8
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
replace, the historical pre-publication candidate GitHub evidence above.

The 2ff8dde evidence snapshot did not provide independent deployment evidence
that the enterprise API and worker had been started with the same explicitly
provisioned `CYBERASSESS_WORKER_IDENTITY` and
`CYBERASSESS_WORKER_GENERATION`. The Compose file required those values, but a
required environment declaration was not runtime proof. That historical gate
was `UNVERIFIED` at the time of the snapshot.

The earlier authorized CT 108 observation supplies managed-tool evidence for
the old deployed checkout only, not for the 2ff8dde candidate. CT 108 was
running with healthy API, worker, PostgreSQL 16, and Redis 7 containers, and
the API health endpoint returned HTTP 200 with `HEALTHY`. However, the deployed
checkout was detached at commit `5195389044400d923f84230f4e835fd1d7fadfc5`,
not the 2ff8dde candidate, and the deployed Compose/runtime environment and
both live API and worker containers lacked the two worker binding variables.
The same image ID was observed for the old API and worker, but that did not
establish deployment of that historical candidate or shared worker binding.

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

For that earlier observation, no scan was run. The local environment's Docker
daemon was unavailable, so no local runtime claim was substituted for the
authorized CT observation. The managed-tool skips above remained applicable to
the 2ff8dde candidate, and no tool provenance claim for the later published
commit was fabricated in that historical record.

Docker Compose network separation remains a container-network boundary, not
dynamic destination-level egress enforcement. Provider egress governance is
therefore not claimed complete by this evidence.

No GitLab operation was performed during this historical follow-up. GitLab
promotion remained blocked until the grouped publication passed the
GitHub-first and independent-auditor gates; the current exact GitHub
publication and mirror state are recorded in the final section below.

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

This historical follow-up improves the evidence quality, removes the
demonstrated Windows assurance-test race, and records successful historical
pre-publication GitHub CI. It does not close the lifecycle matrix. Rows 35–41
remain `OPEN`. Remaining gates at that time included exact-source deployment
with explicitly shared worker identity/generation, broader independent
OS-level and restart evidence, current published managed-tool
runtime/provenance evidence, and independent auditor acceptance. The delivery scope itself is clean; the global worktree
intentionally retains pre-existing user-owned changes and artifacts outside
the delivery scope.

## Section B historical pre-publication bounded runtime-candidate evidence — 2026-09-12

This section is appended after the 2ff8dde documentation reconciliation. It
records a real CT 108 deployment of the bounded source candidate before the
grouped GitHub publication commit was created. The later publication must
rebuild and redeploy the exact GitHub commit; this pre-publication evidence is
not silently relabeled as proof for an earlier commit.

### Demonstrated implementation defects and bounded corrections

The CT 108 Docker daemon is Docker 29.1.3 using the legacy builder and has no
BuildKit `buildx` command. The unmodified Dockerfile therefore failed before
the first build step because `FROM --platform=$BUILDPLATFORM` received an empty
platform value. A subsequent constrained build reached the pinned Trivy Go
compilation and failed with `signal: killed`, identifying compiler parallelism
as the second reproducible resource defect. The source candidate makes only
these demonstrated build corrections:

- declares `ARG BUILDPLATFORM=linux/amd64` before the first `FROM` and
  `ARG TARGETARCH=amd64` after it, while retaining the pinned base image and
  amd64-only Nmap source-build guard; and
- invokes the pinned Trivy source build with `go build -p=1` to bound compiler
  parallelism on the constrained CT builder.

The runtime stop vector then demonstrated a separate production defect: the
worker process did not exit on Docker's standard SIGTERM within the 30-second
grace period, while SIGINT terminated it. `run_worker.py` now installs
event-loop-owned SIGTERM/SIGINT handlers, exits the consume loop, removes its
handlers, and always closes the Redis queue. No scan or tool operation was
added to this fix.

### Candidate image and hardened runtime evidence

The corrected source context was archived locally under
`.project-temp/section-b-runtime-deploy-20260912/context-worker-signal-001-modified.tar`
with size `6282240` bytes and SHA-256
`f70c55e83d0786139397294cfc27eb0f9edb385df4056a42c19f710feb8bfa36`. Its
extracted Dockerfile SHA-256 is
`b5848f63cd202b19209e84c52304174eb28896df886fdf11020a9e69c6ba3123`, and its
`run_worker.py` SHA-256 is
`3202e473e9c72aa2b31f6ee10350d985c69d268c1b7db3c4e1ecd69ee1f9c336`.

The CT build completed successfully with the temporary tag
`ghcr.io/andresslacson1989/security-assessment-platform:section-b-worker-signal-candidate`.
The image is Linux amd64, size `750902792` bytes, and has image ID
`sha256:f9bf37685c7f5660faf12fc31dc0a5a814ba45ceafbbfd985652651c8895eae9`.
The complete remote build log has SHA-256
`f4301e42d8a57a3f891bd3138eea9314a39cef730e60a2324be780b9ff11002e` and is
retained at the CT deployment staging path
`/opt/cyberassess/.codex-deploy-section-b-2ff8dde/context-worker-signal-002/build.log`.
The local evidence copy is
`.project-temp/section-b-runtime-deploy-20260912/ct108-worker-signal-build.log`
with SHA-256
`da73052ac4b10c9aeba6fb5984bee9597ffcd0fda360c085795b5241eb08ec3e`.

The candidate API and worker ran in CT 108 with the exact image ID above. The
API health endpoint returned HTTP 200 and `HEALTHY` with five registered
engines. PostgreSQL 16 returned `pg_isready` accepting connections; Redis 7
returned `PONG`; the `cyberassess-workers` Redis Stream group existed with
zero pending messages. The existing PostgreSQL and Redis container image IDs
remained the pinned
`sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685`
and
`sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf`.

The deployment environment was updated atomically at
`/etc/cyberassess/runtime.env` with non-empty worker identity and generation
values, preserving root ownership and mode `0600`; raw values were not
recorded. The sorted hash of the two provisioned environment entries was
`9976acb434fc0a78fe02dccb25a7bbd5d5e5b14a8200c724ab516d655c4a19b2` in both
containers. The application getters resolved matching identity hashes
`82a8b3bf03dbf76ea1c268dfa923018bb72f92ce2f776267f4ec702b0a4dfcf3` and
generation hashes
`0b78e476653ad4187343d1d34c81fad5606c8596d4daff0eb23525f57fb3f9f3` in both
the API and worker processes. This proves the binding was available from the
service runtime, without exposing the values or accepting them from a scan
request.

The standard Docker shutdown vector completed with worker PID `2086802`
exiting with code `0` under `docker stop -t 30`; a subsequent start produced
worker PID `2088212`, and the queue pending count remained zero. The local
runtime evidence ledger is
`.project-temp/section-b-runtime-deploy-20260912/ct108-runtime-candidate.log`,
size `1849` bytes, SHA-256
`62d8f0eb85ee00e4ffa65df740b7752e27bebcc5c00a5a06982e4eb5e4e8c0c9`.

Under the hardened one-shot container vector, UID `999` could not write the
managed Nmap or Subfinder paths. Nmap reported `7.95`; Subfinder reported
`v2.6.5` using an ephemeral test configuration. Direct managed trust
verification returned true for both tools. Importing the authoritative
registry in the disposable container reported `FLEET_COUNT=26`. No scan was
run.

### Authentication and assurance boundary

The authenticated recovery-health vector remains unverified for this runtime
candidate because the previously supplied `admin/admin` credentials returned
HTTP 401. Read-only PostgreSQL metadata showed one active administrator
account (`admin`, role `ADMIN`, organization `org-7f0c365a`), but no password
was inspected or reset. This is an explicit evidence blocker, not a reason to
delete or recreate history. The protected database fingerprint recorded above
remained unchanged, and no scan/test history was deleted.

The source candidate was not yet a GitHub-published commit when this runtime
evidence was collected. The required next delivery step is one grouped
Section B commit containing the demonstrated source changes and the evidence
record updates, followed by GitHub-first publication and all six required
GitHub Actions jobs. GitLab remains an unmodified mirror-only destination until
the independent auditor accepts the final evidence.

### Local source verification after the worker correction

After the worker signal-handling correction, the bounded Section B source suite
was rerun against a disposable project-local database and project-local pytest
base directory. The result was `201 passed, 8 skipped, 1 deselected`, with one
Starlette/httpx deprecation warning. The deselection was the historical
`.ci`-snapshot inventory test whose retained snapshot does not match the
current 26-tool registry; it is not counted as a passing acceptance test. The
full result is retained at
`.project-temp/section-b-runtime-deploy-20260912/local-source-verification-003/result.log`
with SHA-256
`826052ed8c2c0b97024296962f82b87e05f41d6071ea989d8044fd7201d72622`.

## Historical pre-final-source CT108 authentication and active-handler evidence — 2026-09-12

The earlier runtime-candidate observation that the supplied administrator
credential returned HTTP 401 is retained as historical evidence. It was
resolved for the current CT108 runtime through a narrow, explicitly
authorized demo-account recovery; this section supersedes only that
authentication observation and does not rewrite the earlier build or lifecycle
claims.

The exact runtime target was CT108 at `192.168.99.66`, using PostgreSQL
`16.15`, database `cyberassess`, and the application role `cyberassess`. A
read-only pre-change inspection found one active `ADMIN` user named `admin` in
organization `org-7f0c365a`. The user explicitly authorized resetting that
demo administrator credential. No full database reset was performed. One
transaction matched the existing user identity, username, role, organization,
and active state and reported `UPDATE 1` for `users.hashed_password`. Raw
credentials and raw password hashes were not recorded.

The pre-change counts were `users=1`, `scans=0`, `findings=0`,
`finding_occurrences=0`, `execution_requests=0`, `execution_runs=0`, and
`audit_events=6`. The post-change counts were unchanged for all persistence
and history tables except `audit_events=9`; the three additional rows are the
normal successful-login audit events produced by the verification calls. No
scan, finding, execution, or test history was deleted or reset. The
project-local operational record is
`.project-temp/section-b-recovery-closure-20260912/runtime-auth-recovery.md`.

The current authenticated checks returned:

- `POST /api/auth/login`: HTTP `200`;
- `GET /api/auth/me`: HTTP `200`, `admin`, role `ADMIN`, organization
  `org-7f0c365a`; and
- `GET /api/system/executions/recovery/health`: HTTP `200`, organization
  `org-7f0c365a`, `recovery=[]`.

Bearer tokens were used only in memory and were not printed or retained. The
password chosen for this demo-only recovery is intentionally below the normal
application password-strength policy because the user explicitly authorized
that exact credential; it must not be treated as production-safe.

The CT108 worker was stopped with a 30-second grace period and restarted. Its
PID changed from `2206036` to `2231656` while the API and worker remained on
image `sha256:02555401d3e53d23ab8037e7bf6b87755cdb65e7658d2321eb39e6e6678dc9bc`.
Both containers remained `cyberassess`, read-only, `cap_drop=ALL`, and
`no-new-privileges=true`. PostgreSQL accepted connections, Redis returned
`PONG`, and the `cyberassess-workers` stream group had zero pending messages and
zero lag before and after restart. The API returned `HEALTHY`, version `14.3.0`,
with five registered engines. No scan was run.

The added test
`backend/tests/test_execution_launch_inventory.py::test_worker_signals_during_active_handler_finish_work_then_exit`
invokes both SIGINT and SIGTERM while the actual nested worker handler is
awaiting completion. It proves that signal delivery requests an orderly loop
stop, allows the active public orchestrator handoff to finish, prevents a
second consume cycle, and closes the queue.

Post-change disposable local verification completed as follows:

| Evidence | Result | SHA-256 |
| --- | --- | --- |
| `.project-temp/section-b-recovery-closure-20260912/post-change/section-b-targeted.log` | 96 passed, 46 skipped, 1 warning in 144.01s | `4ca83165f6cb3961e40f56e3957e2ec151b033c9ad94ae9e25e2b3544cddc77b` |
| `.project-temp/section-b-recovery-closure-20260912/post-change/section-b-targeted.xml` | JUnit for the targeted lifecycle suite | `67e1f8e09828e14d8ad6f19c26e4ea162622cf1c244d5a498732d3212d5ba781` |
| `.project-temp/section-b-recovery-closure-20260912/post-change/database-backend.log` | 36 passed, 1 warning in 7.95s | `aa9a166257e9b3ede04a080266be56bfdb0e253ee0b726e8f520ffdc0c0bdf1f` |
| `.project-temp/section-b-recovery-closure-20260912/post-change/database-backend.xml` | JUnit for the database-backend suite | `95cd5f0ad477e0ee716e3f8602e8ece3684019c7699d94fad770fce7b18e05e4` |

The full substantive local regression, run with the same project-local
database and temporary roots, completed with `954 passed, 85 skipped, 1
deselected, 15 warnings in 516.41s`. The only deselection was the preserved
historical `.ci` worktree-inventory assertion, whose untracked local evidence
tree is intentionally not modified or deleted. The full regression log SHA-256
is `fc315cc10c575c2e8e3d2105f018c94bdd1f74b0e171e9e10bf2dd5c4521a370` and its
JUnit SHA-256 is
`aa0a81f0fe04386868888c766b293e8965ba99f0d19a59f7fdc04f91d1af9fee`.

The protected repository SQLite database remained `10285056` bytes with mtime
`2026-09-04T23:24:42.6548237Z` and SHA-256
`7a5a019389f69574b7bae31c355efeeed47fbe9f203e2c2a65c946e21cba6ecc`. The
saved delivery goal's prior no-destructive-database-change rule was
superseded only for the exact, user-authorized CT108 account operation; the
repository database remains outside delivery operations and was not modified.

The preceding authentication and active-handler evidence is historical
pre-publication evidence. The current published exact-source build, runtime,
CI, database, and mirror status are appended below. GitLab remains a
mirror-only destination and cannot satisfy the independent-auditor gate.

## Current published exact-source runtime and CI closure evidence — 2026-09-12

### Publication and source binding

The exact application/test source used for the current Section B runtime and CI
evidence is commit
`031cda1f93fd0e7cebf6ec50452da43dc7bf980f` on
`security/nmap-installer-closure`, with parent
`cb563414a1721a780ed0d0184ed8e9ee6c6dbcd8` and tree
`0a43ef6b895f059a991173122bd220ac37140579` ([GitHub commit](https://github.com/andresslacson1989/security-assessment-platform/commit/031cda1f93fd0e7cebf6ec50452da43dc7bf980f)).
The exact source archive
`security-assessment-platform-031cda1f.tar` was `6,318,080` bytes with
SHA-256
`32066405c11f07e4b94d17c1b43136bfd0bff54035aa54843828db1b687ead25`.
The archive transferred to CT108 matched the same size and digest; the
extracted source was verified against that archive. The corrective publication changes only the three
evidence documents named by this record; it does not modify contracts, Nmap
implementation, Dockerfile, protected data, or unrelated Section A work.

### Exact CT108 build and deployment

The exact archive was built on CT108 as Linux/amd64 image
`ghcr.io/andresslacson1989/security-assessment-platform:section-b-final-031cda1`.
The image ID/RepoDigest is
`sha256:a66b873c679d1f3873c3c093d70e0ac3f05ee907aff5ff082c4517f35a55c4e1`,
created `2026-09-12T09:54:32.364976258Z`, with size `751654768` bytes. Its
labels bind the image to revision
`031cda1f93fd0e7cebf6ec50452da43dc7bf980f`, source archive digest
`32066405c11f07e4b94d17c1b43136bfd0bff54035aa54843828db1b687ead25`, and
source `github.com/andresslacson1989/security-assessment-platform`. The
retained build log is
`/opt/cyberassess/.codex-deploy-section-b-final-031cda1/build-031cda1-legacy.log`
on CT108; its project-local copy is
`.project-temp/section-b-recovery-closure-20260912/final-source-031cda1/ct108-build-031cda1.log`.
Both copies are `28,667` bytes with SHA-256
`19c7bcbe7eda35cd9a5b25950f8045b08fda06869b87b277d792b8a692fdbbd6`.

Only the API and worker application services were recreated from this exact
image. The API container is
`3b281c1f48a9c12fcf501aaa6c40ba162ded7175db6537c0818c951ad780fb03`, created
`2026-09-12T09:55:36.987748198Z`, running and healthy, with command
`["python", "run_platform.py"]`. The worker container is
`3902a58854a0c4efb3eb8fc9807ea344d30fd8e036210a165ac512282d9bc75c`, created
`2026-09-12T09:55:36.98279058Z`, running, with command
`["python", "/app/run_worker.py"]`. Both use the exact image, run as
`cyberassess`, use read-only root filesystems, drop all capabilities, and
enable `no-new-privileges`.

PostgreSQL and Redis were preserved and not recreated. PostgreSQL is container
`e88c23415c583d99de289c173e7f3a7ceb280596e4fec5aebdb387d11f374bf0`, using
`postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685`,
created `2026-09-08T16:13:05.320938141Z`. Redis is container
`8e73e9c2a7c7e10d966f314e50ad2c9f03525f2607b9cf9465e07e8cdecda104`, using
`redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf`,
created `2026-09-08T16:03:01.114442821Z`. PostgreSQL accepted connections,
Redis returned `PONG`, and the `cyberassess-workers` group reported pending
`0` and lag `0` with 36 consumers.

The exact-runtime API health check returned HTTP `200` with status `HEALTHY`,
version `14.3.0`, storage `OK`, `scans_stored=0`, `total_scans_stored=0`, and
`registered_engines_count=5`. Authenticated checks returned HTTP `200` for
login, `/api/auth/me` as `admin`/`ADMIN` in `org-7f0c365a`, and the
tenant-scoped `/api/system/executions/recovery/health` endpoint with
`recovery=[]`. The worker was orderly restarted from PID `2268860` to
`2269163`; stop and start both exited `0`, and the restarted worker retained
the exact image identity. No scan, provider credential injection, or
unrestricted external scanning was performed.

The exact-runtime disposable hardened inventory probe reported
`FLEET_COUNT=26` with IDs `amass`, `bandit`, `checkov`, `dockle`, `ffuf`,
`gitleaks`, `grype`, `gtfobins`, `httpx`, `hydra`, `katana`, `kube-bench`,
`metasploit`, `nmap`, `nuclei`, `osv-scanner`, `prowler`, `retire`,
`schemathesis`, `semgrep`, `sqlmap`, `sslyze`, `subfinder`, `syft`, `trivy`,
and `trufflehog`. The probe used no network, a read-only filesystem, all
capability drops, no-new-privileges, and disposable tmpfs mounts; it performed
no scan.

### Authorization, persistence, and protected data

The CT108 credential operation was limited to the explicitly authorized
demo-account recovery. One existing active administrator row was updated in
PostgreSQL database `cyberassess`; no full database reset, schema change,
account creation, or history deletion occurred. Current counts are
`users=1`, `scans=0`, `findings=0`, `finding_occurrences=0`,
`execution_requests=0`, `execution_runs=0`, and `audit_events=10`. The audit
increase consists of successful verification logins. Raw credentials and
password hashes were not recorded.

The protected repository SQLite database remains outside delivery operations.
Its unchanged fingerprint is `10285056` bytes, mtime
`2026-09-04T23:24:42.6548237Z`, SHA-256
`7a5a019389f69574b7bae31c355efeeed47fbe9f203e2c2a65c946e21cba6ecc`.

### Authoritative GitHub Actions evidence

GitHub Actions run
`34685317236` ([run](https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34685317236))
executed for exact SHA `031cda1f93fd0e7cebf6ec50452da43dc7bf980f` and
completed successfully. All six jobs passed:

| Job | Job ID | Result |
| --- | --- | --- |
| Windows Job Object assurance | `103531200228` | 19 passed, 0 skipped |
| PostgreSQL 16 schema assurance | `103531200272` | 29 passed, 0 skipped |
| Hardened production image verification | `103531200286` | passed |
| Compile backend | `103531200317` | passed |
| Focused contract verification | `103531200328` | 341 passed, 11 skipped |
| Full repository verification | `103531200341` | 1026 passed, 14 skipped, 15 warnings |

Retained artifact archive digests are:

| Artifact | Archive digest |
| --- | --- |
| `focused-contract-evidence-34685317236` | `sha256:1b06e56eca45f63c37f0f1594a1e6b0a12255c2fab7da10607ad5fd3b49f27c5` |
| `full-repository-evidence-34685317236` | `sha256:1274378bc6a7744183b474316ab8a80025c7f77329c2b435e1ecee35ab5f54bd` |
| `postgres-schema-evidence-34685317236` | `sha256:c8a2d9ddbac261e97a9999634efd36d2493cf6ebf59ef97035f91789fd5ac0f2` |
| `windows-job-object-evidence-34685317236` | `sha256:3a31edfb4708d4010eb8ee99b09667d9267902f665fdb94fe3deea29ef093417` |

The downloaded files are retained under
`.project-temp/section-b-recovery-closure-20260912/github-34685317236/`.
The focused log/XML hashes are
`2375C4081E2012DE4A87B271CC8345D5A367BC877AC2412723E55C8277F578B9` and
`E023F2A8AC6D2CCB218483A6014B951AEF9F08A8890433A52CD12A4DBF82A9E4`; the
full log and skip-classifier hashes are
`3097A22B1D957DE23EDCB579F02101E490C65BEED8322CEF6CBF027DAB66D8AF` and
`FE9BCDB7B4DBE76CA538738236F9969766D91C0A834328A24F835264E0F18555`.
The PostgreSQL log/XML hashes are
`657E8BEAEB1E4C6782F8C42083311CA70C7EF15BDD9EFAE7EC03ED60D9ED0F47` and
`3BCEA268EE173DAE7FCD34DBBD5BABD408165A72193C07F695FFCB954527C153`;
the Windows log/XML hashes are
`898CE90FC860827455D20950DD03E5F492BAB2949F5026701CFF2058982DA527` and
`9A19DC08F1201F2E18AFB2DE877CFCE26B4326E77757C9A6E51EB61F36E7398C4`.

The full-suite classifier records exactly 14 skips: three managed-tool
availability skips, ten Windows/platform-covered skips, and one historical
provenance-blocked fixture. They remain skips and are not counted as passes.
Warnings include the upload-artifact Node.js 24 migration notice and Python
deprecation warnings; no warning was treated as a pass or failure.

### Delivery boundary and remaining acceptance state

The local branch and GitHub branch were verified at the exact published SHA.
GitLab was not updated because its read-only remote returned HTTP `530`; the
mirror remains deferred until the GitHub-first publication and independent
auditor gates are satisfied. GitLab is not an acceptance provider. Docker
Compose network segmentation remains a container-network boundary and is not
dynamic destination-level egress enforcement.

This current evidence closes the stale publication references but does not
close the lifecycle matrix. The rows remain `OPEN` pending independent
auditor acceptance and the remaining durable cancellation/recovery,
tenant-isolation, and broader OS-level evidence that is not established by
the orderly worker-loop test, deployment smoke checks, or a green CI run alone.
