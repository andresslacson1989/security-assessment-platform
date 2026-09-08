# Test Server Isolated Validation — 2026-09-08

## Decision

`VALIDATED_ISOLATED_ONLY`

Canonical commit `2a16276abc867421058a407372d6e30671319f84` was exercised in an isolated, loopback-only process inside authorized non-production LXC CT 108. The existing service at `/opt/cyberassess`, its active checkout, and its persistent database were not switched, restarted, migrated, copied, repaired, or modified by this validation.

This evidence is not a deployment record, production acceptance, dependency-provenance attestation, or final contract acceptance.

## Scope and safety boundary

- Proxmox connection: SSH to the existing Proxmox host at `192.168.99.2`, followed by read-only inspection or explicitly scoped `pct exec 108` operations inside CT 108. Credentials and key material were not printed or copied into evidence.
- Active application address: `192.168.99.66:8000`.
- Active application path: `/opt/cyberassess`.
- Isolated validation root: `/tmp/cyberassess-validation-2a16276-20260908T1455Z` inside CT 108.
- Isolated listener: `127.0.0.1:18080`; it was never exposed on the CT network interface.
- External scanning, provider credential injection, tool installation, and third-party target contact were prohibited and did not occur.
- Runtime evidence retained outside the repository:
  - `/tmp/cyberassess-validation-2a16276-20260908T1455Z/logs/validation-summary.txt`
  - summary SHA-256: `ef0c95ae89026a695bbdddb3602ccbb6399c900379134e7fc38e7eafb012b627`
  - `/tmp/cyberassess-validation-2a16276-20260908T1455Z/logs/focused-tests.log`
  - focused-test log SHA-256: `b3082de8a1f40e88a057e0ffa2d9aeaaadb4be689e4677bbcaa738c6e9a9a105`

## Canonical source identity

The local governed branch, GitHub ref, and GitLab mirror ref were independently resolved before validation:

| Identity | Value |
| --- | --- |
| Governed branch | `security/nmap-installer-closure` |
| Commit | `2a16276abc867421058a407372d6e30671319f84` |
| Tree | `ae794811408a500e0897ea8f22f5bd094f0c10d2` |
| Parent | `216d3e3e3c9937f288ac81a2f91f6c2fbd70fd95` |

The canonical branch was exported as a complete Git bundle. `git bundle verify` succeeded, and SHA-256 remained `01b30979d2023ea6ab2c24c8e1adb1bc1c1edd9a571449935088378bbc0109d2` before transfer, on the Proxmox host, and inside CT 108. The isolated repository was initialized without changing the active checkout, fetched from that bundle, and checked out detached. Fresh checks returned the exact canonical commit and tree above; `git diff --exit-code` returned `0` after validation.

The active server checkout did not already contain the canonical commit object: `git cat-file -e 2a16276...^{commit}` returned exit code `128`. No `git pull`, reset, merge, active-checkout checkout, provider branch operation, or history rewrite was used.

## Existing live service — unchanged baseline

| Evidence | Before | After |
| --- | --- | --- |
| CT state | `running` | `running` |
| Branch | `security/nmap-installer-closure` | unchanged |
| Commit | `ef0dbb4297ae86559761da265175ed007dcc0ba9` | unchanged |
| Tree | `1deae3498c694a576fd9f5597683f140a92b3674` | unchanged |
| Process | user `cyberassess`, PID `268`, PPID `1` | same process identity |
| Command | `/opt/cyberassess/venv/bin/python run_platform.py` | unchanged |
| Working directory | `/opt/cyberassess` | unchanged |
| Listener | `0.0.0.0:8000` | unchanged |
| Start time | `Sat Sep 5 11:17:11 2026` | unchanged |
| Health | HTTP `200`, `HEALTHY`, version `14.3.0` | HTTP `200`, `HEALTHY`, version `14.3.0` |

The active checkout was already dirty before validation and remained outside this goal. Its modified and untracked paths were recorded during preflight; no active-checkout file was edited, staged, discarded, or incorporated into the isolated checkout.

The post-validation active health response was timestamped `2026-09-08T15:07:24.917315+00:00`, reported 11 stored scans and five registered engines, and showed uptime `273011.34` seconds.

## Persistent runtime database non-modification proof

Only filesystem metadata and Git status for the exact runtime path were inspected. Application records were not read.

| Property | Before | After |
| --- | --- | --- |
| Exact path | `/opt/cyberassess/data/cyberassess.db` | same |
| Size | `6692864` bytes | `6692864` bytes |
| Modification time | `2026-09-08 12:25:06.720282582 +0000` | unchanged |
| Epoch modification time | `1788870306` | unchanged |
| Owner/group | `cyberassess:cyberassess` | unchanged |
| Mode | `0644` | unchanged |
| Git status for exact path | no entry | no entry |

No migration, repair, backup, copy, vacuum, deletion, archive, staging, publication, or application-record query was performed against this database. The known version-8 migration-ledger identity mismatch remains an unresolved release risk.

## Isolated runtime configuration

The validation application used:

- detached source at the canonical commit and tree;
- process user `cyberassess`;
- `OPERATING_MODE=TEST`;
- an empty `DATABASE_URL`;
- absolute disposable SQLite path `/tmp/cyberassess-validation-2a16276-20260908T1455Z/state/validation.db`;
- test-only JWT material generated inside the process and never printed;
- `PYTHONPATH` bound to the isolated checkout's `backend` directory;
- one Uvicorn worker on `127.0.0.1:18080`;
- no reload process.

A fresh virtual environment was attempted without network access. It correctly contained no third-party dependencies, and contacting a package index was prohibited. The validation therefore used `/opt/cyberassess/venv/bin/python` as a read-only dependency environment while executing only source from the canonical isolated checkout. This proves runtime compatibility with the currently installed dependency environment; it does not establish independent dependency provenance or a clean-install build.

Two foreground runs were observed:

| PID | PPID | Start | Command result |
| --- | --- | --- | --- |
| `642410` | `642409` | `Tue Sep 8 14:58:37 2026` | graceful shutdown, exit `0` |
| `643861` | `643860` | `Tue Sep 8 15:07:50 2026` | graceful shutdown, exit `0` |

Both used `/tmp/cyberassess-validation-2a16276-20260908T1455Z/checkout` as their working directory. After validation, port `18080` was closed and no validation child process remained.

## Disposable database and migration evidence

Application startup created and migrated only the disposable validation database.

| Check | Result |
| --- | --- |
| Initial metadata | `413696` bytes; mode `0600`; mtime `2026-09-08 14:58:39.557357625 +0000` |
| Final metadata | `417792` bytes; mode `0600`; mtime `2026-09-08 15:04:21.643621670 +0000` |
| Migration ledger | versions `1` through `13` present |
| SQLite integrity | `PRAGMA integrity_check` returned `ok` |
| Startup/migration result | application startup completed; process later shut down with exit `0` |

This successful disposable migration does not resolve or waive the separate mismatch on the existing persistent database.

## Runtime validation vectors

All HTTP traffic in this section targeted only the loopback validation listener.

| Vector | Evidence | Result |
| --- | --- | --- |
| Root/UI | `GET /` returned HTTP `200`, `text/html; charset=utf-8`, 49,626 bytes | PASS |
| Health/version | `GET /api/system/health` returned HTTP `200`, `HEALTHY`, version `14.3.0`, five registered engines | PASS |
| Initialization status | `GET /api/auth/status` returned HTTP `200`, `initialized=true`, `mode=READY` after disposable bootstrap | PASS |
| Bootstrap | test-only local bootstrap returned HTTP `201` | PASS |
| Login | valid test-only credentials returned HTTP `200`; token value was not logged | PASS |
| Authenticated identity | `GET /api/auth/me` returned HTTP `200` | PASS |
| Authentication denial | wrong password returned HTTP `401`; unauthenticated asset listing returned HTTP `401` | PASS |
| Safe inventory fixture | an isolated copy of the repository Compose manifest under the checkout's managed `data/workspaces` directory was registered as an `IAC_TEMPLATE`; HTTP `201` | PASS |
| Scan request | `POST /api/scans/start` returned HTTP `201`, `AUTHORIZATION_REQUIRED`, `PENDING_APPROVAL`, and `execution_started=false` | PASS |
| Persistence/retrieval | tenant scan history returned HTTP `200` and contained the scan; one scan row, one authorization-request row, and the JSON cache artifact were present in disposable storage | PASS |
| Tenant isolation | second disposable tenant saw zero assets and zero scans; cross-tenant approval attempt returned HTTP `404` | PASS |
| Invalid request | scan request without an inventory asset returned HTTP `422` | PASS |
| External effects | no scan approval, dispatch, tool installation, external target, or external network scan was used | PASS |

## Deterministic process and SSE verification

The following exact focused test selection was executed from the detached canonical checkout with a second disposable database and an external pytest temporary directory:

```text
python -m pytest -p no:cacheprovider \
  --basetemp=/tmp/cyberassess-validation-2a16276-20260908T1455Z/pytest-final-tmp \
  -q -ra \
  tests/security/test_process_launch_boundary.py::test_supervisor_child_observes_only_reviewed_environment \
  tests/test_api_endpoints.py::test_sse_streaming_endpoint \
  tests/test_api_endpoints.py::test_live_scan_sse_streaming
```

Environment binding used `CYBERASSESS_DB_PATH=/tmp/cyberassess-validation-2a16276-20260908T1455Z/state/pytest-final.db`, empty `DATABASE_URL`, `OPERATING_MODE=TEST`, and canonical `PYTHONPATH=backend`.

Result: `3 passed in 2.01s`, exit code `0`.

The first test crossed the real `ProcessSupervisor` child-process boundary and verified that reviewed environment values were preserved while ambient secrets and unsafe process controls were removed. The two SSE tests verified completed-stream evidence and live progress/log/cancellation delivery. No test was skipped or dependency-gated in this focused selection. A post-test process check found no remaining child under the isolated server process.

## Repository and infrastructure boundaries

- No application source, test, contract, workflow, `AGENTS.md`, authoritative goal, `.ci` content, branch, or tag was changed by validation.
- The local repository's pre-existing untracked `.ci/` content remained unowned and unstaged.
- No runtime database was added to delivery scope.
- No Proxmox guest configuration or guest other than CT 108 was changed.
- The active service was not synchronized to the canonical commit.

## Remaining blockers and next decision

The validation closes only the isolated compatibility question. It does not close:

- the persistent version-8 migration-ledger mismatch;
- active-service synchronization and deployment validation;
- A6 provenance;
- file ownership attribution for previously captured repository changes;
- authoritative GitHub Actions execution and acceptance evidence;
- dependency provenance and clean-install reproducibility;
- independent final contract acceptance.

A separate explicit goal is required before switching the active service. That goal needs an approved disposition for the dirty active checkout and a database migration/reconciliation plan. Until then, the live server remains on `ef0dbb4297ae86559761da265175ed007dcc0ba9`.

## GitHub CI remediation evidence — 2026-09-09

This addendum records the GitHub verification performed after the isolated
server validation above. It applies to the remediation commit below and does
not replace the server-validation decision or constitute deployment,
dependency-provenance, or final contract acceptance.

### Source and workflow identity

| Identity | Value |
| --- | --- |
| Governed branch | `security/nmap-installer-closure` |
| Remediation commit | `468070caa2dae5ac24f027bb7d04c5deaaf50ab4` |
| Parent commit | `5195389044400d923f84230f4e835fd1d7fadfc5` |
| GitHub ref verified | `refs/heads/security/nmap-installer-closure` resolved to the remediation commit |
| Workflow | `Contract Verification` |
| GitHub Actions run | `34289803258` |
| Trigger | `push` |
| Run URL | https://github.com/andresslacson1989/security-assessment-platform/actions/runs/34289803258 |
| Overall conclusion | `success` |
| GitLab publication at this checkpoint | Not performed; GitHub-first promotion gate remained in force |

The remediation commit contains only the grouped CI/process-verification
change: full-history checkout for the history-dependent jobs, Linux
process-group liveness handling that excludes zombie/dead entries, and a
structural workflow regression assertion. The protected runtime database,
`AGENTS.md`, and the untracked `.ci/` evidence tree were not included in that
commit.

### GitHub job results

| Job | Result | Evidence |
| --- | --- | --- |
| Compile backend | PASS | Backend compilation completed successfully |
| Focused contract verification | PASS | `186 passed, 1 skipped` from 187 tests; the sole skip was the allowlisted historical `a1c4fc4` artifact-mismatch case |
| Full repository verification | PASS | `820 passed, 33 skipped, 14 warnings` from 853 tests; the skip classifier completed successfully |
| PostgreSQL 16 schema assurance | PASS | `29 passed, 0 skipped` |
| Hardened production image verification | PASS | Image build, read-only/no-capability hardening smoke test, and application health smoke test all completed successfully |

The full-suite skip classifier recorded exactly:

- 29 dependency-deferred PostgreSQL tests, covered by the PostgreSQL job;
- 1 unavailable managed Nmap binary;
- 2 unavailable approved managed Subfinder v2.6.5 runtime tests; and
- 1 provenance-blocked historical `a1c4fc4` migration fixture.

No unclassified skip, test failure, or job failure was present in run
`34289803258`.

### Downloaded evidence digests

The uploaded JUnit and log artifacts were downloaded into the project-local
validation evidence area. Their SHA-256 digests are recorded here so the
reported counts can be independently compared with the immutable GitHub run:

| Artifact | SHA-256 |
| --- | --- |
| `focused-contract.xml` | `4ec7ba810de05d5eda94084c532fba4848e0529eef1365fc4ae0865dc542a33f` |
| `focused-contract.log` | `d6e0efede13f6bdedb9df91f72b67df077297aabde77ec45cc82da95d73ac5b8` |
| `full-suite.xml` | `52cac88a1fb25760a57667605da7aec9ac81fb5b305e954fda84a08defd95dcf` |
| `full-suite.log` | `07426924896a11e0f5ba7a60ceca14f456246a4f4aff5289c5228a1f15a7f7eb` |
| `full-suite-skip-classification.txt` | `073b7c6c8d519ad14754d0b08651f22a3a3eb48c4b2e696b5e0cf232ddacca75` |
| `postgres-suite.xml` | `aaa327b788bd98e1bf45c4afb0b385b7ff93c5e4855d9984c188659979289963` |
| `postgres-suite.log` | `37f811ae4320bb1214a3a7a8451d464f9245db17a91bdcc95bc3512841d8e7e8` |

### Assurance interpretation

This run closes the previously observed GitHub CI failures on the remediation
source: the focused and full jobs had complete history, and the Linux process
supervisor confirmed timeout completion when only zombie/dead process entries
remained. The process control remains conservative when procfs cannot be
reliably inspected, and the result does not claim that an operating-system
race is mathematically impossible.

The two real managed Subfinder v2.6.5 runtime vectors remain explicitly
classified as environment-unavailable because the approved managed binary is
not installed in the GitHub runner. This is an evidence limitation, not a
passing runtime verification. Active CT 108 was not restarted, synchronized,
or scanned as part of this CI run.
