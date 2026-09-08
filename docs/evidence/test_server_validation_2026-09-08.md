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
