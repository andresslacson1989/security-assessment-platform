# Section A: scan request and approval persistence

Status: IN PROGRESS. This is an implementation checklist, not acceptance evidence.

Baseline: `a1c4fc4`, with the existing uncommitted correction-round-3 worktree preserved.
Authority: auditor task `01a06c58-589e-7850-88ab-9a68ea4ec949`, read-only reassessment received on 2026-09-05.

Only Section A is authorized for this correction pass. Sections B (dispatch), C
(process ownership), D (recovery), and E (four-tool capability implementation)
remain subsequent independent review gates. Approval persistence must not imply
that executable dispatch has passed review.

## A1: parent and tenant isolation

- `backend/app/core/db.py`: migrate the operation primary key from
  `(operation_id, organization_id)` to a parent-scoped composite identity.
  Include parent request and tenant in every operation lookup and update.
  Preserve the original requester when creating child requests.
- `backend/app/core/models.py`: define and validate operation-instance identity.
- `backend/app/core/migration_registry.py` and `migration_artifacts.py`: add a
  forward migration, deterministic preflight, and schema postconditions. Preserve
  historical migration identity and existing data.
- Tests: two same-tenant parents containing the same operation coexist; approving
  one leaves the other unchanged; cross-tenant access fails.

Verified source evidence: the current v11 table uses a tenant-wide operation
primary key; the manifest builder generates repeatable `engine:tool` identifiers;
the approval update omits `scan_request_id`. This is a real repeated-scan defect.

## A2: deterministic request creation

- `backend/app/api/scans.py`: accept and validate creation `Idempotency-Key`.
- `backend/app/core/models.py`, `db.py`, and `storage.py`: bind the key to a
  canonical input fingerprint and tenant; return the original request on replay.
  Generated IDs and timestamps must not change the input fingerprint.
- Tests: identical replay returns the same request; changed input conflicts;
  concurrent identical creation creates exactly one parent and one child set.

## A3: reconstructible approved content

- `backend/app/core/scan_manifest.py`: accept effective `ScanConfig`, profile,
  engine selection, enable flags, behavior-changing options, target/project
  bindings, budgets, and credential references. Never persist plaintext secrets.
- `backend/app/core/models.py`: ensure nested content cannot mutate an approved
  manifest; define canonical serialization and reject duplicate operation keys.
- `backend/app/core/db.py`: persist all hash material, reconstruct and rehash it
  after acquiring approval locks, and reject tampering or policy changes.
- Tests: every accepted behavior-changing option affects the hash; unsupported
  options fail validation; storage roundtrip rehashes identically; tampering fails.

## A4: truthful operation inventory

- `backend/app/core/tool_operation_policy.py`: replace inferred availability with
  evidence-backed operation schemas and explicit unresolved support states.
- `backend/app/core/scan_manifest.py`: preserve all 26 fleet identities, represent
  native GTFOBins and CI/CD operations, retain both Trivy engine operations, and
  apply disabled-tool exclusions consistently.
- Tests: complete fleet identity, native operation entries, distinct dual Trivy
  instances, applicability, duplicate rejection, and disabled-tool exclusions.
- No four-tool feature expansion belongs to this section.

## A5: valid and side-effect-idempotent approval

- `backend/app/api/scans.py`: use the registered `execution:approve` scope with
  the administrator role; return explicit pending dispatch information until B.
- `backend/app/core/db.py`: validate current principal, session, expiry,
  revocation, asset ownership/delegation, policy, manifest and budgets after
  locks, including replay. Replay must not create additional child authority.
- Tests: ordinary tenant administrator, missing permission, inactive principal,
  expired/revoked session, changed manifest, and repeat approval.

Completed partial evidence: the route now uses `execution:approve`; the actual
route dependency accepts a tenant administrator with normal default scopes and
rejects an administrator lacking the required scope. Isolated test: 1 passed.
This establishes the permission guard only, not successful durable approval.

## A6: transactions, upgrades and delivery evidence

- `backend/app/core/storage.py` and `db.py`: parent, operation, scan, run and audit
  writes commit or roll back together. Verify connection ownership and lock order.
- Extend existing API, authorization, manifest and migration tests with failure
  injection, fresh database creation, and valid prior-version upgrade fixtures.
  Keep separate ledger-gap rejection tests; do not substitute them for upgrades.
- Configure disposable databases before application imports. Do not use
  `data/cyberassess.db` as a test fixture or alter it during diagnostics or
  tests without separate explicit authorization. An authorized read-only
  inspection of an exact path is permitted when its scope and evidence are
  recorded; destructive operations require separate authorization.
- Reconcile affected authoritative contracts and mirrors without claiming that
  documentation changes establish implementation acceptance.
- Record test commands, results and logs, requirement-to-test mapping, baseline
  and final diff identity, changed-file rationale and unresolved limitations.
- Run the isolated full regression suite and classify observed failures from
  their actual logs. Do not classify unobserved failures as stale.
- Commit and push once when the section is complete, then ask the auditor to
  review A1–A6. Pause edits during that review. Section A acceptance does not
  establish full-contract or four-tool completion.

## Section A verification record — 2026-09-08

This record documents the current bounded verification state. It is evidence
for auditor review, not an acceptance decision. The working tree remains
uncommitted and unpublished because the auditor's Section A gate requires
acceptance before delivery operations.

> Historical snapshot notice: the test counts and scope notes in this record
> were captured before the subsequent auditor-rework correction round. They
> remain preserved as historical evidence but are superseded by the latest
> correction-round record below.

### Changes verified in this pass

- `backend/app/core/db.py`: PostgreSQL migration v11 now creates the exact
  `(scan_request_id, organization_id)` parent key before child foreign keys;
  the v11 postcondition verifies the named unique parent index and both
  composite child foreign keys using schema-qualified PostgreSQL catalogs; the
  v13 verifier uses schema-qualified primary-key inspection; and the v13
  PostgreSQL apply path has an idempotent fast path plus coordinator-owned
  durable ledger recording.
- `backend/app/core/scan_request_migration_v13.py`: PostgreSQL v13 checks the
  canonical request columns, parent-scoped operation key, and valid
  idempotency index before returning without rebuilding an already complete
  schema.
- `backend/app/core/migration_artifacts.py`: current forward-apply and
  postcondition fingerprints match the reviewed source for the supported
  SQLite and PostgreSQL paths. Historical migration fingerprint values remain
  unchanged.
- `tests/security/test_postgres_integration.py`: PostgreSQL fixtures now derive
  the expected migration versions from `MIGRATION_REGISTRY`, use the current
  constraint/index identities, exercise v2 remediation through the bounded
  helper without replaying later non-replayable historical DDL, and pass the
  current approval-call contract.

### Verification results

All database-backed checks below used disposable paths. No test used
`data/cyberassess.db`.

| Check | Result | Evidence |
| --- | --- | --- |
| Python compilation | PASS | `python -m py_compile tests/security/test_postgres_integration.py backend/app/core/db.py backend/app/core/scan_request_migration_v13.py backend/app/core/migration_artifacts.py` |
| SQLite migration/artifact vectors | 17 passed, 1 skipped, 41 deselected | Explicit `CYBERASSESS_DB_PATH` and explicit pytest base directory; the skip is the historical `a1c4fc4` v1 artifact-mismatch fixture at `tests/security/test_scan_request_migration.py:180`. |
| 26-tool fleet consistency | 3 passed | Explicit disposable SQLite path. |
| Pre-v13 manifest freeze | 1 passed, 41 deselected | `backend/tests/test_scan_manifest_contract.py -k pre_v13_migration_sources_and_metadata_remain_frozen`. |
| PostgreSQL schema assurance | 13 passed | Fresh disposable `postgres:16-alpine`; explicit loopback `CYBERASSESS_POSTGRES_TEST_URL`; readiness check; schema test file; container removed after the run. |
| Full local regression | 786 passed, 23 skipped, 15 warnings | Explicit disposable SQLite path and pytest base directory; 298.99 seconds. Skips and warnings were emitted by the suite and were not reclassified as passes. |
| Repository whitespace check | PASS | `git diff --check`. |

The PostgreSQL run also covered fresh bootstrap, rerun/idempotency, v2 legacy
foreign-key remediation, schema-health rejection of wrong-column indexes,
approval correlation rejection without authority mutation, audit integrity,
and duplicate/orphan/cross-tenant migration preflight rejection.

### Verification caveats and protected runtime state

- One preliminary local command omitted the explicit SQLite path and attempted
  to import the ambient runtime database. It failed during collection on the
  existing migration-ledger identity mismatch for v8 and is excluded from the
  pass counts. The tests were rerun successfully with explicit disposable
  paths. This environment mistake must not be used as application evidence.
- A separate preliminary run used pytest's default temporary directory and
  received host-level access-denied errors. It was rerun with an explicit
  disposable pytest base directory and produced the passing results above.
- The exact runtime database path
  `E:\web apps\security-assessment-platform\data\cyberassess.db` was inspected
  only for metadata during this pass. Its observed size was `10285056` bytes
  and its `LastWriteTimeUtc` remained `2026-09-04T23:24:42.6548237Z`. A
  preliminary application import consulted the ambient migration-ledger
  metadata and failed on the existing v8 identity mismatch; it did not
  intentionally inspect application records. The file was not staged,
  modified, copied, mounted, archived, or included in any delivery operation.
- At the time of this historical verification pass, the branch was
  `security/nmap-installer-closure` at HEAD
  `351430bc47144581371eb5bb544e7bd9b55f9db5`, matching the configured
  `origin/security/nmap-installer-closure` ref. The worktree was intentionally
  dirty from the broader uncommitted Section A correction round, and that pass
  itself performed no commit, push, branch operation, deployment, or mirror
  operation. The later checkpoint publication is recorded below and supersedes
  this paragraph only as a statement of current repository delivery state.

### Remaining Section A status

### Section A auditor-rework closure record — 2026-09-08

This record covers the auditor's final Section A rework request. It remains
evidence for independent review and is not a local acceptance declaration.

> Historical snapshot notice: the results in this record predate the final
> v13 exact-schema verification and workflow-static-test correction round.
> They remain immutable historical evidence; the latest results are recorded
> in the correction-round record below.

- `ValidatedTarget` now stores `authorized_scope` and `resolved_addresses` as
  tuples and recursively freezes `authorization_context` using the existing
  JSON-compatible immutable mapping boundary. Construction rebuilds the
  values, so caller-owned lists and nested dictionaries cannot mutate the
  sealed object. Canonical JSON serialization remains stable after a
  round-trip, and a derived SHA-256 digest is unchanged.
- The existing target tamper test now records both controls: direct mutation
  is rejected by the immutable representation, while a copied object with a
  changed scope is rejected by the gateway integrity seal.
- `.github/workflows/contract-verification.yml` now runs on `main` and the
  governed `security/nmap-installer-closure` branch, with `workflow_dispatch`
  retained as a controlled manual trigger. The PostgreSQL skip guard is an
  executable multiline Python guard that fails only when `skipped > 0`; the
  focused suite has a separate guard that allows only the documented
  historical `a1c4fc4` fixture skip and fails on any new skip. Required job
  IDs and pinned action references remain unchanged. The focused job now
  includes migration, launch-inventory, execution-decision/approval, and
  workflow-hardening coverage.
- A disposable PostgreSQL 16 catalog probe demonstrated the pre-change
  defect with two validated `organization_id → organizations(id)` foreign
  keys on `scan_authorization_requests`. The shared v11 forward DDL now has
  one declaration, and the PostgreSQL and SQLite fresh-schema tests assert
  exactly one parent organization binding. Existing runtime databases were
  not altered; any legacy schema requiring operator reconciliation remains a
  separate deployment concern.
- Current forward-apply fingerprints for migrations v1–v12 and the current
  pre-v13 evidence snapshot were recalculated from the reviewed source after
  the DDL correction. Historical migration ledger/checksum fingerprints and
  the committed pre-v13 baseline were not rewritten. The known v12-to-v13
  historical fixture remains blocked/unverified and is not represented as a
  pass.

| Rework checkpoint | Result | Evidence |
| --- | --- | --- |
| ValidatedTarget deep immutability and canonical round-trip | PASS | `backend/tests/test_scan_manifest_contract.py`: targeted immutability test; `tests/security/test_web_dast_assurance.py`: tamper-boundary test. |
| Workflow YAML and executable guard validation | PASS | YAML parser accepted the workflow; `tests/security/test_container_hardening.py`: governed-trigger, guard compilation, zero/nonzero PostgreSQL behavior, allowlisted/unexpected focused-skip behavior. |
| Expanded focused Section A suite | 160 passed, 1 documented skip | Explicit disposable SQLite path and separate pytest base; the only skip is the allowlisted historical `a1c4fc4` fixture. |
| Fresh PostgreSQL 16 schema assurance | 13 passed | New disposable PostgreSQL 16 container, loopback URL, explicit acknowledgment, fresh schema, container removed afterward. |
| Full local regression | 788 passed, 23 skipped, 15 warnings | Explicit disposable SQLite path and pytest base; exit code 0. Warnings/skips remain visible and are not counted as passes. |
| Current migration artifact/source reconciliation | PASS | Runtime forward-apply vector test and current pre-v13 source/metadata freeze test. Historical baseline preserved. |

The repository remains uncommitted and unpublished pending the auditor's
independent acceptance. No branch, remote, deployment, existing container,
Proxmox guest, or `data/cyberassess.db` file was changed in this rework.

The fresh database and regression evidence support the implementation changes,
but Section A remains `IN PROGRESS` pending the auditor's independent review.
The historical v12-to-v13 fixture mismatch remains an explicit unresolved
historical-evidence limitation. Sections B (dispatch), C (process ownership),
D (recovery), E (four-tool capability implementation), and the later
GitHub-authoritative CI/CD delivery gate remain outside this bounded closure
pass.

### Section A correction-round current verification record — 2026-09-08

This is the current evidence record for the correction round. It supersedes
the numerical results in the two historical records above without deleting
those records. It is evidence for independent auditor review, not a local
acceptance declaration.

#### Implementation and provenance corrections

- `ValidatedTarget` public construction and copy paths (`model_copy`,
  `model_construct`, and deprecated `copy`) re-enter normal validation and
  recursively freeze nested authorization values. The dedicated test covers
  direct mutation, public copy updates, unknown fields, and canonical
  serialization stability.
- The same public reconstruction guard now covers `ScanManifestOperation`,
  `ScanManifestEngineOperation`, `ScanAuthorizationManifest`, and
  `ScanAuthorizationRequestRecord`. Unknown fields, changed canonical target
  values with stale hashes, invalid target types, and organization/tenant
  mismatches fail closed across `model_copy`, `model_construct`, and deprecated
  `copy`. The manifest digest builder uses a private trusted construction path
  only for its zero-hash digest preimage; ordinary public construction is
  validation-bound.
- Manifest mappings are backed by an immutable tuple-backed `Mapping`, not a
  `dict` subclass. Ordinary and inherited C-level dictionary mutators are
  rejected, nested values remain detached and immutable, and the SSRF
  execution-boundary verifier accepts the secure `Mapping` representation.
- Contract mirror verification now requires raw-byte equality, not merely
  normalized text equality. The Contract 04 source/mirror line-ending drift
  was repaired from the authoritative `contracts/` copy and both files now
  have identical bytes.
- The v13 SQLite complete-schema fast path now invokes the full v13 verifier
  before returning. This keeps direct callable use fail-closed instead of
  relying only on the coordinator's subsequent verification step.
- The v13 SQLite and PostgreSQL verifiers require the exact parent-scoped
  operation primary key, tenant-bound child uniqueness, composite parent and
  child foreign keys, organization bindings, required request material,
  idempotency index, and exact all-or-none child-link CHECK. PostgreSQL
  catalog checks include btree, readiness, validity, and constraint
  validation properties.
- The current v13 forward-apply artifact values were recalculated from the
  reviewed source after the fast-path correction: SQLite
  `sha256:820f109dbe3e626363e475a16a0caa3fac638fa4e7b15139976d328a303e4334`;
  PostgreSQL
  `sha256:f86fbbb9e9ca9fb84f7a5f102251b26ef7b6df28a0336f011ed64b257cb8ca90`.
  The provenance test compares the source-derived values to the committed
  evidence map and preserves the historical v1-v10 ledger identities.
- The frozen v12-to-v13 fixture was executed from the committed `a1c4fc4`
  archive. It remains `PROVENANCE_BLOCKED` because the legacy subprocess
  returns the exact committed v1 forward-apply artifact mismatch. No pass
  claim is made; recovery of the accepted historical v1 baseline remains an
  owner-escalated release-blocking evidence item.

#### Verification results

| Check | Result | Evidence |
| --- | --- | --- |
| Workflow YAML parse and Python compilation | PASS | YAML parser accepted `.github/workflows/contract-verification.yml`; `python -m compileall -q backend tests` exited 0. |
| Workflow static contract and executable guards | 11 passed, 1 warning | `tests/security/test_container_hardening.py`; governed triggers, exact job IDs, SHA-pinned actions, disposable paths, artifact policy, and skip classifiers. |
| SQLite v13 migration, manifest, tamper, fast-path, and provenance vectors | 69 passed, 1 documented skip, 1 warning | `tests/security/test_scan_request_migration.py backend/tests/test_scan_manifest_contract.py`; the only skip is the recorded `a1c4fc4` provenance block. |
| Model and execution-boundary tamper vectors | 74 passed, 1 warning | `backend/tests/test_scan_manifest_contract.py tests/security/test_web_dast_assurance.py tests/security/test_validated_target_seal.py`; includes ordinary and C-level nested-mapping mutation attempts and the actual SSRF integrity boundary. |
| Focused Section A contract suite | 184 passed, 1 documented skip, 0 failures | The exact focused file allowlist from `.github/workflows/contract-verification.yml`, 185 collected tests, rerun with an isolated disposable SQLite path and pytest base directory; the only skip is the recorded historical fixture block. |
| PostgreSQL 16 schema assurance | 29 passed, 0 skipped, 1 warning | Fresh disposable `postgres:16-alpine` container, loopback URL, explicit disposable-database acknowledgment, catalog tamper/restart vectors, and container removal. |
| Full local regression | 812 passed, 39 skipped, 15 warnings | Disposable SQLite path, isolated pytest base directory, JUnit total `851`, failures `0`, errors `0`, duration `286.83s`; the strengthened manifest validator is included. |
| Contract source/mirror byte consistency | PASS | `tests/security/test_contract_fleet_consistency.py`; all maintained `contracts/` and `docs/contracts/` pairs compare equal as raw bytes, including the repaired Contract 04 pair. |
| Historical worktree inventory serialization and capture-time reconciliation | PASS | `test_worktree_inventory_snapshot_matches_documented_git_serialization` plus an independent recomputation at capture time; explicit NUL-delimited porcelain status, strict UTF-8 path decoding, Python Unicode code-point path sort, LF/TAB serialization, exact state/path entries, and matching all/non-`.ci`/`.ci` digests. |
| Section A pre-publication delivery-candidate manifest coverage | 6 passed | `tests/security/test_contract_fleet_consistency.py` historical deterministic run; 106 unique non-`.ci` entries were classified exactly once with captured porcelain-state equality, declared classification totals, normalized contract references whose locators resolve in-file, source-of-truth evidence, existing test files/symbols, and an in-memory tampered-locator rejection. `independent_test_exercised` remains a declared evidence claim, not runtime correlation. The manifest records 39 Section A candidates, 9 evidence/governance paths, 55 outside Section A, and 3 unresolved paths. |
| Repository whitespace check | PASS | `git diff --check`. |

The final rerun evidence files are retained outside the repository at these
disposable paths: focused contract JUnit
`C:\Users\junme\AppData\Local\Temp\cyberassess-focused-final-evidence-45dfc4f21a764d69b18c4ebfd0ce5581\focused-contract.xml`,
full-suite JUnit
`C:\Users\junme\AppData\Local\Temp\cyberassess-full-final-evidence-34fd4a33a23e42779cdc0dd6a9766f2f\full-suite.xml`,
and PostgreSQL JUnit
`C:\Users\junme\AppData\Local\Temp\cyberassess-pg-final-f7420759f2994a72914bb6e1c857d54e\postgres-suite.xml`.
They are not delivery files and do not contain the runtime database.

The full-suite skip classifier observed exactly these reasons:

| Count | Classification | Reason |
| ---: | --- | --- |
| 29 | `DEPENDENCY_DEFERRED_TO_POSTGRES_JOB` | `CYBERASSESS_POSTGRES_TEST_URL is required for the isolated PostgreSQL integration suite` |
| 4 | `PLATFORM_CAPABILITY_UNAVAILABLE` | `Symlinks require elevated privileges on Windows` |
| 2 | `ENVIRONMENT_UNAVAILABLE_MANAGED_TOOL` | `UNAVAILABLE: approved managed Subfinder v2.6.5 binary is not installed` |
| 1 | `ENVIRONMENT_UNAVAILABLE_MANAGED_TOOL` | `Managed nmap binary not present on this dev machine` |
| 1 | `PLATFORM_CAPABILITY_UNAVAILABLE` | `Symlink creation is unavailable in this environment` |
| 1 | `PLATFORM_CAPABILITY_UNAVAILABLE` | `Unix process sessions are not available on Windows` |
| 1 | `PROVENANCE_BLOCKED_ESCALATION_REQUIRED` | `historical a1c4fc4 fixture is blocked by its committed v1 artifact mismatch` |

The full local run therefore has no unclassified skips. The 15 warnings remain
visible and are not counted as passes; they include existing dependency,
deprecated TLS, async-test, API-deprecation, and pytest-cache permission
warnings. `actionlint` is not installed in this environment and is not claimed
as executed.

The first PostgreSQL rerun in this correction round failed at the repository's
disposable-harness guard for 28 database-dependent cases because the supplied
URL used `/postgres`, which is not an allowed `_ci` or `_test` database name;
one non-database test passed and the fresh container was removed. This was a
test-configuration failure, not application evidence. The corrected rerun used
a newly created `cyberassess_test` database and passed all 29 PostgreSQL tests;
no application code changed between those runs.

#### Scope and runtime-state evidence

- The exact runtime database path
  `E:\web apps\security-assessment-platform\data\cyberassess.db` remains
  outside delivery scope. Its observed metadata remains `10285056` bytes and
  `LastWriteTimeUtc` `2026-09-04T23:24:42.6548237Z`. The user has explicitly
  authorized exact-path read-only inspection; this correction pass only
  encountered the existing v8 migration-ledger identity mismatch during
  ambient import and did not inspect application records. The database was
  not staged, modified, copied, mounted, archived, or published.
- The historical pre-publication snapshot was captured on branch
  `security/nmap-installer-closure` at HEAD
  `351430bc47144581371eb5bb544e7bd9b55f9db5`. It contains 1,815 visible
  status entries: 106 non-`.ci` entries and 1,709 `.ci` entries. These captured
  facts remain immutable evidence and are not a claim about the current
  post-publication live worktree.
- After explicit user authorization, the exact 106 manifest-listed non-`.ci`
  paths were committed as the non-production rollback checkpoint
  `fa05003f0b841c800ca805be80106a7a8c708d60`, with tree
  `adb08c837c679b05e69aeef302c016227c0052cb` and sole parent
  `351430bc47144581371eb5bb544e7bd9b55f9db5`. The checkpoint was published
  to GitHub first and then mirrored by a normal fast-forward to GitLab at the
  identical SHA and tree. Neither `.ci` nor `data/cyberassess.db` is present in
  the checkpoint commit.
- Immediately after checkpoint publication, the local worktree had zero staged
  entries and 1,709 visible entries, all under `.ci`; it had zero non-`.ci`
  status entries. GitHub Actions was not run as an acceptance prerequisite for
  this explicitly non-production checkpoint. No deployment, runtime database
  mutation, test-server synchronization, Proxmox operation, or contract
  acceptance is claimed.
- The inventory count uses the complete command
  `git status --porcelain=v1 --untracked-files=all --no-renames -z`.
  Compact `git status --short` output may collapse the `.ci/` tree and must not
  be used as the complete path count. The checked-in evidence validator and an
  independent recomputation both reproduced all recorded counts, path digests,
  and state/path digests.
- Disposable test databases and pytest directories were created outside the
  runtime database path. The previously preserved repository `.ci/` tree was
  restored to its original location after the auditor requested restoration;
  its physical tree contains 1,811 files and 350 descendant directories, of
  which 1,709 file paths are visible in Git status and 102 are excluded by
  existing ignore rules. It remains preserved and outside delivery scope
  pending ownership/cleanup classification; it is not a runtime data source.
- The machine-checkable historical pre-publication snapshot
  `docs/evidence/section_a_worktree_inventory_2026-09-08.json` records the
  exact non-`.ci` status entries and deterministic path digests for all visible
  status groups. Its non-`.ci` entries are independently reconstructed from the
  no-renames Git transition between the recorded pre-publication HEAD and the
  checkpoint commit; current preserved `.ci` evidence remains validated
  separately. The temporary preservation directory used before restoration no
  longer exists because the `.ci/` tree was restored in place; no preserved path
  was deleted.

#### Exact path-by-path worktree inventory

This inventory is the historical pre-publication status captured after the
correction-round verification.
The machine-checkable snapshot named above accounts for all 1,815 visible
status entries. The machine-checkable candidate manifest
`docs/evidence/section_a_delivery_candidate_manifest_2026-09-08.json` expands
to every one of the 106 non-`.ci` status/path pairs exactly once and records
the applicable contract references, test vectors, change kind, independent
exercise status, and unresolved ownership state for each group. The 1,709
`.ci` entries are preserved as one explicitly identified artifact set and are
represented by the snapshot's exact path and state/path digests. Every listed
repository path was unstaged at capture; the 106 non-`.ci` paths were later
published together in the non-production checkpoint without resolving their
recorded ownership. Git metadata does not establish whether a change originated
with the user, an earlier agent, or this correction round, so ownership remains
`UNRESOLVED` and no path is treated as disposable source.

The source-of-truth rule is evidence-backed rather than assumed: `contracts/README.md`
under `## Master Contract Index (Contracts 01 – 09)` identifies `contracts/` as
the authoritative production-level contract directory; the existing
`tests/security/test_contract_fleet_consistency.py::test_authoritative_contract_mirrors_and_scope_match_26_tool_fleet`
defines and checks the corresponding `docs/contracts/<same filename>` mirror;
`contracts/05_DELIVERABLES_AND_ACCEPTANCE_CRITERIA_CONTRACT.md` §3 and
`AGENTS.md` §GitHub-to-GitLab mirror consistency govern delivery and promotion.
Raw-byte equality proves synchronization, while those repository references
establish which copy is authoritative.

| Status class | Count | Delivery decision | Exact-list authority |
| --- | ---: | --- | --- |
| `SECTION_A_CANDIDATE`; ownership `UNRESOLVED` | 39 | `REVIEW` against A1–A6 and auditor scope | Candidate manifest `groups` with exact paths, porcelain states, contract clauses, test vectors, and checkpoint mappings. |
| `EVIDENCE/GOVERNANCE`; ownership `UNRESOLVED` | 9 | Retain as review evidence; not implementation authorization | Candidate manifest `groups`; includes policy, goal, checkpoint, provenance, inventory, and candidate-manifest artifacts. |
| `OUTSIDE-A`; ownership `UNRESOLVED` | 55 | Preserve and review in the applicable later section; do not silently stage | Candidate manifest `groups`; includes tool, engine, installer, process, and Contract 09 paths. |
| `UNRESOLVED`; ownership `UNRESOLVED` | 3 | Stop and obtain owner/auditor classification; do not guess | Candidate manifest `groups`; current unresolved paths are observation/orchestration implementation and its test. |
| `.ci` preserved tree | 1,709 visible status paths | `RUNTIME-EXCLUDED` delivery-exclusion label for preserved CI/test evidence, not runtime data; preserved in place pending ownership/provenance review | Inventory snapshot `.ci` entries and physical-tree metadata. |
| `data/cyberassess.db` | Not in Git status | `RUNTIME-EXCLUDED`; exact-path read-only inspection permitted, no delivery operation | Runtime-state evidence and explicit database exclusion in the manifest. |

The exact runtime path `E:\web apps\security-assessment-platform\data\cyberassess.db`
does not appear in `git status`, `git diff`, or the inventory above. It is
explicitly `OUTSIDE DELIVERY` regardless of the user-authorized exact-path
inspection amendment. The `.ci/` directory is preserved in place and is not a
delivery candidate pending ownership review; its status-path digest and counts
are recorded in the machine-checkable snapshot. No other untracked path is
silently classified as generated.

#### Current status

The non-production checkpoint is published and mirrored, but Section A remains
`IN PROGRESS`. The frozen historical fixture remains
`PROVENANCE_BLOCKED_ESCALATION_REQUIRED`, ownership of the captured broader
worktree remains unresolved, and a checkpoint does not convert those paths into
an accepted delivery section. GitHub Actions was not run for the checkpoint, so
no authoritative CI success is inferred. The current test server was not
synchronized to the checkpoint and remains outside this evidence-closure goal.
Final contract acceptance, release review, and deployment remain pending their
respective gates.

#### Authorized single-branch topology inventory and closure

The user subsequently authorized reducing both providers to the existing
governed branch `security/nmap-installer-closure`. No branch is created, renamed,
or force-updated. Before any deletion, the provider inventory was:

| Provider/ref | Tip SHA | Tree SHA | Commits unique from governed tip `6d90d5a` | Provider state before cleanup |
| --- | --- | --- | ---: | --- |
| GitHub `main` | `250a5b3a6f5e045f365610bbb6f568c4edb92770` | `b146b1c8a7c3148e24cc24786511b7dc2396f182` | 0 | Default branch; unprotected; required-status enforcement off. |
| GitHub `security/audit-closure-2026-09-03` | `b83c27a1252a50eeb94a977f61e681f3b82b0427` | `568ecf9aa03f91acc18dc64795a3223322e63e66` | 23 | Non-default; unprotected; required-status enforcement off. |
| GitHub `security/e13-enterprise-audit-closure` | `17bdd84f085a9e7733921acd3b8a93a3f172aa37` | `7b9b7f6cee6c1e4249ffb8816f8d6fc332f785f5` | 0 | Non-default; unprotected; required-status enforcement off. |
| GitHub `security/nmap-installer-closure` | `6d90d5a86c0b3b8af5082aeb39108325be755375` | `107ff1f4d0588418fdbfa6a7575266bc164543be` | 0 | Governed keep branch; unprotected; required-status enforcement off. |
| GitLab `security/nmap-installer-closure` | `6d90d5a86c0b3b8af5082aeb39108325be755375` | `107ff1f4d0588418fdbfa6a7575266bc164543be` | 0 | Sole GitLab branch; mirror only. |

GitHub reported no repository rulesets and no classic branch protection on the
default or governed branches; its branch listing reported all four refs as
unprotected with required-status enforcement off. The authorized provider
sequence is therefore: publish this evidence record on the governed branch to
GitHub first; mirror the identical commit to GitLab; change the GitHub default
branch from `main` to the already-existing governed branch; and delete only the
three exact non-governed GitHub refs by normal branch deletion. GitLab requires
no branch creation or deletion.

At completion, live provider verification must show exactly one branch on each
provider, named `security/nmap-installer-closure`, with identical SHA, tree, and
ordered reachable history. The final SHA/tree of the commit containing this
record is necessarily external delivery evidence: embedding that commit's own
SHA in its contents would change the Git object. The final delivery report binds
that SHA/tree to this document and the provider refs. The 23 commits unique to
the old audit-closure ref are intentionally losing their branch name under the
user-authorized reduction; no tag, replacement ref, history rewrite, or
force-push is created.

#### Post-checkpoint evidence-closure verification — 2026-09-08

The evidence validator now treats the 1,815-entry inventory and 106-path
candidate manifest as historical pre-publication records. It independently
reconstructs the captured non-`.ci` states from the no-renames Git transition
between parent `351430bc47144581371eb5bb544e7bd9b55f9db5` and checkpoint
`fa05003f0b841c800ca805be80106a7a8c708d60`: checkpoint status `M` maps to
captured porcelain state ` M`, and checkpoint status `A` maps to captured state
`??`. Deletes, renames, copies, type changes, unmerged states, `.ci` paths, and
`data/cyberassess.db` are rejected. The current preserved `.ci` tree is still
validated when present; a clean delivery checkout instead verifies that `.ci`
was excluded from the checkpoint tree.

| Check | Result | Evidence |
| --- | --- | --- |
| Focused contract/evidence suite | 7 passed, 0 failed, exit 0 | Fresh disposable SQLite path and pytest base outside the repository; validates Git parent/commit/tree identity, the 106 reconstructed captured paths, six preserved inventory digests, current `.ci` preservation, manifest/snapshot identity, delivery-provider roles, 26-tool consistency, contract mirrors, and negative transition/locator tamper cases. |
| Full local regression | 814 passed, 39 skipped, 14 warnings, exit 0 | Fresh disposable SQLite path and external pytest base; JUnit records 853 cases, 0 failures, 0 errors, 39 skipped, and 286.569 seconds. Skips remain visible and are not counted as passes; PostgreSQL tests are dependency-gated in this local run. |
| Full-suite JUnit | RETAINED OUTSIDE REPOSITORY | `C:\Users\junme\AppData\Local\Temp\cyberassess-postcheckpoint-regression-final-61b911d2bcd24150b3106cb17685a27b\full-suite.xml`; 129,424 bytes. |

This verification does not change the non-production status of the checkpoint,
does not supply authoritative GitHub Actions evidence, does not resolve A6
historical provenance or path ownership, and does not prove test-server
synchronization or deployment readiness.

#### Full-regression warning-count reconciliation — 2026-09-08

The previously reported `14` and independently observed `15` warning counts are
both retained because they come from two reproducible command variants. All
three comparison runs used
`C:\laragon\bin\python\python-3.13\python.exe`, Python `3.13.0`, pytest `9.1.1`,
the `anyio` and `asyncio` pytest entry-point plugins, and
`-p no:cacheprovider`. No `PYTESTADDOPTS`, `PYTHONWARNINGS`, repository warning
filter, test edit, or warning suppression was used.

| Run | Exact material command options | Result | Attribution |
| --- | --- | --- | --- |
| JUnit evidence command | `--basetemp <external>/pytest --junitxml <external>/full-suite.xml -q -ra` with explicit disposable `CYBERASSESS_DB_PATH`, empty `DATABASE_URL`, `PYTHONPATH=backend`, `OPERATING_MODE=TEST`, and a test-only JWT secret | 814 passed, 39 skipped, **14 warnings**, exit 0, 299.61s; JUnit 853 cases, 0 failures/errors, 39 skipped, 299.589s | Reproduces the documented 14-warning evidence. JUnit: `C:\Users\junme\AppData\Local\Temp\cyberassess-warning-reconcile-junit-3c445b09ee914c458f9f1488426f950b\full-suite.xml`. |
| Independent auditor command | `--basetemp <external>/pytest -q` with disposable `CYBERASSESS_DB_PATH` and empty `DATABASE_URL`; no JUnit option | 814 passed, 39 skipped, **15 warnings**, exit 0, 281.34s | Independently observed result supplied by the auditor. |
| Controlled no-JUnit comparison | `--basetemp <external>/pytest -q -ra` with the same explicit test-mode environment as the JUnit command, but no JUnit option | 814 passed, 39 skipped, **15 warnings**, exit 0, 311.15s | Isolates the observable variance from the extra environment and `-ra`; the no-JUnit form still reports 15. |

The warning-category comparison identifies the additional no-JUnit warning as
a second unawaited `AsyncMockMixin._execute_mock_call` `RuntimeWarning` attached
to `test_scenario_14_interactive_http_repeater` through
`unittest.mock.py`. The JUnit command reports the scenario-14 warning through
`fastapi.routing.py` and one `unittest.mock.py` warning for scenario 19; the
no-JUnit commands additionally report the scenario-14 `unittest.mock.py`
instance. This is separately attributable reporting evidence, not proof that a
warning disappeared from the application and not authority to classify either
count as a pass. The historical 15-warning regression record above remains
unchanged.

## Subsequent CI/CD section: GitHub Actions authority, GitLab mirror

Product direction received from the auditor on 2026-09-05. This is pending
implementation and does not expand the current Section A execution scope.

- Preserve `.github/workflows/contract-verification.yml` and
  `backend/app/engines/cicd_audit/github_actions_auditor.py`.
- Add `.gitlab-ci.yml` and a separate GitLab audit provider alongside the existing
  GitHub auditor. Inspect actual provider configuration before choosing checks.
- Update `backend/app/engines/cicd_audit/engine.py` and
  `backend/app/core/models.py` with normalized, separately attributable provider
  results. GitHub Actions is authoritative for required CI status, pipeline
  policy, release/deployment gates and CI compliance evidence. GitLab is a
  repository mirror only; GitLab CI/CD results are separately attributable
  diagnostics and cannot satisfy, replace, or override a GitHub Actions gate.
- Persist provider, pipeline ID, commit/ref, source revision, policy revision,
  timestamp and evidence digest with tenant/project and audit correlation. Locate
  the actual persistence and reporting call sites before assigning those edits.
- Expose authority and secondary status in the API, `frontend/js/app.js`, and
  reports. Unavailable, stale, unauthorized or unverifiable GitLab evidence must
  visibly degrade or block authoritative gates, never silently fall back to GitHub.
  Preserve conflicting results independently.
- Review protected branches/tags, protected variables, runner trust/protection,
  token scopes, merge-request approval/status gates, dependency pinning, artifact
  integrity/retention, secret exposure and environment protections. Mark checks
  without sufficient evidence unverified; do not reuse GitHub permission semantics.
- Reconcile Contracts 02, 03, 04, 05, 06, 07 and 08 and their authoritative mirrors
  against the approved provider model and actual implementation.
- Acceptance checkpoints: authoritative GitHub Actions pass; GitHub failure or
  unavailability blocks acceptance; GitLab mirror/ref/SHA verification follows
  GitHub success; GitLab-only results cannot satisfy acceptance; conflicting
  results are retained; cross-provider evidence is rejected; each provider is
  independently auditable; tenant/project/commit binding is preserved. Include
  actual GitHub Actions pipeline evidence before claiming deployed gate success;
  any GitLab pipeline evidence is diagnostic only.
- Produce the detailed CI/CD file-by-file plan after call-site inspection and
  required authority sections pass review. Preserve runtime database state and
  keep it out of delivery commits.
