Complete the CyberAssess repository delivery and contract-acceptance cycle using enterprise-grade engineering, security, testing, documentation, CI/CD, and release practices.
CI/CD provider authority for this delivery cycle:
- GitHub Actions is the authoritative CI/CD execution, policy, release/deployment-gate, and compliance-evidence provider.
- GitLab is a repository mirror only. GitLab CI/CD status, policy, release, deployment, or compliance results must not satisfy an acceptance gate.
- GitHub publication and GitHub Actions verification must complete before any GitLab mirror update.

Database access policy amendment (explicit user authorization, 2026-09-07):
- The prior blanket prohibition on reading `data/cyberassess.db` is superseded.
- The database remains the standalone runtime persistence source defined by the contracts and remains outside delivery commits, mirrors, archives, and publication.
- An explicitly authorized task may inspect or maintain an exact database path and operation. Read-only access is the default for inspection; destructive changes require separate explicit authorization and evidence.
- This amendment does not authorize unrelated implementation, migration, deployment, cleanup, or publication work.

Except for an explicitly authorized scope change, no edits, agent messages, commits, pushes, deployments, or infrastructure changes will begin until this goal is authorized.
- Always use enterprise-level standards for edits, layouts, APIs, behaviors, security controls, tests, and releases.
- Do not overcomplicate simple, bounded tasks.
- Do not guess or assume when repository evidence is available or information is unclear.
- Do not make random changes outside the approved contract scope.
- Preserve all 26 tools, scan history, test history, registries, and existing user changes.
- Do not modify, stage, mount, archive, publish, or include data/cyberassess.db in delivery work unless the exact operation is separately authorized; authorized reads must be scoped and recorded.
- Test every behavior or contract change.
- Commit and push once per completed section, never for micro-changes.
- Do not claim completion without fresh evidence.
- The working tree must not be described as clean unless it is actually clean.
Current planning thread:
- Owns scope, decisions, implementation coordination, evidence integration, and final acceptance.
Independent auditor:
- codex://threads/01a06c58-589e-7850-88ab-9a68ea4ec949
- Reviews every implementation section against the contracts and AGENTS.md.
- Must provide the next detailed plan before the next edit.
- Must receive the exact diff, test results, CI evidence, risks, and unresolved criteria after every section.
GitLab agent:
- codex://threads/01a07125-0da6-7c11-93dd-d9de71f457c5
- Must be asked for GitLab mirror project/ref, exact-SHA verification, promotion,
  artifact, and infrastructure needs.
- Must not be used as a GitLab CI acceptance gate; GitHub Actions is authoritative.
- Must not be used as a substitute for auditor acceptance.
- Must not modify repository source or runtime database data unless separately authorized.
Checkpoints:
1. Read the root AGENTS.md and enumerate any nested AGENTS.md files.
2. Identify authoritative contracts, mirrors, generated copies, and consistency tests from repository evidence.
3. Record:
   - current branch and HEAD;
   - GitHub and GitLab remotes;
   - worktree status;
   - staged and unstaged file ownership;
   - runtime database status;
   - current GitHub and GitLab commit state;
   - latest GitHub Actions workflow and job results;
   - current GitLab mirror ref and exact-SHA state.
4. Inspect the existing uncommitted AGENTS.md change and preserve it until its scope is approved.
5. Do not edit during this section.
Exit criteria:
- Repository state is documented.
- Existing user changes are separated from any proposed change.
- Runtime database data is confirmed outside the delivery scope, with any authorized access recorded separately.
- No unknown source-of-truth assumption remains.
Send the baseline and current failure evidence to the auditor.
The auditor must provide:
- detailed goal analysis;
- contract clauses involved;
- exact authoritative contract file;
- exact mirror or derived file paths;
- source-of-truth rule;
- exact mismatch and cause;
- minimum authorized files;
- required invariants;
- test commands;
- runtime and CI evidence requirements;
- rollback boundary;
- explicit out-of-scope items;
- acceptance and escalation conditions.
No implementation may begin until this plan is received and reviewed.
Primary inspection files:
- tests/security/test_contract_fleet_consistency.py
- Exact contract files identified by repository search.
- Exact mirrored contract files identified by repository search.
- contracts/
- docs/contracts/
- Any contract index or traceability files proven relevant by the auditor.
Rules:
- Do not assume that contracts/ or docs/contracts/ is authoritative.
- Do not manually make copies “look similar.”
- Determine whether the mirror is byte-identical, semantically synchronized, generated, or intentionally different.
- Update only the source or mirror authorized by the auditor.
- Preserve negative tests that reject stale or divergent mirrors.
- Do not alter unrelated contract sections.
- Do not change tool counts, registries, or security boundaries as part of a mirror repair.
Exit criteria:
- Source-of-truth behavior is explicit.
- The contract and mirror are synchronized according to the repository’s defined rule.
- The focused contract test passes locally.
- The auditor approves the candidate diff.
Inspection-only files unless separately authorized:
- backend/app/core/db.py
- backend/app/core/migration_artifacts.py
- tests/security/test_execution_decision_authority.py
Required checks:
- Verify the v1–v10 migration artifact values against the actual runtime serialization formula.
- Verify SQLite and PostgreSQL vectors.
- Verify one-byte source mutation rejection.
- Verify one-byte artifact mutation rejection.
- Confirm no migration verifier logic is changed without explicit auditor authorization.
- Confirm migration tests use only disposable database paths; do not use data/cyberassess.db as a test fixture unless separately authorized.
- Use only disposable local and CI database paths.
The previous migration-artifact repair must be treated as a completed bounded section, not an excuse for unrelated persistence changes.
Only files explicitly approved by the auditor may be edited.
Potential files, subject to evidence and authorization:
- AGENTS.md
- tests/security/test_contract_fleet_consistency.py
- Exact authoritative contract file(s).
- Exact contract mirror file(s).
- backend/app/core/db.py, only if the auditor proves the current defect requires it.
- backend/app/core/migration_artifacts.py, only if the auditor proves another artifact correction is required.
- .github/workflows/, only if GitHub Actions behavior is proven defective.
- .gitlab-ci.yml, only if a mirror-side compatibility or verification need is proven;
  it must not become an acceptance gate.
- .ci/ files, only if explicitly required by the auditor’s plan.
Files that must not be modified, staged, archived, or published unless separately authorized:
- data/cyberassess.db
- Unrelated Section A modifications.
- Tool adapters, installers, registries, and runtime code unrelated to the approved defect.
- Proxmox configuration and existing guests.
- Scan and test history data.
Run only the tests required by the approved plan, including:
- focused contract consistency tests;
- migration artifact vector tests;
- mutation-rejection tests;
- compilation and static checks;
- applicable full regression tests;
- applicable PostgreSQL integration/schema tests using disposable databases;
- 26-tool registry-preservation checks;
- runtime database path and delivery-exclusion checks.
Evidence must distinguish:
- configured;
- unit-tested;
- locally executed;
- CI-executed;
- skipped;
- failed;
- independently verified.
A skipped test or dependency-gated job is not a pass.
Before staging:
- inspect the exact diff;
- confirm only approved files are included;
- run git diff --cached --check;
- confirm data/cyberassess.db is not staged;
- confirm unrelated user changes are not staged;
- verify the grouped section commit message.
Delivery sequence:
1. Create one grouped commit for the completed section.
2. Push that exact commit to GitHub.
3. Verify the local SHA equals the GitHub branch SHA.
4. Verify the expected files and commit exist on GitHub.
5. Run and verify the required GitHub Actions workflow jobs for that exact commit.
6. Capture GitHub Actions runner identity, timestamps, job status, exit codes, logs,
   artifacts, retries, cancellations, and disposable PostgreSQL evidence.
7. Stop if GitHub publication, GitHub Actions verification, worktree scope, or review
   gates fail.
8. Only after GitHub and GitHub Actions pass, ask the GitLab agent to mirror the exact
   GitHub-verified commit and governed ref using normal non-destructive updates.
9. Verify that GitLab resolves to the identical commit object, tree, ref, and reachable
   history. GitLab CI results, if any, are mirror-side diagnostics only and must not
   replace or override GitHub Actions acceptance evidence.
Ask the GitLab agent to:
- mirror the exact GitHub-verified commit and corresponding governed branch/ref;
- verify the GitLab ref resolves to the identical commit object, tree, and reachable history;
- capture mirror operation status and exact-SHA evidence;
- confirm disposable database isolation for any mirror-side operation;
- confirm the runtime database is not modified, staged, archived, or included in delivery; record any separately authorized read access;
- report any GitLab-side pipeline result separately without making it an acceptance gate.
Required GitHub Actions jobs must execute and pass:
- compile-backend
- focused-contract-verification
- full-repository-verification
- postgres-schema-assurance
GitHub Actions PostgreSQL assurance requires actual:
- postgres:16-alpine startup;
- readiness verification;
- schema test execution;
- retained logs and artifacts.
A declared service, skipped job, stale artifact, dependency-gated result, or GitLab-only
result is not evidence of GitHub Actions success.
After every completed section:
1. Send the auditor:
   - exact commit SHA;
   - changed-file list;
   - diff summary;
   - local test commands and results;
   - GitHub commit/ref verification;
   - GitHub Actions workflow, job, log, artifact, and PostgreSQL evidence;
   - GitLab exact-SHA mirror/ref evidence;
   - runtime evidence;
   - runtime-database and authorized-access evidence;
   - unresolved risks;
   - failed, skipped, or unverified criteria.
2. Ask the auditor for:
   - independent contract review;
   - acceptance decision;
   - detailed remaining-gap analysis;
   - next file-by-file implementation plan;
   - next checkpoints and evidence requirements.
3. Wait for the auditor’s response.
4. Do not begin the next edit until the next plan is received.
5. Repeat the loop until no applicable contract criterion remains unresolved.
Contradictory GitHub and GitLab results must remain distinguishable. They must not be silently merged into a single positive result.
Final acceptance requires evidence for all applicable requirements, including:
- contract and mirror consistency;
- 26-tool preservation;
- security and process isolation;
- output and resource bounding;
- tool trust and artifact integrity;
- migration safety;
- scan and test history persistence;
- capability refresh behavior;
- installer lifecycle behavior;
- GitHub Actions authoritative CI/CD behavior;
- GitLab mirror consistency and exact-SHA behavior;
- GitHub-to-GitLab ref and commit mirroring;
- runtime execution evidence;
- runtime database preservation and authorized-access evidence;
- clean delivery scope;
- exact remote SHA equality;
- independent auditor approval.
The goal is complete only when:
- all required sections pass;
- all required GitHub Actions jobs execute and pass on the accepted SHA;
- GitHub is verified first;
- GitLab contains the identical verified commit;
- no runtime database data was changed;
- all 26 tools remain available;
- the auditor confirms acceptance.
Until then, the status remains executing or escalated with the precise blocker documented.
