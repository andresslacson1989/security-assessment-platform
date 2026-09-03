# CyberAssess Audit Security Closure Plan

**Closure branch:** `security/audit-closure-2026-09-03`  
**Audited base:** `a5dea124dd2556c2aac959dac5c74281c9402231`  
**Purpose:** Close all material findings from the 2026-09-03 read-only security audit without weakening existing contracts, managed-tool assurance, tenant isolation, or evidence traceability.

## Governing execution model

Every section follows the same acceptance chain:

`CONTRACT -> IMPLEMENTATION -> AUTHORITATIVE STATE -> REAL EXECUTION -> OBSERVABLE RESULT -> ADVERSARIAL PROOF -> TRACEABILITY`

A section is not accepted until its negative-path tests prove the former failure mode can no longer occur.

---

## Section A — Authentication, scope authority, JWT and password policy

### Files
- `backend/app/core/auth.py`
- `backend/app/api/auth.py`
- `backend/app/core/models.py` only if the durable identity schema requires it
- `tests/security/test_auth_tenant_boundaries.py`
- new focused authorization assurance tests as needed
- Contracts 01/08 if implementation wording changes

### Required fixes
1. Remove implicit wildcard `*` scope from tenant user sessions.
2. Define server-owned role scope sets. Only `SYSTEM_PRINCIPAL + ADMIN` may receive wildcard authority.
3. `scan:internal` must be explicit and must never be obtained from a tenant role merely by logging in.
4. API-key scope delegation must remain a subset of the caller's effective authority.
5. Restrict JWT verification to the actually configured signing algorithm; do not mix symmetric and asymmetric algorithms in one untyped key store.
6. Raise password storage work factor to the OWASP PBKDF2-HMAC-SHA256 baseline (600,000 iterations) while preserving verification of existing stored hashes.
7. Enforce the NIST SP 800-63B single-factor minimum password length of 15 characters for newly created/bootstrap passwords; retain a large maximum and no arbitrary composition rules.
8. Email-bearing request models must use validated email types where dependency support exists.

### Acceptance tests
- Tenant viewer/developer/analyst/admin logins never acquire `*`.
- `scan:internal` is absent unless explicitly granted through an authoritative mechanism.
- System admin can retain wildcard authority.
- A tenant user cannot mint an API key for a scope they do not possess.
- RS256 token headers are rejected when the deployment is HS256.
- New password hashes use >=600,000 PBKDF2-HMAC-SHA256 iterations; legacy hashes still verify.

---

## Section B — Internal target and SSRF privilege separation

### Files
- `backend/app/core/auth.py`
- `backend/app/core/ssrf_protector.py`
- `backend/app/api/tools.py`
- scan/asset authorization call sites
- SSRF/adversarial tests

### Required fixes
1. Separate private-network authorization from loopback/link-local/metadata/reserved destinations.
2. `scan:internal` may permit explicitly authorized RFC1918/private targets, but must not implicitly permit loopback, link-local, multicast, reserved, or cloud metadata endpoints.
3. If exceptional metadata/loopback capability is ever supported, it must use a separate explicit scope and dedicated audit trail; default implementation remains deny.
4. Preserve DNS rebinding protections and selected-destination pinning.

### Acceptance tests
- `scan:internal` permits an authorized RFC1918 target.
- The same principal is denied `127.0.0.1`, `::1`, `169.254.169.254`, link-local IPv6, multicast, and reserved ranges.
- Repeater cannot reach those destinations through redirect hops.

---

## Section C — Scan-owned process lifecycle isolation

### Files
- `backend/app/core/process_supervisor.py`
- `backend/app/core/binary_resolver.py` / adapter execution boundary only if needed for context propagation
- `backend/app/core/orchestrator.py`
- `tests/security/test_process_launch_boundary.py`
- new process isolation assurance tests

### Required fixes
1. Replace global cancellation semantics with scan/execution-context ownership.
2. Every child PID must be associated with exactly one execution context.
3. Cancelling scan A may terminate only processes owned by A.
4. Global shutdown may still terminate all processes through an explicit supervisor-wide operation.
5. Timeouts remain process-tree scoped and bounded.

### Acceptance tests
- Two simulated concurrent scans register distinct processes; cancelling A cannot kill B.
- Timeout for one execution does not touch another execution context.
- Explicit global shutdown still cleans all process trees.

---

## Section D — Evidence truth and telemetry state

### Files
- `backend/app/api/scans.py`
- `backend/app/core/models.py` if a NOT_EXECUTED/UNKNOWN status is needed
- relevant engines/adapters only if execution records are incomplete
- telemetry/acceptance tests

### Required fixes
1. Never infer `SAFE` from absence of findings.
2. Never populate `tools_executed` unless authoritative execution evidence exists.
3. Endpoint test records must represent one of: executed-safe, finding, partial, failed, blocked, timed-out, cancelled, or not-executed/unknown.
4. Remove generic telemetry synthesis that claims CSRF, injection, Nuclei, crawler, or other checks ran when execution records do not prove it.
5. Coverage state must degrade or explicitly say not assessed when execution evidence is absent.

### Acceptance tests
- Endpoint with no execution record produces no fabricated SAFE checks.
- A successful zero-findings execution may produce SAFE only when a corresponding authoritative execution record exists.
- Degraded tool states cannot be overwritten by findings or generated dossier data.

---

## Section E — Repeater evidence integrity and bounded I/O

### Files
- `backend/app/api/tools.py`
- Repeater tests/security tests

### Required fixes
1. Never synthesize `TLSv1.3` or any TLS property when telemetry is unavailable.
2. Represent unavailable TLS metadata as `None`/unknown.
3. Stream response bodies with a hard byte ceiling before full allocation.
4. Preserve sanitization and bounded output semantics.
5. Continue to use validated-target transport with proxy bypass and redirect policy.

### Acceptance tests
- Missing TLS metadata remains unknown.
- A response larger than the limit is stopped/truncated while streaming; the full payload is never buffered.
- Secret sanitization remains intact.

---

## Section F — Application HTTP hardening and local bind defaults

### Files
- `backend/app/main.py`
- `run_platform.py`
- frontend assets if CSP requires removal of inline handlers
- API/security-header tests

### Required fixes
1. Standalone launcher defaults to loopback (`127.0.0.1`), not all interfaces.
2. Public binding requires explicit `HOST` configuration.
3. Remove obsolete security headers where they provide no protection.
4. Tighten CSP to actual frontend dependencies. Eliminate unnecessary third-party script/font origins and reduce/remove `unsafe-inline` where feasible without breaking the UI.
5. Validate/bound caller-supplied correlation IDs before logging and reflection.

### Acceptance tests
- Default host is loopback.
- Invalid/oversized correlation IDs are replaced/rejected safely.
- CSP contains only required sources.

---

## Section G — Deployment, queue, egress and reproducibility

### Files
- `docker-compose.yml`
- `Dockerfile`
- `docs/DOCKER_COMPOSE_DEPLOYMENT.md`
- Contract 01 / assurance matrix where claims require qualification
- deployment/container tests

### Required fixes
1. Make the external-process egress boundary explicit: the repository must fail closed or clearly require and verify an external egress policy rather than imply that a named bridge is an allowlist.
2. Add Redis authentication for the enterprise topology and use authenticated queue URLs.
3. Avoid mutable application image `latest` as the authoritative production deployment reference.
4. Pin base images by digest when an authoritative digest is available and tracked.
5. Preserve non-root/read-only/cap-drop/no-new-privileges/noexec hardening.
6. Production documentation must state exactly which controls are application-enforced versus infrastructure-enforced.

### Acceptance tests
- Enterprise configuration fails closed when required queue authentication/egress policy configuration is absent.
- Container hardening smoke tests remain green.

---

## Section H — CI, repository governance and documentation truth

### Files
- `.github/workflows/contract-verification.yml` (retained for this closure; LocalCI migration explicitly deferred)
- `README.md`
- version/contract docs
- assurance matrix and traceability docs

### Required fixes
1. README must match the current 26-tool architecture and current contract set.
2. Remove hard-coded stale test-count claims; use verifiable/current evidence wording.
3. Quickstart must use the hash-locked dependency installation path.
4. Python support claims must match what CI actually verifies; either test all claimed versions or narrow the claim.
5. Document managed-tool fail-closed/fallback behavior accurately per tool class.
6. Document localhost default binding.
7. Repository governance requirement: required pre-merge CI/checks must be documented. If branch protection cannot be configured by code, record it as an explicit repository-admin acceptance prerequisite rather than falsely claiming enforcement.

### Acceptance tests
- Documentation contract-consistency tests fail on stale fleet/test/runtime claims where practical.

---

## Section I — Final adversarial assurance and acceptance

### Files
- `tests/security/*`
- `tests/test_acceptance_scenarios.py`
- `docs/SECURITY_INVARIANT_TRACEABILITY.md`
- `docs/TOOL_ASSURANCE_MATRIX.md`
- final closure report

### Required proof
1. Full repository regression passes.
2. Focused security assurance for every finding passes.
3. Production image hardening job passes.
4. No finding is marked fixed solely by inspection; every one has executable regression evidence or an explicitly documented infrastructure prerequisite.
5. Traceability maps each closed audit finding to implementation and test evidence.

## Final decision rule

`ACCEPTED` is permitted only when all software-enforceable findings are closed and all infrastructure-only controls are explicitly identified as deployment prerequisites with fail-closed configuration where technically possible. Otherwise the release remains `REWORK / IN PROGRESS`.
