# Contributing to CyberAssess

Thank you for your interest in contributing to CyberAssess. Please read this guide carefully to understand our contribution workflow, security invariants, and code quality expectations.

---

## 1. Development Principles & Invariants

CyberAssess is built on formal security contracts. Contributions must adhere to the core development model:

```text
CONTRACT
    ↓
IMPLEMENTATION
    ↓
AUTHORITATIVE STATE
    ↓
REAL EXECUTION
    ↓
OBSERVABLE RESULT
    ↓
ADVERSARIAL PROOF
    ↓
TRACEABILITY
```

### Non-Negotiable Invariants:
1. **Never Assume — Verify Truth**: Every state claim (`SAFE`, `VERIFIED`, `EXECUTED`) must be backed by concrete execution evidence. Absent evidence requires degraded states (`NOT_EXECUTED_PREREQUISITE_MISSING`, `UNKNOWN`, `BLOCKED`, `FAILED`).
2. **Preserve Existing Security Controls**: Never introduce `verify=False`, `shell=True`, `trust_env=True`, `0.0.0.0` port exposures in production, or wildcard authorization.
3. **Multi-Tenant Isolation**: Every database query on shared entities must filter on `organization_id`.
4. **Least-Privilege Scoping**: Wildcard `["*"]` is reserved exclusively for system administrators (`PrincipalType.SYSTEM_PRINCIPAL`).

---

## 2. Contribution Workflow

1. **Fork or Branch**:
   - Create a descriptive topic branch off `main` (e.g. `feat/new-security-check` or `fix/ssrf-ipv6-bracket-parsing`).
   - Do not commit directly to `main`.

2. **Implement Changes**:
   - Write clean, idiomatic Python conforming to PEP 8.
   - Include type annotations for all function parameters and return types.
   - Follow asynchronous best practices (avoid blocking synchronous I/O in async loops).

3. **Update Contracts & Traceability**:
   - If changing an API endpoint, data schema, or tool adapter, update the relevant contract in `contracts/` and `docs/contracts/`.
   - Update `docs/SECURITY_INVARIANT_TRACEABILITY.md` if modifying any security control.

4. **Add Tests**:
   - Every bug fix or feature must include automated tests.
   - Security-sensitive changes (auth, SSRF, process termination, egress) MUST include an adversarial test under `tests/security/`.

5. **Verify Locally**:
   Run the full test suite before opening a pull request:
   ```bash
   pytest tests/ -v
   ```
   All tests must pass cleanly.

---

## 3. Pull Request Guidelines

- Provide a clear summary of the change, the rationale, and the verification performed.
- Reference any relevant issues or contract sections.
- Ensure no credential material, secrets, or temporary logs are committed.
- Keep pull requests focused on a single change or cohesive invariant closure.
