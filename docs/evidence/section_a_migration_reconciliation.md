# Section A migration reconciliation specification

Status: **FORMALLY CLOSED AS A BLOCKER; v12→v13 remains UNVERIFIED**.

## Repository facts

The frozen-source probe in
`docs/evidence/section_a_frozen_migration_probe.md` used archived commits and
disposable database roots. No tested commit supplied an internally verified
v12 fixture. Several v12-era candidates fail their own committed v1
forward-apply artifact verifier; earlier candidates reach only v8 or v9.

This does not prove that every historical copy of CyberAssess is incompatible.
It proves only that the repository history tested here does not provide the
authoritative, reproducible v12 baseline required for acceptance.

## Required operator inputs

Before a v12→v13 upgrade can be accepted, an operator must supply:

1. An authoritative release commit or signed tag for the pre-v13 release.
2. The complete v1–v12 registry, implementation, artifact, checksum, and
   provenance ledger belonging to that release.
3. An approved migration baseline identifying the expected schema and data
   invariants at v12.
4. A maintainer-approved reconciliation ticket and operator identity.

Historical artifacts must not be regenerated or rewritten to make a fixture
pass.

## Fail-closed runtime policy

Normal startup must reject unknown migration versions, ledger gaps, identity or
artifact drift, incomplete canonical request material, and unresolved
reconciliation attempts before any schema mutation. It must never invent
manifest hashes, approval state, defaults, or a winner for duplicate,
orphaned, ambiguous, or cross-tenant rows.

Any future bounded maintenance path is separate from normal startup. It must
require backup, read-only inspection, dry-run output, an
operator-approved change manifest, a transaction boundary, rollback capability,
postcondition verification, tenant-scoped authorization, and an immutable audit
record. No destructive cleanup is authorized by this document.

## Inspection and future reconciliation process

The first step is a read-only report of schema version, migration ledger
identities, artifact/provenance mismatches, affected rows, and schema
postconditions. The repository currently documents this process rather than
inventing a new executable command.

Only after the operator supplies the required baseline may a bounded
reconciliation operation be designed and reviewed. It must be dry-run first,
must not select winners automatically, and must be executed only against an
explicitly selected disposable or production database under the approved
maintenance controls.

## Acceptance boundary

Fresh v13 initialization and transactional rollback are separately evidenced.
The genuine v12→v13 upgrade, restart idempotence, and historical tamper
verification are **not accepted** until the authoritative baseline is supplied
and independently verified. Section A therefore cannot advance to later
implementation sections on the current repository history alone.
