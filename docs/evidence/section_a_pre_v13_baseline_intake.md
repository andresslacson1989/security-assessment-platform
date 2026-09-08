# Section A authoritative pre-v13 baseline intake

Status: **INPUT REQUIRED**. This document defines what an operator must supply
before the v12→v13 migration can be validated. It does not authorize migration
reconciliation or database mutation.

## Required baseline package

The package must identify one authoritative pre-v13 release and contain, or
provide reproducible access to, all of the following:

- signed release tag or immutable commit ID and its provenance;
- complete v1–v12 application source, including `db.py` and all migration
  callables;
- the matching migration registry and historical verifier implementations;
- matching SQLite and PostgreSQL apply artifacts, checksums, manifests, and
  artifact-revision values;
- the historical migration-event and migration-ledger schema;
- the expected v1–v12 schema-version vector and postcondition definitions;
- the backend/database policy used by that release;
- a disposable v12 fixture, or reproducible instructions that create one from
  the supplied source without using a production database;
- release integrity/provenance evidence and the maintainer/operator approval
  ticket identifying the baseline owner.

The package is incomplete if any artifact is only described by filename,
provided from a different commit, or cannot be reproduced and verified in an
isolated directory.

## Read-only intake validation

Before any database connection is opened, the operator should verify the
package manifest, immutable commit/tag, file list, file digests, backend
variants, and provenance signatures. Validation must fail closed on missing
files, duplicate identities, digest mismatch, unsupported backend, source/
artifact revision mismatch, or an absent v12 target declaration.

The validator must then run the supplied release source in a unique disposable
working directory with a disposable database path. It must record:

1. source commit/tag and package digest;
2. registry and verifier identities for v1–v12;
3. apply-artifact and manifest digests for each supported backend;
4. the resulting migration ledger and event identities;
5. schema version and postcondition results;
6. database path, process exit code, and timestamp.

No production path, including `data/cyberassess.db`, may be opened during
intake. A successful source startup is not sufficient by itself: every
v1–v12 identity and postcondition must match the supplied baseline manifest.

## Pre-mutation acceptance checklist

The operator must supply evidence for every item below before a migration test
may proceed:

- [ ] immutable release/tag/commit verified;
- [ ] complete v1–v12 source and registry verified;
- [ ] historical apply artifacts and checksums verified for the selected backend;
- [ ] historical verifier identities and provenance verified;
- [ ] disposable v12 fixture created without ledger deletion or fabricated rows;
- [ ] schema, ledger, and event vector independently reviewed;
- [ ] duplicate/orphan/cross-tenant preflight expectations defined;
- [ ] backup, dry-run, transaction, rollback, and postcondition procedures approved;
- [ ] operator identity and reconciliation ticket recorded.

Any unchecked item keeps the migration state **BLOCKED/UNVERIFIED**. No
default hashes, empty manifests, inferred historical values, or automatic
winner selection may be introduced.

## Required handoff

The operator should provide the baseline package location or immutable release
reference, its manifest/digest, validation logs, disposable fixture location,
backend selection, and approval ticket. Until that handoff is complete, the
repository remains limited to fresh-v13 and rollback evidence; no v12→v13
acceptance claim may be made.
