# Section A frozen migration probe

Status: **BLOCKED / UNVERIFIED**. This is evidence of the historical fixture
probe, not acceptance of the v12-to-v13 upgrade.

## Method

Each candidate was archived read-only from Git into a unique temporary
directory. The legacy application was started from that archive so its own
committed default database path was inside the temporary directory. No
production database or repository `data/cyberassess.db` path was used.

The probe command was equivalent to:

```text
git archive <commit>
python -c "from app.core.db import db_manager; print('initialized')"
```

The resulting temporary ledger was inspected with SQLite using:

```text
SELECT version FROM schema_migrations ORDER BY version;
```

## Candidate results

| Candidate | Result |
|---|---|
| `a1c4fc4` | blocked at legacy v1 forward-apply artifact verification |
| `1a09a18` | blocked at legacy v1 forward-apply artifact verification |
| `f13ee1f` | blocked at legacy v1 forward-apply artifact verification |
| `2dcb89f` | blocked at legacy v1 forward-apply artifact verification |
| `5230ecc` | initialized an isolated legacy ledger through v9; not a v12 fixture |
| `0ccc9fe` | initialized an isolated legacy ledger through v9; not a v12 fixture |
| `2e4b004` | initialized an isolated legacy ledger through v9; not a v12 fixture |
| `ca3261b` | initialized an isolated legacy ledger through v8; not a v12 fixture |
| `3713810` | failed during legacy v1 initialization; not a v12 fixture |
| `a95c752` | initialized an isolated legacy ledger through v8; not a v12 fixture |

The `5230ecc` result is not treated as upgrade evidence: it is only a
successful v9 legacy initialization, and it cannot satisfy the required
frozen v12 source/artifact pair.

## Consequence

No candidate tested so far provides a verified, genuine v12 database for the
current explicit v13 callable. The v12-to-v13 upgrade, restart idempotence,
and v13 artifact-tamper acceptance gates therefore remain unverified.

The correct next action is operator reconciliation or identification of a
historical commit whose complete pre-v13 registry, implementation, and
artifact set verifies internally. Historical verifiers and artifacts must not
be rewritten to make a fixture pass.
