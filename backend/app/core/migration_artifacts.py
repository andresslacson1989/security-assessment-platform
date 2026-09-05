"""Reviewed migration postcondition artifact fingerprints.

These values are intentionally maintained outside the registry construction
logic.  Changing a migration verifier requires an explicit artifact update and
registry review; runtime startup rejects an implementation that does not match
the approved fingerprint.
"""

from __future__ import annotations

POSTCONDITION_ARTIFACT_REVISION = "execution-postconditions-v2"
FORWARD_APPLY_ARTIFACT_REVISION = "execution-migration-apply-v1"
FORWARD_APPLY_MANIFESTS = {
    1: {"sqlite": "execution_runs tenant composite request binding", "postgresql": "execution_runs tenant composite request binding"},
    2: {"sqlite": "execution_runs legacy binding remediation", "postgresql": "execution_runs legacy binding remediation"},
    3: {"sqlite": "execution_runs immutable snapshot columns", "postgresql": "execution_runs immutable snapshot columns"},
    4: {"sqlite": "execution_runs decision composite binding", "postgresql": "execution_runs decision composite binding"},
    5: {"sqlite": "migration-owned duplicate parent cleanup", "postgresql": "migration-owned duplicate parent cleanup"},
    6: {"sqlite": "decision/request compatibility columns", "postgresql": "decision/request compatibility columns"},
    7: {"sqlite": "durable execution dispatch intent table", "postgresql": "durable execution dispatch intent table"},
    8: {"sqlite": "tenant-bound dispatch lease columns and foreign keys", "postgresql": "tenant-bound dispatch lease columns and foreign keys"},
    9: {"sqlite": "remove only the proven migration-owned duplicate parent index", "postgresql": "remove only the proven migration-owned duplicate parent index"},
}
FORWARD_APPLY_SOURCE_SHA256 = {
    1: {"sqlite": "sha256:b71e3c53bb026219ec718dde3641bf8179b439f2ea8c2e2cdb9a2d29c323ec3d", "postgresql": "sha256:5cd8e4809c898a96150c0cbe94a53a5600d1a38d931aa1200bd0c99d670ec459"},
    2: {"sqlite": "sha256:d8c1bd087ff055da6a5b464ff0e261a6050daa7bf3646ddf48119595099f90da", "postgresql": "sha256:b5bbc185499508295b99f04c70528c6d47b5e9fdb4d4ce61b24d01e6720fa405"},
    3: {"sqlite": "sha256:65bcc49081598767fec261caa65cbf93205e0a511fd7279959c947f5a32c1d48", "postgresql": "sha256:dbfe5972784c09e11bf095b87fe9b49f45038e96bf7a4b8892f29630274b7f70"},
    4: {"sqlite": "sha256:dc04d71709d0fae6773f74bcec8ee621b6d01490ff133e60daeef01b2ad555d1", "postgresql": "sha256:43633eacd0012e258b44132e4daa12ff81cc1043e61e6fa838acd257db267d8a"},
    5: {"sqlite": "sha256:e26d23b1dc541c7f6371ba702aece49ac71c17b2f66d7934bd75735cbdb72a0b", "postgresql": "sha256:c70c1c302e9d26285c851b95d3b7f7d15afa496b643d94cd4969aa5dded63bc4"},
    6: {"sqlite": "sha256:47061dcc51dcd6f4306c58fda94099dacb6d56c5835ffa7494b0340ad9bceff6", "postgresql": "sha256:3dbb563f71dcafd914d87d37139455fd40204fbd61524764d6dfc59f10ecc043"},
    7: {"sqlite": "sha256:81da3def8a69cfbccd4fc119663bf191fc48242dab0a160932105b0712863cf9", "postgresql": "sha256:75e6b812950e9977ea7bcc833b69a927b00cb57855d016ec11d697fe74e9db7f"},
    8: {"sqlite": "sha256:14b388f3857dee87052ff244a6f02f76ac8edcb8506e7d5f73a5cff88a0625ff", "postgresql": "sha256:f2d24da67a70ec17dd7e5bb196806e986c1889dd2bc6d9db0a17bb62080184fb"},
    9: {"sqlite": "sha256:13b228817842d62cd0e8fe2f0e357168e52762a73d444b1cc97b405e0f67d50d", "postgresql": "sha256:36c58745d765027509a67757135e3d68380eb90ab071898ccdd128a07d9e4e1e"},
}

POSTCONDITION_SOURCE_SHA256 = {
    "_verify_migration_v1_postconditions": "sha256:dc73db43009963308b455d1803967ea23257132a22443738beaaa10df6a47caf",
    "_verify_migration_v2_postconditions": "sha256:dc73db43009963308b455d1803967ea23257132a22443738beaaa10df6a47caf",
    "_verify_migration_v3_postconditions": "sha256:f374c82515fece05f9e59878df78d73dbf438dcf212ef2b737e934ccb487b8fd",
    "_verify_migration_v4_postconditions": "sha256:1c6679cd32bf744ba3043927449ff67a0690d6f52b9a4b02afb17d288621af7b",
    "_verify_migration_v5_postconditions": "sha256:dc73db43009963308b455d1803967ea23257132a22443738beaaa10df6a47caf",
    "_verify_migration_v6_postconditions": "sha256:637314d1088d968cc45d62cd8fb330f41e94b50b3777c7f31616d7894c6708f5",
    "_verify_migration_v7_postconditions": "sha256:acb4d1fe5a68075271e719e48ee98989ef357de4af73c389088ea3df6ae5465a",
    "_verify_migration_v8_postconditions": "sha256:fa3a73f138323ac681b97bfddfeabe3ed4eb8dd329c8d3f0df522264a6b39462",
    "_verify_migration_v9_postconditions": "sha256:a887d95175bda9cf1a5b7b49c223e1f3880d1d0cd19219a9091a62333fcde03e",
}
