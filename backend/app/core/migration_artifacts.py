"""Reviewed migration postcondition artifact fingerprints.

These values are intentionally maintained outside the registry construction
logic.  Changing a migration verifier requires an explicit artifact update and
registry review; runtime startup rejects an implementation that does not match
the approved fingerprint.
"""

from __future__ import annotations

POSTCONDITION_ARTIFACT_REVISION = "execution-postconditions-v2"

POSTCONDITION_SOURCE_SHA256 = {
    "_verify_migration_v1_postconditions": "sha256:dc73db43009963308b455d1803967ea23257132a22443738beaaa10df6a47caf",
    "_verify_migration_v2_postconditions": "sha256:dc73db43009963308b455d1803967ea23257132a22443738beaaa10df6a47caf",
    "_verify_migration_v3_postconditions": "sha256:f374c82515fece05f9e59878df78d73dbf438dcf212ef2b737e934ccb487b8fd",
    "_verify_migration_v4_postconditions": "sha256:1c6679cd32bf744ba3043927449ff67a0690d6f52b9a4b02afb17d288621af7b",
    "_verify_migration_v5_postconditions": "sha256:dc73db43009963308b455d1803967ea23257132a22443738beaaa10df6a47caf",
    "_verify_migration_v6_postconditions": "sha256:637314d1088d968cc45d62cd8fb330f41e94b50b3777c7f31616d7894c6708f5",
    "_verify_migration_v7_postconditions": "sha256:01fe9da8a8e2106ac2486b490e0fd60f8eccf7724e16c5707b2f8e3621aeafd4",
    "_verify_migration_v8_postconditions": "sha256:fa3a73f138323ac681b97bfddfeabe3ed4eb8dd329c8d3f0df522264a6b39462",
}
