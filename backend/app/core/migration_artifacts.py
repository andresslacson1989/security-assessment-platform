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
    1: {"sqlite": "sha256:01ed6a22623898cd9b4e6cfc17ab5b846b63176d9d07d5514998a48d3989260a", "postgresql": "sha256:4299beddc3f2f9a1a589e447b40cfd741bde7b8f906da9d9d50b53a72562bbfa"},
    2: {"sqlite": "sha256:e65a919602f96826aa76df53a81e551078f2c25c58f05ec0fe486142dea916fe", "postgresql": "sha256:fd30664838979c8afbcdbe59188bc7d7d1b9346d7e6a480da272e787637e4b4f"},
    3: {"sqlite": "sha256:e12cbc7cba6c4b3a9d45b2d0de305ebfe25aa881c8ad74ea0e5b5bf4b3e95196", "postgresql": "sha256:68961cae5b171aa5e24d8925955debfc3a04562f008c7870a38e6f2555428777"},
    4: {"sqlite": "sha256:acc24bdf6a293a658d447713c44a30cec2d25c432453f40d5f3870cc5f91bd06", "postgresql": "sha256:39984b5ad0ca47c31de25d215b8caae2d7068f70de613c35f189e31dd6f995bb"},
    5: {"sqlite": "sha256:21d634173e51aa8625a722bd9fec5041ad2036fee56c8f02f209c0abec31bde9", "postgresql": "sha256:aed35ffbadab4350ff858dee605af462fa2daa09ff4077dd2d54f222baf0a252"},
    6: {"sqlite": "sha256:268594886aa3ccc57a664439b192c6bc69c58aa0654fd1b72652a3ef04f23c18", "postgresql": "sha256:1957b10933ebaeb4fd0ab17048923324c19604c09e9d49a2f936c820bbeb2756"},
    7: {"sqlite": "sha256:3c7d463dc769b3dd9423d0b3ccceebccf8d2b189a36d3ba4dfe50ca7c144f3bb", "postgresql": "sha256:380b68df5b913841b6e56822ad00cbce5b1d171e36932be431339864e40d440b"},
    8: {"sqlite": "sha256:2357e4ea280aae0d3bb34c9c7253164eb3f511c0ce48cab3932d9e66d78cf25b", "postgresql": "sha256:95382d807705c8b303ae1874c84e1feb739e26a76c683c670abc61b932a20a6e"},
    9: {"sqlite": "sha256:ebc6937cc64d9439c9a2311f86f76d9acf2202e063cc44900ec434636ba133d1", "postgresql": "sha256:7502424f4defd452ddbbd565a46e0972bacb1fcbc9a80f51ea67eefe4dbcad77"},
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
