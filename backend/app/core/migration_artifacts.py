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
    10: {"sqlite": "tenant-bound process ownership and immutable recovery evidence", "postgresql": "tenant-bound process ownership and immutable recovery evidence"},
}
FORWARD_APPLY_SOURCE_SHA256 = {
    1: {"sqlite": "sha256:9148b33df6533537fc92370bbf10f760d53861b390dee2ffc30a757b40588b9c", "postgresql": "sha256:9c92c199ec6c75345e1eb75613828e464676ac2170dd1de0fa52873a9fd40dea"},
    2: {"sqlite": "sha256:d323dacc71e9d9bbd223285264d4d0e9dc416d0c78c5ff58adc45bf21022a4cb", "postgresql": "sha256:45dc5b71a4b3d2cff68be871894a64cdbf9a57b36123390734e43b2553a5d471"},
    3: {"sqlite": "sha256:5aac06d32fcc8c509824ea01ffdc1dcdfc94fb5d24983da2ec010af5edeccf5e", "postgresql": "sha256:614e2588d1989ff60f3b07e1993b69c3f59bb618168587126913be02b6f41d95"},
    4: {"sqlite": "sha256:616e0d21bd28dba769a205c813989e3c80ecb91493cff011632624f259c30d8f", "postgresql": "sha256:9d90fa995c14b4a61e0e0a29876ddb661193d0b8960b6a06f4516ab145c9288e"},
    5: {"sqlite": "sha256:d9d6f4c87c5d6c3a554468c15a72f233902164e85a4b5884f32686bd2f5fe105", "postgresql": "sha256:db7d8e6bbbd533b0b05a55aecd1eb9bb48b6baf9508de534aa5cf54fa3cf837a"},
    6: {"sqlite": "sha256:2c7d4e8cc50739928de7b58ef2f5dbb474cb1d85aa43619b56a335265d5d6739", "postgresql": "sha256:3482c767b48d4e548c4140da5f91c14486db0dee07d2896494ba40ec31d740eb"},
    7: {"sqlite": "sha256:c692577ab2281fc5d297bb9acc565d7a5f19271e750987b5958600fd77a20c10", "postgresql": "sha256:7cd44e73bd9cbe126543eaa57db6aa555b0fd336c4b979f99893dd9169b10a37"},
    8: {"sqlite": "sha256:8094728b1fc74c186d05d2bcd7353394c72c08e8d9961ee4a48b90409d191a8b", "postgresql": "sha256:739edce913385076cc6bb235ebc114770f798ab80ea683abc673f50a969da815"},
    9: {"sqlite": "sha256:e37121fc5e542424bab1251dc7f2e1bf22fb87f0a14565030636013f82f19b1f", "postgresql": "sha256:130e8b89041475ceda2c8a3ad02fb3f23d19c4074275999cc012cce73a9599a7"},
    10: {"sqlite": "sha256:352f51ff1f3fdb6c8453dce8bed59e5734736a5eb9792a85a5f31ec9a4154632", "postgresql": "sha256:ede3c088ddbe938a43d79416bd83b5546fe14bc7df818624de00f3eb56a8ea49"},
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
    "_verify_migration_v10_postconditions": "sha256:0c9dbfd369deee0e3240845793bb61be9bc8e66ac9eeaf2e9612e1dcc00c52f7",
}
