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
    1: {"sqlite": "sha256:efe0e41b2a6577088fd5250d96d03fabddda9ed8b7c7fc7c776c32806043da02", "postgresql": "sha256:9b5879a82fa6a21842f9eb053f7154133341009c8730b32495714845ea6fdb3b"},
    2: {"sqlite": "sha256:d88e8d072e0f5392e7e5546931c2e5b0a1700eea098f1889ae254537c0696b1f", "postgresql": "sha256:09fd7a2505c01ff5659570b0d731abf348a4cdcd5d9aa21a1c9598cc34545b22"},
    3: {"sqlite": "sha256:aafa95f1ca1ad3385720803277e83b92e3aa62ce8b6e5be86fdf348c8a345bcb", "postgresql": "sha256:0b16e431ac866f1eaa04351355c0320399958267c90ddb214c3a6ae385f5b4a4"},
    4: {"sqlite": "sha256:cd671465b60b0241308b55a67d03d9b74870d868a875071d049ac2270864cc6b", "postgresql": "sha256:d8d405fcefaf2102deae05afaa7b8ceee8d6dbd361b21389bbf499a27f6a5866"},
    5: {"sqlite": "sha256:2be97b45dbed297ae812f068468d661c65ae26130c926bab7f599e6308cc974a", "postgresql": "sha256:9631bf85d0879fae6a8cb1715c35877a595deebce5a080945f1588afd9276ef9"},
    6: {"sqlite": "sha256:95276ea45038d1981da0b453da192a49eed3e5bc5f261c7c3876b11fb9a40738", "postgresql": "sha256:1a59f362ca96e65921c3cd0b03bbe648ed4b227967f8269859c442ecee71477f"},
    7: {"sqlite": "sha256:4fbb0aee354a999e2dcbf21cb9e9911fcb47e309222fd232427c3f2ff967aa1d", "postgresql": "sha256:f8d888adac03c624409f65d51609337f297e5fca2638528b780fe4960b8563b2"},
    8: {"sqlite": "sha256:6a9321a33a3af3b4cd1350b6fb68bee570f4268e5479541c6b6250656ad89f7e", "postgresql": "sha256:c73057a361645525b0ebb39ebf446cd33492803ea2081c1cae07f62fc5368d1d"},
    9: {"sqlite": "sha256:3f235514ae70e0057e1c3d9550b8f0c0bffed1b353c2cef2e86c92e45d8dc970", "postgresql": "sha256:5d0433293f83f4469a981da2a6683033feb80dbca19c7b9fe9c031ea5564194c"},
    10: {"sqlite": "sha256:02226630ed9e13093a6780d5a1b197fc0c787b48ab0bb086f7d9f98fd2384214", "postgresql": "sha256:6264f2ef1bb13110326b999909546ab90744ec9e10959595ff64fc67424e8cd1"},
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
