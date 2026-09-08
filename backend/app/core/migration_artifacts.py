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
    11: {"sqlite": "tenant-bound scan authorization parent, operations, and fleet snapshot", "postgresql": "tenant-bound scan authorization parent, operations, and fleet snapshot"},
    12: {"sqlite": "parent approval, child execution links, and worker generation", "postgresql": "parent approval, child execution links, and worker generation"},
    13: {"sqlite": "parent-scoped scan operation identity and canonical request material", "postgresql": "parent-scoped scan operation identity and canonical request material"},
}
FORWARD_APPLY_SOURCE_SHA256 = {
    1: {"sqlite": "sha256:8a0778721d6be2da6acb4c0c3324bff2fd93d81be008e5855d0ef7eae047b8e0", "postgresql": "sha256:cad1976d162f7b2feb70c8c3621afd36f96841bca0280b13e9e891af33de1cef"},
    2: {"sqlite": "sha256:5140808ebabe415c2b8eed51cf6a96153aa0f9c39dd23086424f4f364bc13ff4", "postgresql": "sha256:692475db28925fb483da0e49a2024ffaa4978dcbea5c6f31b33f56ab1b416166"},
    3: {"sqlite": "sha256:32d694cc7c3007223e837fe6709f6bf7a6890c81b7fafccda7c23e918378d8df", "postgresql": "sha256:90b6427dfd7099c68efdb2e7c870c5be81152923869367028601962ce728d87b"},
    4: {"sqlite": "sha256:62516993eb967c06d07778a14abeb5935f1da3e78cf5753b2b51247495642231", "postgresql": "sha256:796f69cdc62b1d9257f4339ea085167ec8cad3eff9c7b4dc3c140e92b93496b8"},
    5: {"sqlite": "sha256:31d6bd391cdf79374c65117b40d8a3eaf23925f91e353bff5b3b4f6da9176c68", "postgresql": "sha256:2f4ff41705201a7b70abc6c65b7d74695bb090a22159f696b70162cc2eb59f7d"},
    6: {"sqlite": "sha256:756480f8c46c3dc540a49a7e4d1fb72ad4e7aba7048a8077c246e2d7b5d18ec3", "postgresql": "sha256:784cf5483370f2e690b78ddbf46a8165a65d8eb5f60a28c619eafeb5e15aae56"},
    7: {"sqlite": "sha256:4e653211c3bb615f8455a04aca91fc992a104f890226a3a3f10473765a00e179", "postgresql": "sha256:49414cf849a465ebab6de20e90efb7f2b75f1f65eb0e46b86c91345bf9a1034e"},
    8: {"sqlite": "sha256:cc97230c6f967c521e29ff91d51976e4a3185f17dee7e3d86b27bf71ebbacb0e", "postgresql": "sha256:b061ff07680d1c2efe73badf179aa6ec6f54253548f4f116a6219cc4f3076844"},
    9: {"sqlite": "sha256:acd7a834e2e33fe0d8c67ae9df0e7afbfc73a2d0e771beec295d2532667f0fb0", "postgresql": "sha256:ff183bc0ff4fbd0f1c8eeaa29e6e0602e3b91ed51779e72dcb1c5b89e20dbaee"},
    10: {"sqlite": "sha256:aed28dda074a4d02db12982896288fd5743cc06010b38be4671663e20f3acbc8", "postgresql": "sha256:a01bb87d6de0ce935f771f39966328296e562d1cd6169cf4e7f0fe02f151e6ea"},
    11: {"sqlite": "sha256:f98b27aa80d9829db869f024f1dc0a4ece591993c5b464f91fb786a791dd68ea", "postgresql": "sha256:fc097d6b87ba2bcb3af09a0c118916dca23b6d4916ead9f5976b39fe94b9da8e"},
    12: {"sqlite": "sha256:066ae684b0dc8450f195f35265b580f3a2f1f9ad7b595461f1dabcb45cb33913", "postgresql": "sha256:6485aa439c8a7cf17d5673a075295ff85208957ec1a94ec47b10b442489e476b"},
    13: {"sqlite": "sha256:820f109dbe3e626363e475a16a0caa3fac638fa4e7b15139976d328a303e4334", "postgresql": "sha256:f86fbbb9e9ca9fb84f7a5f102251b26ef7b6df28a0336f011ed64b257cb8ca90"},
}

# Migration ledger checksums incorporate the verifier artifact that was
# approved when each migration identity was published.  Keep this map
# immutable when a verifier receives a narrowly scoped compatibility fix;
# changing it would make existing success-ledger checksums unverifiable.
MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256 = {
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
    "_verify_migration_v11_postconditions": "sha256:0a003056bb9f0e8146d5a77bcaee3217a68480ad61ecc840f3c7c63cbb2d9a37",
    "_verify_migration_v12_postconditions": "sha256:0ea8bd639bab55719af06ce499a27cc7a8758a96a495eff7f422f5db07652cfe",
    "_verify_migration_v13_postconditions": "sha256:43de748c65e83754eb85910846957ca3b1ef7c9f74b27aa7606376f22e54f840",
}

# This is the current implementation identity used by live authoritative
# schema verification.  It is intentionally separate from the historical
# checksum material above so a proven verifier correction cannot invalidate
# existing migration-ledger identities.
POSTCONDITION_SOURCE_SHA256 = {
    "_verify_migration_v1_postconditions": "sha256:d73742acf78163c4bf6647db7250016d73ca397a541b5bfdd4eae7e3d0db04a9",
    "_verify_migration_v2_postconditions": "sha256:6adf5f0d0145218249381d84c8981d5eb189dd12d80495696ab68cfa3c178d88",
    "_verify_migration_v3_postconditions": "sha256:1b88df9388f8b16288771f432b249265bdf52124ea9eef5cd05cec50d1da4b8a",
    "_verify_migration_v4_postconditions": "sha256:87d0466913eee934c6a398cfbdc7299be47a5b384ec40f986891bea4896538d2",
    "_verify_migration_v5_postconditions": "sha256:4be32c13dc44103de82f61eb3cbe1fcee13008ff70b28c2ad4c21598ffdc5049",
    "_verify_migration_v6_postconditions": "sha256:b5e03446462e26b5eba0a4d6fb9c40a9f6f0581c3629d7a84e52350740f57c49",
    "_verify_migration_v7_postconditions": "sha256:acb4d1fe5a68075271e719e48ee98989ef357de4af73c389088ea3df6ae5465a",
    "_verify_migration_v8_postconditions": "sha256:0b7993600559646c79dc2d56bdbf4ab6c9b1154495767f02c4269b4b98e873fd",
    "_verify_migration_v9_postconditions": "sha256:a887d95175bda9cf1a5b7b49c223e1f3880d1d0cd19219a9091a62333fcde03e",
    "_verify_migration_v10_postconditions": "sha256:f7c6b70bc95fe5ee2bb1c1062454a8b4db5121fa483926794c1708b06c211ae8",
    "_verify_migration_v11_postconditions": "sha256:371741f9a54764ad5d7b7293489c6ceb6d8827d9ba4e177410bae73aa99194f0",
    "_verify_migration_v12_postconditions": "sha256:0abd928081cdb9bc79056ab97f28d9d095c44450ab1d34ae0a0a13b96fa1e005",
    "_verify_migration_v13_postconditions": "sha256:a32915d2520b4add71e3e756b03c87ff4dbcaffbd7a47d80fabee42dec078e9e",
}
