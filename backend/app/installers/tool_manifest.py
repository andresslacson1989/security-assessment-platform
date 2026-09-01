"""
Contract 01 §7, Contract 03 §2 & Contract 08 §4:
Authoritative Pinned Tool Version Manifest & Cryptographic SHA-256 Checksum Registry.
Ensures tool supply-chain integrity, preventing unpinned or tampered binary execution.
"""

from __future__ import annotations
import hashlib
from typing import Dict, Optional, Any, Tuple


# Authoritative Pinned Tool Manifest with Pinned Release Tags & Canonical SHA-256 Checksums
PINNED_TOOL_MANIFEST: Dict[str, Dict[str, Any]] = {
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        "pinned_version": "v3.2.0",
        "category": "Web DAST",
        "sha256_checksums": {
            "windows_amd64": "a927ea4b32f7d928700e8e61869b0d949d287d49d7ec9db3b22938f9eb103ba3",
            "linux_amd64": "8351b05772f37268fd172476de3f0c831ca9d9b9b1a6c64bacd38ef055e5d052",
            "linux_arm64": "57886fcfd9b15548adbfbc0816b18db5aa9bd0b9b72d5183a55ccac586feeaa5",
            "darwin_amd64": "407437c4cbf1bffc040e5c03c375c98e2d9b48c33e054f0e0798656706d3574f",
            "darwin_arm64": "1970bd8164fbef8c0368f559bf7d36dced65442e708ae2a476ae8ce047fadd5c",
        }
    },
    "ffuf": {
        "repo": "ffuf/ffuf",
        "pinned_version": "v2.1.0",
        "category": "Web DAST",
        "sha256_checksums": {
            "windows_amd64": "c0aec0289f1963cfc38a204f9ebe97712441c670fa7d7aad145cf87b15f038d4",
            "linux_amd64": "fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5",
            "linux_arm64": "6ae920d09d5202762fca21967a460c6fb88135bdfa806bee4d3d2c430dcedeea",
            "darwin_amd64": "d2d8a561f166d34d60d90f2f9b0a7ebe1414c0836549a1292e8da3206ac8781d",
            "darwin_arm64": "df1fdfbdc7ab6abb54cdf212452d585121bf291512649cf36c43a18d849f960e",
        }
    },
    "gitleaks": {
        "repo": "gitleaks/gitleaks",
        "pinned_version": "v8.18.2",
        "category": "Code SAST",
        "sha256_checksums": {
            "windows_amd64": "aa19543417c668b15e89b3357413099d81a75029a8ebbaec5034b7c8cc33c7e5",
            "linux_amd64": "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee",
            "linux_arm64": "4df25683f95b9e1dbb8cc71dac74d10067b8aba221e7f991e01cafa05bcbd030",
            "darwin_amd64": "b2dc4f853128062856273d422e2f29791a036641c1655feb83192078970fbfc0",
            "darwin_arm64": "7be53fa77d7ec10cb8a7085d6ebcf375d55dd4c71f2cf6e7e6bf11554847a095",
        }
    },
    "trivy": {
        "repo": "aquasecurity/trivy",
        "pinned_version": "v0.50.0",
        "category": "Infra IaC / Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "7ef999da89cc79aa9369d714cb9fdf3c32ef093a1f8d48e35a111a43a059f3d9",
            "linux_amd64": "1ff1e6d2bc1050a4da61706f30a91176b6ef0aa0fefca23a63ec592ff3320f69",
            "linux_arm64": "b535d21469e38d4f40f09ce988f57273cae1823eb5d7426bc1c4228fe00bca80",
            "darwin_amd64": "5cbef468bfbdf8a3c8e54737d2f9d854ef24cf74f7622c4f1c1f5165bb057632",
            "darwin_arm64": "1adceeb01a2f641fb00c0f83652ee995726fa45d62551cf1639d675aa97e20ec",
        }
    },
    "subfinder": {
        "repo": "projectdiscovery/subfinder",
        "pinned_version": "v2.6.5",
        "category": "Network EASM",
        "sha256_checksums": {
            "windows_amd64": "11c2a40a822546e0a8373b201c3fbccbc693b80c2189e12bf84324cd0be701d9",
            "linux_amd64": "19320e575c4fb422b1d2f9e4800b624eb5b5215e526db506570cb73dd2de5907",
        }
    },
    "httpx": {
        "repo": "projectdiscovery/httpx",
        "pinned_version": "v1.6.0",
        "category": "Network EASM",
        "sha256_checksums": {
            "windows_amd64": "52c3721a905f04d88efd0c66321fe1b03c64182e55da0d7c0ddcb2f92f479bb6",
            "linux_amd64": "a209fbf6eb95cdfb3be9a90a1a57463c6dd1879a56ca32bb4a39cc55d9b0754d",
        }
    },
    "katana": {
        "repo": "projectdiscovery/katana",
        "pinned_version": "v1.0.5",
        "category": "Web DAST",
        "sha256_checksums": {
            "windows_amd64": "4ba8e8a926dd5ca7b84462544a87ea9711ca06c7c28b131e7dae0d64d145b511",
            "linux_amd64": "d50ba599822701628396659a2b2bc7dc074eed23374c3e7c1794355cd4852f83",
            "linux_arm64": "e9fa87ef114ab8afde2f1f77ce357d62ba3d68091a46f550f32358918162d0aa",
        }
    },
    "syft": {
        "repo": "anchore/syft",
        "pinned_version": "v1.0.1",
        "category": "Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "95bc151e3a713a31f7ae7bfacbe0bda8c8d8e08e390038b0c2fc7220c1b9c49c",
            "linux_amd64": "420f90e57def27745e414efcb7a41384b2ccdccafca87c327096ca44621ab0ce",
            "linux_arm64": "c8582aa0e1c92c84c4a751c739ac3d7ca48c88a54b5d1b884d0629d7df72a6f9",
            "darwin_amd64": "3730868e23a65c0c2b94bd1d3c7ce608176aa98b631bf98249f04bec1a035b12",
            "darwin_arm64": "5dc061290afb7e8249dc590fcf4a7e15966346e73948415559855e1154fc0f42",
        }
    },
    "grype": {
        "repo": "anchore/grype",
        "pinned_version": "v0.74.0",
        "category": "Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "0088cb8969c893ae3ee9ba018e1ff8639f17a11a63c2250ad3f4c6dd48fe1d31",
            "linux_amd64": "7645f114e46cabb989254ec8ec34107240382a4b0626d940aa91a835177fbaf3",
            "linux_arm64": "754edfce7cdaa28849f997c9959879b21f753c382066af7c31ef238353558ba9",
            "darwin_amd64": "4c26b9047407f3743f7cfc025613aebcda4fee2c2befac4800f3c560bfbbb4cb",
            "darwin_arm64": "540e72006397995440e134641c05ce16f19538ad1e44cc2cabb3be091b763acf",
        }
    },
    "osv_scanner": {
        "repo": "google/osv-scanner",
        "pinned_version": "v1.7.0",
        "category": "Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "cd85bb140c2406e91f365947f1d3e30b942b2450f3e643cef9a6b1a6c87e6eb0",
            "linux_amd64": "3baa59720f92a37a90b23317d51dcd0a8eb11e612d3218e00859b36bfa2f84bc",
            "linux_arm64": "9ac3f0dc3f0fbfae5fc9e8e00d46906e08e5e85f88c5e79950d331d0f139a5c5",
            "darwin_amd64": "db94288f80a29742e98f0c7e520fae411e16f5c2a251f5bf12d8a30a91fd6bdd",
            "darwin_arm64": "b814f74155a9bc30794589f74c8fe3ea23c2e50290a437dc530ca5bc90eb5049",
        }
    },
    "dockle": {
        "repo": "goodwithtech/dockle",
        "pinned_version": "v0.4.14",
        "category": "Infra IaC",
        "sha256_checksums": {
            "linux_amd64": "a7eb7f10c6c3f7bf7209baf48d7b51dec0771aacda1f4773891def77b555e097",
            "linux_arm64": "2ab0fbf42fdbbb1532958244a8c7832f8aeabee27d1e3a545ffdfcff9b0ef332",
            "darwin_amd64": "23d9994f96e5d284fdc573c45c48080b02ca27ac0bd5326bd081cb7548b04837",
            "darwin_arm64": "417f3f9c20f6465c3973d10ee43e1a04fe5ed2338ff989b81b638c87ad9c922e",
        }
    },
}


def calculate_sha256(data: bytes) -> str:
    """Calculates standard SHA-256 hexadecimal digest of raw bytes."""
    return hashlib.sha256(data).hexdigest().lower()


def verify_download_integrity(
    tool_name: str,
    data: bytes,
    expected_sha256: Optional[str] = None,
    platform_key: Optional[str] = None,
) -> Tuple[bool, str, Optional[str]]:
    """
    Verifies the cryptographic integrity of a downloaded tool release archive.
    Returns (is_valid, actual_sha256, error_message).
    Never permits silent bypass on omitted, missing, or mismatched digests.
    """
    actual_hash = calculate_sha256(data)
    manifest_entry = PINNED_TOOL_MANIFEST.get(tool_name)
    if not manifest_entry:
        return False, actual_hash, f"Tool '{tool_name}' is not registered in the authoritative pinned manifest."

    expected = expected_sha256
    if not expected and platform_key:
        checksums = manifest_entry.get("sha256_checksums", {})
        expected = checksums.get(platform_key)

    if not expected:
        # Look up if any matching checksum exists in manifest
        checksums = manifest_entry.get("sha256_checksums", {})
        if len(checksums) == 1:
            expected = next(iter(checksums.values()))

    if not expected:
        return False, actual_hash, f"No authoritative SHA-256 digest is registered for tool '{tool_name}'. Installation rejected."

    if expected.strip().lower() != actual_hash:
        return (
            False,
            actual_hash,
            f"Cryptographic SHA-256 checksum mismatch for '{tool_name}'! Expected '{expected.strip().lower()}', computed '{actual_hash}'."
        )

    return True, actual_hash, None
