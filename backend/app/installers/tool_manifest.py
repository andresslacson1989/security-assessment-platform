"""
Contract 01 §7, Contract 03 §2 & Contract 08 §4:
Authoritative Pinned Tool Version Manifest & Cryptographic SHA-256 Checksum Registry.
Ensures tool supply-chain integrity, preventing unpinned or tampered binary execution.
"""

from __future__ import annotations
import hashlib
import re
from typing import Dict, Optional, Any, Tuple


# Authoritative Pinned Tool Manifest with Pinned Release Tags & Canonical SHA-256 Checksums
PINNED_TOOL_MANIFEST: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "tool_name": "nmap",
        "version": "7.95",
        "release_tag": "v7.95",
        "repo": "insecure-org/nmap",
        "pinned_version": "v7.95",
        "category": "Network Perimeter",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "package_manager": "OS package manager",
        "sha256_checksums": {},
        "asset_names": {},
        "integrity_note": "Raw release archive digest is delegated to the authenticated OS package manager.",
    },
    "nuclei": {
        "tool_name": "nuclei",
        "version": "3.2.0",
        "release_tag": "v3.2.0",
        "repo": "projectdiscovery/nuclei",
        "pinned_version": "v3.2.0",
        "category": "Web DAST",
        "sha256_checksums": {
            "windows_amd64": "a927ea4b32f7d928700e8e61869b0d949d287d49d7ec9db3b22938f9eb103ba3",
            "linux_amd64": "8351b05772f37268fd172476de3f0c831ca9d9b9b1a6c64bacd38ef055e5d052",
            "linux_arm64": "57886fcfd9b15548adbfbc0816b18db5aa9bd0b9b72d5183a55ccac586feeaa5",
            "darwin_amd64": "407437c4cbf1bffc040e5c03c375c98e2d9b48c33e054f0e0798656706d3574f",
            "darwin_arm64": "1970bd8164fbef8c0368f559bf7d36dced65442e708ae2a476ae8ce047fadd5c",
        },
        "asset_names": {
            "windows_amd64": "nuclei_3.2.0_windows_amd64.zip",
            "linux_amd64": "nuclei_3.2.0_linux_amd64.zip",
            "linux_arm64": "nuclei_3.2.0_linux_arm64.zip",
            "darwin_amd64": "nuclei_3.2.0_macOS_amd64.zip",
            "darwin_arm64": "nuclei_3.2.0_macOS_arm64.zip",
        }
    },
    "ffuf": {
        "tool_name": "ffuf",
        "version": "2.1.0",
        "release_tag": "v2.1.0",
        "repo": "ffuf/ffuf",
        "pinned_version": "v2.1.0",
        "category": "Web DAST",
        "sha256_checksums": {
            "windows_amd64": "c0aec0289f1963cfc38a204f9ebe97712441c670fa7d7aad145cf87b15f038d4",
            "linux_amd64": "fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5",
            "linux_arm64": "6ae920d09d5202762fca21967a460c6fb88135bdfa806bee4d3d2c430dcedeea",
            "darwin_amd64": "d2d8a561f166d34d60d90f2f9b0a7ebe1414c0836549a1292e8da3206ac8781d",
            "darwin_arm64": "df1fdfbdc7ab6abb54cdf212452d585121bf291512649cf36c43a18d849f960e",
        },
        "asset_names": {
            "windows_amd64": "ffuf_2.1.0_windows_amd64.zip",
            "linux_amd64": "ffuf_2.1.0_linux_amd64.tar.gz",
            "linux_arm64": "ffuf_2.1.0_linux_arm64.tar.gz",
            "darwin_amd64": "ffuf_2.1.0_macOS_amd64.tar.gz",
            "darwin_arm64": "ffuf_2.1.0_macOS_arm64.tar.gz",
        }
    },
    "gitleaks": {
        "tool_name": "gitleaks",
        "version": "8.18.2",
        "release_tag": "v8.18.2",
        "repo": "gitleaks/gitleaks",
        "pinned_version": "v8.18.2",
        "category": "Code SAST",
        "sha256_checksums": {
            "windows_amd64": "aa19543417c668b15e89b3357413099d81a75029a8ebbaec5034b7c8cc33c7e5",
            "linux_amd64": "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee",
            "linux_arm64": "4df25683f95b9e1dbb8cc71dac74d10067b8aba221e7f991e01cafa05bcbd030",
            "darwin_amd64": "b2dc4f853128062856273d422e2f29791a036641c1655feb83192078970fbfc0",
            "darwin_arm64": "7be53fa77d7ec10cb8a7085d6ebcf375d55dd4c71f2cf6e7e6bf11554847a095",
        },
        "asset_names": {
            "windows_amd64": "gitleaks_8.18.2_windows_x64.zip",
            "linux_amd64": "gitleaks_8.18.2_linux_x64.tar.gz",
            "linux_arm64": "gitleaks_8.18.2_linux_arm64.tar.gz",
            "darwin_amd64": "gitleaks_8.18.2_darwin_x64.tar.gz",
            "darwin_arm64": "gitleaks_8.18.2_darwin_arm64.tar.gz",
        }
    },
    "trivy": {
        "tool_name": "trivy",
        "version": "0.50.0",
        "release_tag": "v0.50.0",
        "repo": "aquasecurity/trivy",
        "pinned_version": "v0.50.0",
        "category": "Infra IaC / Supply Chain",
        "trust_mode": "SOURCE_BUILD_MODE",
        "source_build": True,
        "direct_release_artifact_available": False,
        "source_archive_url": "https://github.com/aquasecurity/trivy/archive/refs/tags/v0.50.0.tar.gz",
        "source_commit": "8ec3938e01a93855503e3400eae9831abbb5de4a",
        "build_toolchain": "go1.21.13",
        "sha256_checksums": {
            "source_archive": "16fa56d6c3549657baa49f1de8ffef5b6a976d7bf11d378d0f097189b70bae2b",
            "go_linux_amd64": "502fc16d5910562461e6a6631fb6377de2322aad7304bf2bcd23500ba9dab4a7",
            "go_linux_arm64": "2ca2d70dc9c84feef959eb31f2a5aac33eefd8c97fe48f1548886d737bffabd4",
        },
        "asset_names": {
            "source_archive": "trivy-0.50.0-source.tar.gz",
            "go_linux_amd64": "go1.21.13.linux-amd64.tar.gz",
            "go_linux_arm64": "go1.21.13.linux-arm64.tar.gz",
        },
    },
    # These tools are supported as diagnostic/manual or native-engine
    # integrations, but their contracts do not define immutable release
    # identities. Keep them explicit in the registry and fail closed rather
    # than treating an unpinned host installation as assured.
    "metasploit": {
        "tool_name": "metasploit",
        "version": "UNPINNED_MANUAL",
        "release_tag": "MANUAL",
        "repo": "rapid7/metasploit-framework",
        "category": "Exploit Verification",
        "trust_mode": "MANUAL_MODE",
        "sha256_checksums": {},
        "asset_names": {},
        "integrity_note": "Diagnostic-only manual installation; no immutable artifact identity is authorized.",
    },
    "sqlmap": {
        "tool_name": "sqlmap",
        "version": "UNPINNED_MANUAL",
        "release_tag": "MANUAL",
        "repo": "sqlmapproject/sqlmap",
        "category": "Web DAST",
        "trust_mode": "MANUAL_MODE",
        "sha256_checksums": {},
        "asset_names": {},
        "integrity_note": "Diagnostic-only manual installation; no immutable artifact identity is authorized.",
    },
    "amass": {
        "tool_name": "amass",
        "version": "UNPINNED_MANUAL",
        "release_tag": "MANUAL",
        "repo": "owasp-amass/amass",
        "category": "Network Perimeter",
        "trust_mode": "MANUAL_MODE",
        "sha256_checksums": {},
        "asset_names": {},
        "integrity_note": "Diagnostic-only manual installation; no immutable artifact identity is authorized.",
    },
    "hydra": {
        "tool_name": "hydra",
        "version": "UNPINNED_MANUAL",
        "release_tag": "MANUAL",
        "repo": "vanhauser-thc/thc-hydra",
        "category": "Authentication Resilience",
        "trust_mode": "MANUAL_MODE",
        "sha256_checksums": {},
        "asset_names": {},
        "integrity_note": "Diagnostic-only manual installation; no immutable artifact identity is authorized.",
    },
    "gtfobins": {
        "tool_name": "gtfobins",
        "version": "NATIVE_ENGINE",
        "release_tag": "NATIVE",
        "repo": "gtfobins/gtfobins.github.io",
        "category": "Host Privilege Escalation",
        "trust_mode": "NATIVE_ENGINE_MODE",
        "sha256_checksums": {},
        "asset_names": {},
        "integrity_note": "Native rule engine; no external executable artifact is installed.",
    },
    "subfinder": {
        "tool_name": "subfinder",
        "version": "2.6.5",
        "release_tag": "v2.6.5",
        "repo": "projectdiscovery/subfinder",
        "pinned_version": "v2.6.5",
        "category": "Network EASM",
        "sha256_checksums": {
            "windows_amd64": "11c2a40a822546e0a8373b201c3fbccbc693b80c2189e12bf84324cd0be701d9",
            "linux_amd64": "19320e575c4fb422b1d2f9e4800b624eb5b5215e526db506570cb73dd2de5907",
        },
        "asset_names": {
            "windows_amd64": "subfinder_2.6.5_windows_amd64.zip",
            "linux_amd64": "subfinder_2.6.5_linux_amd64.zip",
        }
    },
    "httpx": {
        "tool_name": "httpx",
        "version": "1.6.0",
        "release_tag": "v1.6.0",
        "repo": "projectdiscovery/httpx",
        "pinned_version": "v1.6.0",
        "category": "Network EASM",
        "sha256_checksums": {
            "windows_amd64": "52c3721a905f04d88efd0c66321fe1b03c64182e55da0d7c0ddcb2f92f479bb6",
            "linux_amd64": "a209fbf6eb95cdfb3be9a90a1a57463c6dd1879a56ca32bb4a39cc55d9b0754d",
        },
        "asset_names": {
            "windows_amd64": "httpx_1.6.0_windows_amd64.zip",
            "linux_amd64": "httpx_1.6.0_linux_amd64.zip",
        }
    },
    "katana": {
        "tool_name": "katana",
        "version": "1.0.5",
        "release_tag": "v1.0.5",
        "repo": "projectdiscovery/katana",
        "pinned_version": "v1.0.5",
        "category": "Web DAST",
        "sha256_checksums": {
            "windows_amd64": "4ba8e8a926dd5ca7b84462544a87ea9711ca06c7c28b131e7dae0d64d145b511",
            "linux_amd64": "d50ba599822701628396659a2b2bc7dc074eed23374c3e7c1794355cd4852f83",
            "linux_arm64": "e9fa87ef114ab8afde2f1f77ce357d62ba3d68091a46f550f32358918162d0aa",
        },
        "asset_names": {
            "windows_amd64": "katana_1.0.5_windows_amd64.zip",
            "linux_amd64": "katana_1.0.5_linux_amd64.zip",
            "linux_arm64": "katana_1.0.5_linux_arm64.zip",
        }
    },
    "syft": {
        "tool_name": "syft",
        "version": "1.0.1",
        "release_tag": "v1.0.1",
        "repo": "anchore/syft",
        "pinned_version": "v1.0.1",
        "category": "Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "95bc151e3a713a31f7ae7bfacbe0bda8c8d8e08e390038b0c2fc7220c1b9c49c",
            "linux_amd64": "420f90e57def27745e414efcb7a41384b2ccdccafca87c327096ca44621ab0ce",
            "linux_arm64": "c8582aa0e1c92c84c4a751c739ac3d7ca48c88a54b5d1b884d0629d7df72a6f9",
            "darwin_amd64": "3730868e23a65c0c2b94bd1d3c7ce608176aa98b631bf98249f04bec1a035b12",
            "darwin_arm64": "5dc061290afb7e8249dc590fcf4a7e15966346e73948415559855e1154fc0f42",
        },
        "asset_names": {
            "windows_amd64": "syft_1.0.1_windows_amd64.zip",
            "linux_amd64": "syft_1.0.1_linux_amd64.tar.gz",
            "linux_arm64": "syft_1.0.1_linux_arm64.tar.gz",
            "darwin_amd64": "syft_1.0.1_darwin_amd64.tar.gz",
            "darwin_arm64": "syft_1.0.1_darwin_arm64.tar.gz",
        }
    },
    "grype": {
        "tool_name": "grype",
        "version": "0.74.0",
        "release_tag": "v0.74.0",
        "repo": "anchore/grype",
        "pinned_version": "v0.74.0",
        "category": "Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "0088cb8969c893ae3ee9ba018e1ff8639f17a11a63c2250ad3f4c6dd48fe1d31",
            "linux_amd64": "7645f114e46cabb989254ec8ec34107240382a4b0626d940aa91a835177fbaf3",
            "linux_arm64": "754edfce7cdaa28849f997c9959879b21f753c382066af7c31ef238353558ba9",
            "darwin_amd64": "4c26b9047407f3743f7cfc025613aebcda4fee2c2befac4800f3c560bfbbb4cb",
            "darwin_arm64": "540e72006397995440e134641c05ce16f19538ad1e44cc2cabb3be091b763acf",
        },
        "asset_names": {
            "windows_amd64": "grype_0.74.0_windows_amd64.zip",
            "linux_amd64": "grype_0.74.0_linux_amd64.tar.gz",
            "linux_arm64": "grype_0.74.0_linux_arm64.tar.gz",
            "darwin_amd64": "grype_0.74.0_darwin_amd64.tar.gz",
            "darwin_arm64": "grype_0.74.0_darwin_arm64.tar.gz",
        }
    },
    "osv-scanner": {
        "tool_name": "osv-scanner",
        "version": "1.7.0",
        "release_tag": "v1.7.0",
        "repo": "google/osv-scanner",
        "pinned_version": "v1.7.0",
        "category": "Supply Chain",
        "sha256_checksums": {
            "windows_amd64": "cd85bb140c2406e91f365947f1d3e30b942b2450f3e643cef9a6b1a6c87e6eb0",
            "linux_amd64": "3baa59720f92a37a90b23317d51dcd0a8eb11e612d3218e00859b36bfa2f84bc",
            "linux_arm64": "9ac3f0dc3f0fbfae5fc9e8e00d46906e08e5e85f88c5e79950d331d0f139a5c5",
            "darwin_amd64": "db94288f80a29742e98f0c7e520fae411e16f5c2a251f5bf12d8a30a91fd6bdd",
            "darwin_arm64": "b814f74155a9bc30794589f74c8fe3ea23c2e50290a437dc530ca5bc90eb5049",
        },
        "asset_names": {
            "windows_amd64": "osv-scanner_windows_amd64.exe",
            "linux_amd64": "osv-scanner_linux_amd64",
            "linux_arm64": "osv-scanner_linux_arm64",
            "darwin_amd64": "osv-scanner_darwin_amd64",
            "darwin_arm64": "osv-scanner_darwin_arm64",
        }
    },
    "trufflehog": {
        "tool_name": "trufflehog",
        "version": "3.63.0",
        "release_tag": "v3.63.0",
        "repo": "trufflesecurity/trufflehog",
        "pinned_version": "v3.63.0",
        "category": "Code SAST",
        "sha256_checksums": {
            "windows_amd64": "3122ac287e3366d61603affe2f4a3658f72d848879af0de31c737f25eb97756f",
            "linux_amd64": "836cd48d5864a25194c2b6ed1b9dc8d68367a2ee2afb00655306b18359b3cc0d",
            "linux_arm64": "4e3da13e733abbc1a558946357621cc19269fb32ff540ff44a04c0a8e63d4234",
            "darwin_amd64": "7c32c3179dd16d76fb89f4699bc37177f5cfedeba19e692ce9b46c5dfad213b0",
            "darwin_arm64": "48b5b363318ac63b32e7047475a91371bc9a0a8da9caf88e69e0890ddffe0159",
        },
        "asset_names": {
            "windows_amd64": "trufflehog_3.63.0_windows_amd64.tar.gz",
            "linux_amd64": "trufflehog_3.63.0_linux_amd64.tar.gz",
            "linux_arm64": "trufflehog_3.63.0_linux_arm64.tar.gz",
            "darwin_amd64": "trufflehog_3.63.0_darwin_amd64.tar.gz",
            "darwin_arm64": "trufflehog_3.63.0_darwin_arm64.tar.gz",
        },
    },
    "kube-bench": {
        "tool_name": "kube-bench",
        "version": "0.7.0",
        "release_tag": "v0.7.0",
        "repo": "aquasecurity/kube-bench",
        "pinned_version": "v0.7.0",
        "category": "Cluster Posture",
        "sha256_checksums": {
            "linux_amd64": "e9ede7c6f3570cf8f4e81925cd2523fc9c3442fb8304477637f231c7b4647e7d",
            "linux_arm64": "53da250a3211d717378e6ef37ee541d2cd212953628b064f2f7e2ca8a5a7bb57",
            "darwin_amd64": "12837eed1e793c7b452911c676f6ef2d49f37eab48b263c983155d4067fccd5c",
            "darwin_arm64": "ccbe3240941ef18c8e692f00109d68abe5aa48b2a9b841dd916e31365409a3f2",
        },
        "asset_names": {
            "linux_amd64": "kube-bench_0.7.0_linux_amd64.tar.gz",
            "linux_arm64": "kube-bench_0.7.0_linux_arm64.tar.gz",
            "darwin_amd64": "kube-bench_0.7.0_darwin_amd64.tar.gz",
            "darwin_arm64": "kube-bench_0.7.0_darwin_arm64.tar.gz",
        },
    },
    "dockle": {
        "tool_name": "dockle",
        "version": "0.4.14",
        "release_tag": "v0.4.14",
        "repo": "goodwithtech/dockle",
        "pinned_version": "v0.4.14",
        "category": "Infra IaC",
        "sha256_checksums": {
            "linux_amd64": "a7eb7f10c6c3f7bf7209baf48d7b51dec0771aacda1f4773891def77b555e097",
            "linux_arm64": "2ab0fbf42fdbbb1532958244a8c7832f8aeabee27d1e3a545ffdfcff9b0ef332",
            "darwin_amd64": "23d9994f96e5d284fdc573c45c48080b02ca27ac0bd5326bd081cb7548b04837",
            "darwin_arm64": "417f3f9c20f6465c3973d10ee43e1a04fe5ed2338ff989b81b638c87ad9c922e",
        },
        "asset_names": {
            "linux_amd64": "dockle_0.4.14_Linux-64bit.tar.gz",
            "linux_arm64": "dockle_0.4.14_Linux-ARM64.tar.gz",
            "darwin_amd64": "dockle_0.4.14_macOS-64bit.tar.gz",
            "darwin_arm64": "dockle_0.4.14_macOS-ARM64.tar.gz",
        }
    },
    "retire": {
        "tool_name": "retire",
        "version": "4.4.3",
        "release_tag": "4.4.3",
        "repo": "npm:retire",
        "pinned_version": "4.4.3",
        "category": "Code SAST",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "npm_tarball": "1352bd6054d92d261b4d85dbfd75c4cee800f583573b5d9d0c45b56e3282c280",
        },
        "asset_names": {
            "npm_tarball": "retire-4.4.3.tgz",
        },
    },
    "sslyze": {
        "tool_name": "sslyze",
        "version": "5.2.0",
        "release_tag": "5.2.0",
        "repo": "PyPI:sslyze",
        "pinned_version": "5.2.0",
        "category": "Network & TLS",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "pypi_sdist": "15ecb471b251dfbd003ba81a57d36865a93f18b74c7e7883a00d8bbddd365e03",
        },
        "asset_names": {"pypi_sdist": "sslyze-5.2.0.tar.gz"},
    },
    "schemathesis": {
        "tool_name": "schemathesis",
        "version": "3.20.0",
        "release_tag": "3.20.0",
        "repo": "PyPI:schemathesis",
        "pinned_version": "3.20.0",
        "category": "API Security",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "pypi_wheel": "cc5480e0c60ad82dd5887fa596ff820d08e620239edacb648e6eb099b6a5d2b8",
            "pypi_sdist": "52f03b4fa694c5a5e8dd0f606e0afb98644b1989b474f526af6dfb079e501cb4",
        },
        "asset_names": {
            "pypi_wheel": "schemathesis-3.20.0-py3-none-any.whl",
            "pypi_sdist": "schemathesis-3.20.0.tar.gz",
        },
    },
    "semgrep": {
        "tool_name": "semgrep",
        "version": "1.65.0",
        "release_tag": "1.65.0",
        "repo": "PyPI:semgrep",
        "pinned_version": "1.65.0",
        "category": "Code SAST",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "pypi_sdist": "f8d5e9bb4a743399646ff421f7261d19f11c02511c0398055ecf1d01d7a31c64",
            "pypi_wheel": "df77ef830ef039a4e7626556dc6719d6a6221a7966e42fe9cc5a9de2effafd6d",
        },
        "asset_names": {
            "pypi_sdist": "semgrep-1.65.0.tar.gz",
            "pypi_wheel": "semgrep-1.65.0-cp38.cp39.cp310.cp311.py37.py38.py39.py310.py311-none-any.whl",
        },
    },
    "bandit": {
        "tool_name": "bandit",
        "version": "1.7.8",
        "release_tag": "1.7.8",
        "repo": "PyPI:bandit",
        "pinned_version": "1.7.8",
        "category": "Code SAST",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "pypi_wheel": "509f7af645bc0cd8fd4587abc1a038fc795636671ee8204d502b933aee44f381",
            "pypi_sdist": "36de50f720856ab24a24dbaa5fee2c66050ed97c1477e0a1159deab1775eab6b",
        },
        "asset_names": {
            "pypi_wheel": "bandit-1.7.8-py3-none-any.whl",
            "pypi_sdist": "bandit-1.7.8.tar.gz",
        },
    },
    "checkov": {
        "tool_name": "checkov",
        "version": "3.2.0",
        "release_tag": "3.2.0",
        "repo": "PyPI:checkov",
        "pinned_version": "3.2.0",
        "category": "Infra IaC",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "pypi_wheel": "2719334876d0ee6a8ebe8d15ff393cbb4c13dcfe81e3cb9348ef2c1ed8372c6e",
            "pypi_sdist": "8e3aee686f76165f6d4bfcf6a8ee192ee84039a0f5f21315d8639b404a4bc06b",
        },
        "asset_names": {
            "pypi_wheel": "checkov-3.2.0-py3-none-any.whl",
            "pypi_sdist": "checkov-3.2.0.tar.gz",
        },
    },
    "prowler": {
        "tool_name": "prowler",
        "version": "4.1.0",
        "release_tag": "4.1.0",
        "repo": "PyPI:prowler",
        "pinned_version": "4.1.0",
        "category": "Cloud Posture",
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "sha256_checksums": {
            "pypi_wheel": "f52fa978f3283da43ac2e3bc6733d67246c9a02decc757d5b699c31fe31dcd9b",
            "pypi_sdist": "2c4e9a77750b7f3ef83b2fc80ece21dd9cf6d2a55efb6325e8d072aa80e93da3",
        },
        "asset_names": {
            "pypi_wheel": "prowler-4.1.0-py3-none-any.whl",
            "pypi_sdist": "prowler-4.1.0.tar.gz",
        },
    },
}


def audit_tool_manifest(
    tool_names: list[str],
    manifest: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, list[str]]:
    """Classify registry tools without converting incomplete metadata to trust.

    ``assured`` means the entry has the minimum identity and digest metadata
    required for immutable artifact verification.  ``incomplete`` is an
    explicit fail-closed result for known tools whose contract metadata is not
    available yet (for example package-manager delegated or manual tools).
    ``invalid`` is reserved for malformed entries, while ``unregistered``
    identifies tools absent from the authoritative manifest entirely.
    """
    source = manifest if manifest is not None else PINNED_TOOL_MANIFEST
    result = {"assured": [], "incomplete": [], "invalid": [], "unregistered": []}
    digest_pattern = re.compile(r"^[0-9a-f]{64}$")

    for tool_name in tool_names:
        entry = source.get(tool_name)
        if entry is None:
            result["unregistered"].append(tool_name)
            continue

        trust_mode = str(entry.get("trust_mode", "DIRECT_ARTIFACT_MODE")).strip()
        required_identity = all(
            isinstance(entry.get(field), str) and entry[field].strip()
            for field in ("tool_name", "version", "release_tag", "repo", "category")
        )
        checksums = entry.get("sha256_checksums")
        assets = entry.get("asset_names", {})
        structurally_valid = (
            required_identity
            and entry.get("tool_name") == tool_name
            and trust_mode in {
                "DIRECT_ARTIFACT_MODE",
                "SOURCE_BUILD_MODE",
                "PACKAGE_MANAGER_MODE",
                "MANUAL_MODE",
                "NATIVE_ENGINE_MODE",
            }
            and isinstance(checksums, dict)
            and isinstance(assets, dict)
            and all(isinstance(name, str) and name.strip() for name in assets.values())
            and all(
                isinstance(digest, str) and digest_pattern.fullmatch(digest)
                for digest in checksums.values()
            )
            and set(checksums) == set(assets)
        )
        if trust_mode == "DIRECT_ARTIFACT_MODE":
            structurally_valid = structurally_valid and all(
                isinstance(entry.get(field), str) and entry[field].strip()
                for field in ("pinned_version",)
            ) and bool(checksums)
        elif trust_mode == "SOURCE_BUILD_MODE":
            source_commit = str(entry.get("source_commit", "")).strip().lower()
            structurally_valid = structurally_valid and (
                entry.get("source_build") is True
                and entry.get("direct_release_artifact_available") is False
                and isinstance(entry.get("source_archive_url"), str)
                and entry["source_archive_url"].startswith("https://")
                and bool(re.fullmatch(r"[0-9a-f]{40}", source_commit))
                and isinstance(entry.get("build_toolchain"), str)
                and bool(entry["build_toolchain"].strip())
                and "source_archive" in checksums
                and "source_archive" in assets
                and any(key.startswith("go_") for key in checksums)
                and all(key in assets for key in checksums if key.startswith("go_"))
            )
        elif trust_mode in {"MANUAL_MODE", "NATIVE_ENGINE_MODE"}:
            # These integrations are intentionally diagnostic/native only;
            # any artifact digest must not accidentally elevate them to an
            # assured installation mode.
            structurally_valid = structurally_valid and not checksums and not assets
        # A package-manager, manual, or native entry may be delegated when its
        # artifact identity is intentionally unavailable; empty checksums are
        # classified below as incomplete rather than trusted.

        if not structurally_valid:
            result["invalid"].append(tool_name)
        elif not checksums:
            result["incomplete"].append(tool_name)
        else:
            result["assured"].append(tool_name)

    return result


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

    checksums = manifest_entry.get("sha256_checksums", {})
    if not isinstance(checksums, dict) or not checksums:
        return False, actual_hash, f"No authoritative SHA-256 digest is registered for tool '{tool_name}'. Installation rejected."

    # A caller-supplied digest is only an assertion about which manifest
    # artifact is being checked; it is never allowed to establish trust. This
    # prevents a caller from passing the digest of arbitrary bytes and making
    # them appear to be an approved release.
    if platform_key:
        expected = checksums.get(platform_key)
        if not expected:
            return False, actual_hash, f"No authoritative SHA-256 digest is registered for '{tool_name}' artifact '{platform_key}'. Installation rejected."
    elif len(checksums) == 1:
        expected = next(iter(checksums.values()))
    else:
        return False, actual_hash, f"A platform or artifact key is required to select the authoritative digest for '{tool_name}'. Installation rejected."

    if expected_sha256 is not None and expected_sha256.strip().lower() != str(expected).strip().lower():
        return False, actual_hash, f"Caller-supplied digest does not match the authoritative manifest digest for '{tool_name}'. Installation rejected."

    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        return False, actual_hash, f"Authoritative SHA-256 digest metadata for '{tool_name}' is invalid. Installation rejected."

    if expected.strip().lower() != actual_hash:
        return (
            False,
            actual_hash,
            f"Cryptographic SHA-256 checksum mismatch for '{tool_name}'! Expected '{expected.strip().lower()}', computed '{actual_hash}'."
        )

    return True, actual_hash, None
