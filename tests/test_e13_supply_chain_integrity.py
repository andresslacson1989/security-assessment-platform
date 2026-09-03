"""
E13.7 — Adversarial Acceptance Tests for Supply Chain & Reproducible Deployment.
Validates:
- Tool manifest completeness & integrity: all canonical tools possess strict version, trust_mode, category.
- Cryptographic hash mismatch rejection: corrupted/tampered download bytes fail closed.
- Caller digest spoofing rejection: caller cannot authorize arbitrary bytes by providing their own hash.
- Missing binary graceful degradation: resolving non-existent tool returns None, executes without crashes or loops.
- Production container compliance: Dockerfile uses pinned base image, non-root USER directive, and strict .dockerignore.
"""

import os
from unittest.mock import AsyncMock, patch
import pytest

from app.installers.tool_manifest import (
    PINNED_TOOL_MANIFEST,
    verify_download_integrity,
    calculate_sha256,
)
from app.core.binary_resolver import resolve_binary
from app.adapters.nuclei_adapter import NucleiAdapter
from app.core.models import Target, TargetType, ScanConfig, NormalizedExecutionState


def test_tool_manifest_completeness_and_structure():
    """Every registered tool in PINNED_TOOL_MANIFEST must have required identity and metadata."""
    assert len(PINNED_TOOL_MANIFEST) >= 15
    for tool_name, entry in PINNED_TOOL_MANIFEST.items():
        assert entry.get("tool_name") == tool_name
        assert "version" in entry
        assert "category" in entry
        trust_mode = entry.get("trust_mode", "DIRECT_ARTIFACT_MODE")
        assert trust_mode in {
            "DIRECT_ARTIFACT_MODE",
            "SOURCE_BUILD_MODE",
            "PACKAGE_MANAGER_MODE",
            "MANUAL_MODE",
            "NATIVE_ENGINE_MODE",
        }
        if trust_mode in {"DIRECT_ARTIFACT_MODE", "SOURCE_BUILD_MODE"}:
            assert "sha256_checksums" in entry
            assert isinstance(entry["sha256_checksums"], dict)
            assert len(entry["sha256_checksums"]) > 0


def test_cryptographic_checksum_mismatch_rejection():
    """Tampered or corrupted binary downloads must fail closed."""
    tampered_bytes = b"CORRUPTED_OR_MALICIOUS_BINARY_CONTENTS"
    is_valid, _, err = verify_download_integrity(
        "nuclei",
        tampered_bytes,
        expected_sha256="1111111111111111111111111111111111111111111111111111111111111111",
        platform_key="linux_amd64",
    )
    assert is_valid is False
    assert "authoritative" in err.lower() or "mismatch" in err.lower()


def test_caller_digest_spoofing_rejected():
    """A caller cannot bypass supply chain verification by hashing their own payload."""
    arbitrary_bytes = b"ARBITRARY_PAYLOAD_WITH_CALLER_HASH"
    caller_hash = calculate_sha256(arbitrary_bytes)
    is_valid, _, err = verify_download_integrity(
        "ffuf",
        arbitrary_bytes,
        expected_sha256=caller_hash,
        platform_key="linux_amd64",
    )
    assert is_valid is False
    assert "authoritative" in err.lower()


def test_missing_binary_resolution_fails_cleanly():
    """Non-existent tool names resolve to None without raising exceptions or infinite loops."""
    assert resolve_binary("non_existent_tool_xyz") is None
    assert resolve_binary("") is None


@pytest.mark.asyncio
async def test_missing_binary_adapter_graceful_degradation():
    """When a binary is missing on host, adapter gracefully returns zero findings and degraded state."""
    adapter = NucleiAdapter()
    target = Target(name="test", type=TargetType.URL, value="https://example.com")
    config = ScanConfig()

    with patch.object(adapter, "resolve_binary_path", return_value=None):
        findings = await adapter.run(target, config, AsyncMock(), AsyncMock())

    assert findings == []
    assert adapter.last_execution_state in {
        NormalizedExecutionState.NOT_EXECUTED_PREREQUISITE_MISSING,
        NormalizedExecutionState.TOOL_EXECUTION_FAILED,
    }


def test_dockerfile_and_dockerignore_compliance():
    """Dockerfile and .dockerignore adhere to enterprise supply-chain rules."""
    import re
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dockerfile_path = os.path.join(root_dir, "Dockerfile")
    dockerignore_path = os.path.join(root_dir, ".dockerignore")

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        dockerfile = f.read()

    with open(dockerignore_path, "r", encoding="utf-8") as f:
        dockerignore = f.read()

    # R2.4: Require authoritative immutable OCI base image digests (@sha256:<64-hex>)
    from_lines = re.findall(r"FROM (?:--platform=[^\s]+ )?([^\s]+)", dockerfile)
    assert len(from_lines) >= 2, "Dockerfile must contain at least builder and runtime stages"
    
    sha256_digest_regex = re.compile(r"^python:3\.11-slim-bookworm@sha256:[a-f0-9]{64}$")
    for img in from_lines:
        assert "@sha256:" in img, f"Base image {img} is mutable (not pinned by cryptographic digest)"
        assert sha256_digest_regex.match(img), f"Base image {img} does not match strict @sha256:64-hex digest format"

    # Non-root user check
    assert "USER cyberassess" in dockerfile

    # .dockerignore excludes sensitive files
    assert ".git" in dockerignore
    assert ".env*" in dockerignore
    assert "tests/" in dockerignore
    assert "__pycache__" in dockerignore


def test_supply_chain_distinguishes_tag_pinned_from_digest_pinned():
    """R2.4: Invariant verifying mutable tag-only references are rejected as not digest-pinned."""
    import re
    sha256_digest_regex = re.compile(r"^.+@sha256:[a-f0-9]{64}$")

    # Mutable version tags must fail digest pinning check
    assert not sha256_digest_regex.match("python:3.11-slim-bookworm")
    assert not sha256_digest_regex.match("python:3.11-slim")
    assert not sha256_digest_regex.match("python:latest")
    assert not sha256_digest_regex.match("python:3.11@sha256:short")

    # Cryptographic immutable digest must pass
    valid_digest = "python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84"
    assert sha256_digest_regex.match(valid_digest)

