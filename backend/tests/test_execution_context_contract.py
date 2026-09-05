"""Pure contract tests for verifier-issued execution contexts."""

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "core" / "execution_context.py"
spec = importlib.util.spec_from_file_location("execution_context_contract_test_module", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)


def _issued():
    command = ("nmap", "--version")
    return module.GovernedExecutionContext._issue(
        module._AUTHORITY_ISSUER,
        execution_id="run-1", request_id="req-1", organization_id="org-1",
        asset_id="asset-1", target_id="target-1", authorization_decision_id="dec-1",
        request_fingerprint="fingerprint", target_policy_version="target-v1",
        operation_policy_revision="operation-v1", tool_id="nmap", operation_family="network",
        worker_identity="worker-1", worker_generation="generation-1", session_jti="session-1",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=1), correlation_id="corr-1",
        exact_command=command, command_digest=module.canonical_command_digest(command),
        authority_token="opaque-claim",
    )


def test_context_is_issued_and_exact_command_bound():
    context = _issued()
    context.assert_launch(execution_id="run-1", organization_id="org-1", command=["nmap", "--version"])
    with pytest.raises(module.ExecutionContextCommandError):
        context.assert_launch(execution_id="run-1", organization_id="org-1", command=["nmap", "-sV"])


def test_public_reconstruction_cannot_become_authority():
    context = _issued()
    reconstructed = module.GovernedExecutionContext(**context.model_dump())
    with pytest.raises(module.MissingExecutionContextError):
        reconstructed.assert_issued()


def test_attestation_schema_rejects_unknown_fields():
    with pytest.raises(Exception):
        module.WindowsJobAttestation(
            schema_version="windows-job-attestation-v1", proof_type="JOB_OBJECT",
            job_identity="job", root_process_start_token="start", worker_generation="gen",
            captured_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(seconds=1),
            verification_result="UNVERIFIED", digest="0" * 64, unexpected="reject",
        )
