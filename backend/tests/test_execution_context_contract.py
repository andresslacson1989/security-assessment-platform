"""Pure contract tests for verifier-issued execution contexts."""

import importlib.util
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "core" / "execution_context.py"
sys.path.insert(0, str(MODULE_PATH.parents[2]))
spec = importlib.util.spec_from_file_location("execution_context_contract_test_module", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)


def _issued():
    command = ("nmap", "--version")
    context = module.GovernedExecutionContext(
        execution_id="run-1", request_id="req-1", organization_id="org-1",
        asset_id="asset-1", target_id="target-1", target_integrity_seal="seal-1", authorization_decision_id="dec-1",
        request_fingerprint="fingerprint", target_policy_version="target-v1",
        operation_policy_revision="operation-v1", tool_id="nmap", operation_family="network",
        worker_identity="worker-1", worker_generation="generation-1", session_jti="session-1",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=1), correlation_id="corr-1",
        exact_command=command, command_digest=module.canonical_command_digest(command),
        authority_token="opaque-claim",
        operation_options_digest=module.canonical_binding_digest({}),
        resource_budget_digest=module.canonical_binding_digest({}),
        account_impact_budget_digest=module.canonical_binding_digest({}),
        credential_scope_digest=module.canonical_binding_digest({}),
        revocation_check_reference="session-jti:session-1",
    )
    module._register_issued_context(context)
    return context


def _load_execution_service_without_application_startup():
    """Load the issuance boundary without opening the protected application DB.

    This contract test deliberately loads the context module in isolation.  The
    service module is therefore loaded with minimal import-time collaborators;
    the behavior under test is the service-owned issuer, not database startup.
    """
    existing = sys.modules.get("app.core.execution_service")
    if existing is not None:
        return existing
    app_package = sys.modules.setdefault("app", types.ModuleType("app"))
    app_package.__path__ = []
    core_package = sys.modules.setdefault("app.core", types.ModuleType("app.core"))
    core_package.__path__ = []
    sys.modules["app.core.execution_context"] = module
    db_stub = types.ModuleType("app.core.db")
    db_stub._ACTIVE_DATABASE_CONNECTION = object()
    sys.modules["app.core.db"] = db_stub
    models_stub = types.ModuleType("app.core.models")
    models_stub.ExecutionProcessOwnershipRecord = object
    models_stub.EXECUTION_REASON_CODES = set()
    models_stub.ProcessContainerType = object
    models_stub.ProcessOwnershipState = object
    models_stub.LaunchCommitState = object
    models_stub.utc_now = lambda: datetime.now(timezone.utc)
    sys.modules.setdefault("app.core.models", models_stub)
    service_path = MODULE_PATH.with_name("execution_service.py")
    service_spec = importlib.util.spec_from_file_location("app.core.execution_service", service_path)
    service = importlib.util.module_from_spec(service_spec)
    sys.modules[service_spec.name] = service
    assert service_spec.loader is not None
    service_spec.loader.exec_module(service)
    return service


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


def test_no_exported_issuer_or_public_issue_factory():
    assert not hasattr(module, "_AUTHORITY_ISSUER")
    assert not hasattr(module, "issue_non_scan_execution_context")
    assert not hasattr(module.GovernedExecutionContext, "_issue")


def test_binding_maps_are_deeply_immutable():
    context = _issued()
    assert isinstance(context.operation_options, tuple)
    with pytest.raises(Exception):
        context.operation_options += (("new", "value"),)


def test_attestation_schema_rejects_unknown_fields():
    with pytest.raises(Exception):
        module.WindowsJobAttestation(
            schema_version="windows-job-attestation-v1", proof_type="JOB_OBJECT",
            job_identity="job", root_process_start_token="start", worker_generation="gen",
            captured_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(seconds=1),
            verification_result="UNVERIFIED", digest="0" * 64, unexpected="reject",
        )


def test_attestation_digest_is_recomputed_from_canonical_fields():
    captured = datetime.now(timezone.utc)
    values = {
        "schema_version": "windows-job-attestation-v1", "proof_type": "JOB_OBJECT",
        "job_identity": "job", "root_process_start_token": "start", "worker_generation": "gen",
        "captured_at": captured, "expires_at": captured + timedelta(seconds=1),
        "verification_result": "UNVERIFIED",
    }
    with pytest.raises(Exception):
        module.WindowsJobAttestation(**values, digest="0" * 64)
    values["digest"] = module.canonical_binding_digest(values)
    module.WindowsJobAttestation(**values)


def test_non_scan_capability_factory_is_purpose_and_ttl_bounded():
    service = _load_execution_service_without_application_startup()
    issue_non_scan_execution_context = service.issue_non_scan_execution_context
    service_context_module = sys.modules["app.core.execution_context"]
    UnsupportedNonScanContextError = service_context_module.UnsupportedNonScanContextError

    with pytest.raises(module.UnsupportedNonScanContextError):
        module._issue_non_scan_execution_context(
            "arbitrary-authority", ttl_seconds=300, issuer=module._ISSUER_TOKEN,
            worker_identity="worker", worker_generation="generation",
        )
    with pytest.raises(UnsupportedNonScanContextError):
        issue_non_scan_execution_context("installer:tool", ttl_seconds=901)
    context = issue_non_scan_execution_context("installer:tool", ttl_seconds=1)
    context.assert_live()
