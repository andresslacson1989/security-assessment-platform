"""Authorization-seal authenticity regression tests."""

import hashlib

import pytest

from app.core.models import Target, TargetType
from app.core.ssrf_protector import (
    SSRFProtectionError,
    _validated_target_context_digest,
    create_validated_target,
    validate_validated_target,
)


def test_validated_target_seal_is_authenticated_not_recomputable_plain_hash():
    target = Target(name="sealed", type=TargetType.IP, value="1.1.1.1")
    validated = create_validated_target(target, organization_id="org-a", asset_id="asset-a")

    assert validate_validated_target(validated) is validated

    plain_hash = hashlib.sha256(
        f"GATEWAY_SEAL:{validated.target_id}:{validated.authorization_decision_id}:"
        f"{validated.policy_version}:{_validated_target_context_digest(validated)}".encode("utf-8")
    ).hexdigest()
    forged = validated.model_copy(update={"integrity_seal": plain_hash})

    with pytest.raises(SSRFProtectionError, match="integrity seal is invalid"):
        validate_validated_target(forged)
