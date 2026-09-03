"""Encrypted handoff for worker-only cloud credential envelopes.

Credential material must never be persisted as part of a ScanJob or placed in
the durable queue as plaintext.  The control-plane queue message carries an
authenticated, encrypted envelope that only a worker with the separately
provisioned handoff key can open.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from typing import Optional

from app.core.models import CloudCredentialEnvelope


class CredentialHandoffError(ValueError):
    """Raised when encrypted worker credential handoff cannot be trusted."""


def require_credential_handoff_key() -> bytes:
    """Validate the separately provisioned durable-handoff key at startup."""
    return _key_from_environment()


def _key_from_environment() -> bytes:
    value = os.getenv("CLOUD_CREDENTIALS_ENCRYPTION_KEY", "").strip()
    if not value:
        raise CredentialHandoffError("CLOUD_CREDENTIALS_ENCRYPTION_KEY is required")
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
    except (binascii.Error, UnicodeError) as exc:
        raise CredentialHandoffError("credential handoff key must be URL-safe base64") from exc
    if len(key) != 32:
        raise CredentialHandoffError("credential handoff key must decode to 32 bytes")
    return key


def encrypt_credential_envelope(
    envelope: CloudCredentialEnvelope,
    *,
    scan_id: str,
    organization_id: str,
) -> str:
    """Encrypt an envelope with authenticated scan and tenant associated data."""
    if envelope.organization_id != organization_id:
        raise CredentialHandoffError("credential envelope tenant does not match queue intent")
    if not scan_id or not organization_id:
        raise CredentialHandoffError("credential handoff requires scan and tenant identities")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - locked production dependency
        raise CredentialHandoffError("cryptography is required for credential handoff") from exc

    nonce = secrets.token_bytes(12)
    aad = f"cyberassess:cloud-credentials:v1:{scan_id}:{organization_id}".encode("utf-8")
    payload = json.dumps(
        envelope.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(_key_from_environment()).encrypt(nonce, payload, aad)
    token = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return f"v1.{token}"


def decrypt_credential_envelope(
    token: str,
    *,
    scan_id: str,
    organization_id: str,
) -> Optional[CloudCredentialEnvelope]:
    """Decrypt and authenticate a worker envelope; reject every mismatch."""
    if not isinstance(token, str) or not token.startswith("v1."):
        raise CredentialHandoffError("unsupported credential handoff token")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        encoded = token[3:].encode("ascii")
        raw = base64.urlsafe_b64decode(encoded)
        if len(raw) <= 12:
            raise CredentialHandoffError("credential handoff token is truncated")
        nonce, ciphertext = raw[:12], raw[12:]
        aad = f"cyberassess:cloud-credentials:v1:{scan_id}:{organization_id}".encode("utf-8")
        payload = AESGCM(_key_from_environment()).decrypt(nonce, ciphertext, aad)
        envelope = CloudCredentialEnvelope.model_validate(json.loads(payload))
    except CredentialHandoffError:
        raise
    except (binascii.Error, UnicodeError, json.JSONDecodeError, TypeError, ValueError, InvalidTag) as exc:
        raise CredentialHandoffError("credential handoff authentication failed") from exc
    if envelope.organization_id != organization_id:
        raise CredentialHandoffError("credential envelope tenant binding failed")
    return envelope
