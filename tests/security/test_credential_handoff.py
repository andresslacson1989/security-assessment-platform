"""Adversarial tests for encrypted durable cloud-credential handoff."""

import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.core.credential_handoff import (
    CredentialHandoffError,
    decrypt_credential_envelope,
    encrypt_credential_envelope,
    require_credential_handoff_key,
)
from app.core.models import CloudCredentialEnvelope


def _envelope() -> CloudCredentialEnvelope:
    return CloudCredentialEnvelope(
        organization_id="org-a",
        asset_id="asset-a",
        provider="aws",
        credentials={
            "AWS_ACCESS_KEY_ID": "AKIA_TEST",
            "AWS_SECRET_ACCESS_KEY": "secret-test",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def test_credential_handoff_is_authenticated_and_not_plaintext(monkeypatch):
    key = base64.urlsafe_b64encode(b"k" * 32).decode("ascii")
    monkeypatch.setenv("CLOUD_CREDENTIALS_ENCRYPTION_KEY", key)
    envelope = _envelope()

    token = encrypt_credential_envelope(envelope, scan_id="scan-a", organization_id="org-a")
    assert "AKIA_TEST" not in token
    assert "secret-test" not in token
    assert decrypt_credential_envelope(token, scan_id="scan-a", organization_id="org-a") == envelope

    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(CredentialHandoffError):
        decrypt_credential_envelope(tampered, scan_id="scan-a", organization_id="org-a")
    with pytest.raises(CredentialHandoffError):
        decrypt_credential_envelope(token, scan_id="scan-a", organization_id="org-b")


def test_credential_handoff_requires_separately_provisioned_key(monkeypatch):
    monkeypatch.delenv("CLOUD_CREDENTIALS_ENCRYPTION_KEY", raising=False)
    with pytest.raises(CredentialHandoffError):
        encrypt_credential_envelope(_envelope(), scan_id="scan-a", organization_id="org-a")


def test_credential_handoff_startup_validation_requires_a_32_byte_key(monkeypatch):
    monkeypatch.setenv("CLOUD_CREDENTIALS_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"z" * 32).decode("ascii"))
    assert require_credential_handoff_key() == b"z" * 32
    monkeypatch.setenv("CLOUD_CREDENTIALS_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"short").decode("ascii"))
    with pytest.raises(CredentialHandoffError):
        require_credential_handoff_key()


@pytest.mark.asyncio
async def test_durable_queue_delivers_only_authenticated_worker_envelope(monkeypatch):
    from app.core.queue import RedisDurableQueue

    key = base64.urlsafe_b64encode(b"q" * 32).decode("ascii")
    monkeypatch.setenv("CLOUD_CREDENTIALS_ENCRYPTION_KEY", key)

    class FakeRedis:
        def __init__(self):
            self.fields = None

        async def xadd(self, _stream, fields):
            self.fields = fields
            return "message-1"

        async def xautoclaim(self, *_args, **_kwargs):
            return ("0-0", [], [])

        async def xreadgroup(self, *_args, **_kwargs):
            return [("stream", [("message-1", self.fields)])]

        async def xack(self, *_args):
            return None

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = None

    envelope = _envelope()
    assert await queue.enqueue("scan-a", "org-a", envelope) == "message-1"
    assert "AKIA_TEST" not in queue._redis.fields["credential_envelope"]
    received = []

    async def handler(scan_id, organization_id, delivered):
        received.append((scan_id, organization_id, delivered))

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert received == [("scan-a", "org-a", envelope)]


@pytest.mark.asyncio
async def test_queue_manager_forwards_worker_envelope_without_serializing_it(monkeypatch):
    from app.core.queue import ScanQueueManager

    class Backend:
        def __init__(self):
            self.received = None

        async def enqueue(self, scan_id, organization_id, credential_envelope=None):
            self.received = (scan_id, organization_id, credential_envelope)
            return "message-1"

    backend = Backend()
    manager = ScanQueueManager(durable_backend=backend)
    envelope = _envelope()
    await manager.enqueue_only("scan-a", "org-a", envelope)
    assert backend.received == ("scan-a", "org-a", envelope)
