"""Real-path assurance for immutable scan dispatch and terminal replay.

The tests in this module intentionally use the production database methods and
orchestrator worker handoff.  The only test double is the final assessment
engine body, which prevents any real scanner or network activity while keeping
the parent-manifest, normalized rows, child authorities, queue fence, and
settlement path live.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest

from app.core.db import DatabaseManager
from app.core.models import (
    Asset,
    AssetLifecycleStatus,
    AssetType,
    ScanAuthorizationRequestRecord,
    ScanConfig,
    ScanJob,
    ScanProfile,
    ScanStatus,
    Target,
    TargetType,
    ToolAdapterConfig,
    SystemCapabilities,
    utc_now,
)
from app.core.scan_manifest import build_scan_manifest
from app.core.ssrf_protector import create_validated_target
from app.core.tool_fleet import SUPPORTED_TOOL_IDS
from app.engines.network.engine import NetworkAssessmentEngine


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROJECT_TEMP_ROOT = REPOSITORY_ROOT / ".project-temp"
POSTGRES_TEST_URL = os.getenv("CYBERASSESS_POSTGRES_TEST_URL", "").strip()
POSTGRES_TEST_ACK = os.getenv("CYBERASSESS_POSTGRES_TEST_ACK", "").strip()
LIVE_REDIS_TEST_URL = os.getenv("CYBERASSESS_LIVE_REDIS_TEST_URL", "").strip()


@dataclass(frozen=True)
class SeededManifest:
    database: object
    organization_id: str
    user_id: str
    asset_id: str
    scan_id: str
    scan_request_id: str
    operation_id: str
    selected_tool_id: str
    worker_identity: str
    job: ScanJob
    manifest_hash: str


@contextmanager
def _isolated_database(backend: str):
    """Yield a disposable SQLite or explicitly acknowledged loopback Postgres DB."""
    if backend == "sqlite":
        PROJECT_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="real-dispatch-",
            dir=str(PROJECT_TEMP_ROOT),
        ) as directory:
            yield DatabaseManager(Path(directory) / "cyberassess.sqlite3")
        return

    if not POSTGRES_TEST_URL:
        pytest.skip("CYBERASSESS_POSTGRES_TEST_URL is required for isolated PostgreSQL assurance")
    if POSTGRES_TEST_ACK != "I_UNDERSTAND_DISPOSABLE_DATABASE_MUTATION":
        pytest.skip("PostgreSQL assurance requires explicit disposable-database acknowledgment")

    psycopg = pytest.importorskip("psycopg")
    from app.core.db import PostgresDatabaseManager

    parts = urlsplit(POSTGRES_TEST_URL)
    if parts.hostname not in {"127.0.0.1", "::1"}:
        pytest.skip("PostgreSQL assurance requires the literal loopback address")
    if not parts.path.rstrip("/").endswith(("_ci", "_test")):
        pytest.skip("PostgreSQL assurance requires a database ending in _ci or _test")

    schema = "cyberassess_real_dispatch_" + uuid.uuid4().hex
    with psycopg.connect(POSTGRES_TEST_URL, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA "{schema}"')
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["options"] = f"-csearch_path={schema}"
    isolated_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )
    database = None
    try:
        database = PostgresDatabaseManager(isolated_url)
        yield database
    finally:
        if database is not None and database._pool is not None:
            database._pool.close()
        with psycopg.connect(POSTGRES_TEST_URL, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA "{schema}" CASCADE')


@contextmanager
def _fresh_database_manager(database: object):
    """Open a second manager against the same isolated backend and scope."""
    database_url = getattr(database, "database_url", None)
    if isinstance(database_url, str) and database_url.strip():
        from app.core.db import PostgresDatabaseManager

        fresh_database = PostgresDatabaseManager(database_url)
        try:
            yield fresh_database
        finally:
            if fresh_database._pool is not None:
                fresh_database._pool.close()
        return

    database_path = getattr(database, "db_path", None)
    if database_path is None:
        raise AssertionError("isolated database does not expose a fresh-manager identity")
    yield DatabaseManager(database_path)


def _seed_manifest(database: object, *, project_scoped: bool = False) -> SeededManifest:
    """Create one complete tenant-bound parent manifest in the real DAL."""
    suffix = uuid.uuid4().hex
    organization_id = f"org-real-dispatch-{suffix}"
    user_id = f"user-real-dispatch-{suffix}"
    asset_id = f"asset-real-dispatch-{suffix}"
    scan_id = f"scan-real-dispatch-{suffix}"
    scan_request_id = f"scanreq-real-dispatch-{suffix}"
    correlation_id = f"corr-real-dispatch-{suffix}"
    worker_identity = f"worker-real-dispatch-{suffix}"
    project_id = f"project-real-dispatch-{suffix}" if project_scoped else None
    created_at = utc_now()

    with database._connection_scope() as connection:
        connection.execute(
            "INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (organization_id, "Real Dispatch Assurance", f"real-dispatch-{suffix}", created_at.isoformat()),
        )
        connection.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
            (user_id, f"real-dispatch-{suffix}", f"{suffix}@example.invalid", "test-hash", organization_id, created_at.isoformat()),
        )
        if project_id:
            connection.execute(
                "INSERT INTO projects (id, organization_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, organization_id, "Real dispatch project", "Project scope regression", created_at.isoformat()),
            )

    asset = Asset(
        id=asset_id,
        organization_id=organization_id,
        project_id=project_id,
        name="Real dispatch assurance asset",
        type=AssetType.IP_ADDRESS,
        target_value="1.1.1.1",
        active_probing_granted=True,
        lifecycle_status=AssetLifecycleStatus.MONITORED,
        owner="security-owner@example.invalid",
    )
    database.create_asset(asset)

    target = Target(name="Real dispatch target", type=TargetType.IP, value=asset.target_value)
    validated_target = create_validated_target(
        target,
        organization_id=organization_id,
        project_id=project_id,
        asset_id=asset_id,
        active_probing_granted=True,
    )
    configuration = ScanConfig(
        profile=ScanProfile.QUICK,
        adapters=ToolAdapterConfig(
            enable_nmap=True,
            enable_sslyze=False,
            enable_subfinder=False,
            enable_httpx=False,
            enable_amass=False,
            enable_metasploit=False,
        ),
    )
    network_engine = NetworkAssessmentEngine()
    manifest = build_scan_manifest(
        organization_id=organization_id,
        project_id=project_id,
        asset_id=asset_id,
        asset_owner=asset.owner,
        asset_lifecycle_status=asset.lifecycle_status.value,
        validated_target=validated_target,
        profile=ScanProfile.QUICK.value,
        selected_engine_ids=(network_engine.name,),
        engines=(network_engine,),
        requested_expiry=created_at + timedelta(minutes=5),
        scan_config=configuration,
        emergency_stop_reference=f"stop:{suffix}",
    )
    selected_operations = [
        operation for operation in manifest.operations
        if operation.selection_state == "SELECTED"
    ]
    assert len(selected_operations) == 1
    selected_operation = selected_operations[0]
    assert selected_operation.operation_id == "network:nmap"
    assert set(entry.tool_id for entry in manifest.fleet_snapshot) == set(SUPPORTED_TOOL_IDS)
    assert len(manifest.fleet_snapshot) == 26

    job = ScanJob(
        id=scan_id,
        correlation_id=correlation_id,
        organization_id=organization_id,
        project_id=project_id,
        asset_id=asset_id,
        active_probing_granted=True,
        target=target,
        profile=ScanProfile.QUICK,
        enabled_engines=[network_engine.name],
        config=configuration,
        status=ScanStatus.PENDING,
        authorization_state="REQUESTED",
        authorization_request_id=scan_request_id,
        authorization_manifest_hash=manifest.manifest_hash,
    )
    request = ScanAuthorizationRequestRecord(
        scan_request_id=scan_request_id,
        scan_id=scan_id,
        organization_id=organization_id,
        requested_by_user_id=user_id,
        correlation_id=correlation_id,
        manifest_hash=manifest.manifest_hash,
        manifest=manifest,
        expires_at=manifest.requested_expiry,
        creation_idempotency_key=f"real-dispatch-create-{suffix}",
        creation_fingerprint=hashlib.sha256(
            f"real-dispatch:{suffix}".encode("utf-8")
        ).hexdigest(),
    )
    database.save_scan_and_authorization_request(job, request)
    return SeededManifest(
        database=database,
        organization_id=organization_id,
        user_id=user_id,
        asset_id=asset_id,
        scan_id=scan_id,
        scan_request_id=scan_request_id,
        operation_id=selected_operation.operation_id,
        selected_tool_id=selected_operation.tool_id,
        worker_identity=worker_identity,
        job=job,
        manifest_hash=manifest.manifest_hash,
    )


@pytest.fixture(params=("sqlite", "postgresql"), ids=("sqlite", "postgresql"))
def seeded_manifest(request):
    with _isolated_database(request.param) as database:
        yield _seed_manifest(database)


@pytest.mark.parametrize("backend", ("sqlite", "postgresql"), ids=("sqlite", "postgresql"))
def test_project_scoped_real_approval_preserves_matching_and_rejects_mismatch(backend, monkeypatch):
    """Exercise the real approval path for nullable and non-null project scope.

    The project-bound case must authorize only the asset in the same tenant and
    project.  A changed asset project is rejected before child authority
    materialization, which protects the approval boundary from scope drift.
    """
    with _isolated_database(backend) as database:
        matching = _seed_manifest(database, project_scoped=True)
        _approve_seeded_manifest(matching, monkeypatch)

        mismatched = _seed_manifest(database, project_scoped=True)
        with mismatched.database._connection_scope() as connection:
            other_project_id = f"project-other-{uuid.uuid4().hex}"
            connection.execute(
                "INSERT INTO projects (id, organization_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
                (other_project_id, mismatched.organization_id, "Other project", "Scope mismatch regression", utc_now().isoformat()),
            )
            connection.execute(
                "UPDATE assets SET project_id=? WHERE id=? AND organization_id=?",
                (other_project_id, mismatched.asset_id, mismatched.organization_id),
            )

        with pytest.raises(RuntimeError, match="asset ownership or delegation"):
            _approve_seeded_manifest(mismatched, monkeypatch)


def _execution_lifecycle_snapshot(database: object, organization_id: str) -> str:
    """Capture the tenant-scoped durable state used by worker replay."""
    rows: dict[str, list[dict[str, object]]] = {}
    for table in (
        "scan_authorization_requests",
        "scan_authorization_operations",
        "scan_authorization_fleet",
        "execution_requests",
        "execution_decisions",
        "execution_runs",
        "execution_dispatch_intents",
        "execution_process_ownership",
        "execution_recovery_attempts",
        "execution_recovery_state",
        "scans",
        "audit_events",
    ):
        with database._connection_scope() as connection:
            rows[table] = [
                dict(row)
                for row in connection.execute(
                    f"SELECT * FROM {table} WHERE organization_id=?",
                    (organization_id,),
                ).fetchall()
            ]
    return json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str)


def _approve_seeded_manifest(seeded: SeededManifest, monkeypatch) -> str:
    from app.core.execution_service import get_worker_generation

    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", seeded.worker_identity)
    session_jti = f"session-real-dispatch-{uuid.uuid4().hex}"
    result, children = seeded.database.approve_scan_authorization_request(
        seeded.scan_request_id,
        seeded.organization_id,
        seeded.manifest_hash,
        f"real-dispatch-approve-{uuid.uuid4().hex}",
        seeded.user_id,
        session_jti,
        seeded.worker_identity,
        get_worker_generation(),
    )
    assert result == "AUTHORIZED"
    assert len(children) == 1
    seeded.job.authorization_state = "DISPATCHABLE"
    seeded.database.save_scan_record(seeded.job)
    reloaded = seeded.database.get_scan_record(
        seeded.scan_id,
        organization_id=seeded.organization_id,
    )
    assert reloaded is not None
    assert reloaded.authorization_manifest_hash == seeded.manifest_hash
    return children[0]["child_execution_id"]


def _prepare_real_no_process_worker(seeded: SeededManifest, monkeypatch):
    """Build the real worker handoff with only the final engine body replaced."""
    import app.core.orchestrator as orchestrator_module
    from app.core.orchestrator import ScanOrchestrator

    monkeypatch.setattr(orchestrator_module, "db_manager", seeded.database)
    monkeypatch.setattr(
        orchestrator_module,
        "get_scan",
        lambda scan_id, organization_id=None: seeded.database.get_scan_record(
            scan_id,
            organization_id=organization_id,
        ),
    )
    monkeypatch.setattr(orchestrator_module, "save_scan", seeded.database.save_scan_record)
    monkeypatch.setattr(
        orchestrator_module,
        "discover_system_capabilities",
        lambda _config: _empty_capabilities(),
    )

    engine_calls = {"count": 0}
    engine = NetworkAssessmentEngine()

    async def fake_engine_run(target, config, emit_log, emit_progress, emit_finding, **kwargs):
        engine_calls["count"] += 1
        assert target.value == "1.1.1.1"
        authority = kwargs["execution_authority_provider"]
        capability = authority.issue_capability(
            operation_id="network:nmap",
            tool_id="nmap",
            operation_family="network_assessment",
            operation_options={},
            command=["/managed/nmap", "--test-only"],
        )
        capability.revalidate_and_claim(
            tool_id="nmap",
            operation_family="network_assessment",
            operation_options={},
            command=["/managed/nmap", "--test-only"],
            worker_identity=seeded.worker_identity,
            timeout=30,
            max_output_bytes=1024,
        )
        assert capability.abort_start(
            terminal_state="EXECUTION_BLOCKED",
            reason_code="PROCESS_LAUNCH_REJECTED_SECURITY",
        )
        await kwargs["emit_tool_execution_state"]("nmap", "EXECUTION_BLOCKED")
        return []

    engine.run = fake_engine_run
    worker = ScanOrchestrator()
    worker.register_engine(engine)

    from app.core.queue import ScanQueueManager

    return worker, ScanQueueManager(durable_backend=None), engine_calls


def _prepare_real_posix_worker(seeded: SeededManifest, monkeypatch):
    """Build the real worker handoff with a durable POSIX terminal proof."""
    import app.core.orchestrator as orchestrator_module
    from app.core.orchestrator import ScanOrchestrator

    monkeypatch.setattr(orchestrator_module, "db_manager", seeded.database)
    monkeypatch.setattr(
        orchestrator_module,
        "get_scan",
        lambda scan_id, organization_id=None: seeded.database.get_scan_record(
            scan_id,
            organization_id=organization_id,
        ),
    )
    monkeypatch.setattr(orchestrator_module, "save_scan", seeded.database.save_scan_record)
    monkeypatch.setattr(
        orchestrator_module,
        "discover_system_capabilities",
        lambda _config: _empty_capabilities(),
    )

    engine_calls = {"count": 0}
    engine = NetworkAssessmentEngine()

    async def fake_engine_run(target, config, emit_log, emit_progress, emit_finding, **kwargs):
        engine_calls["count"] += 1
        assert target.value == "1.1.1.1"
        authority = kwargs["execution_authority_provider"]
        capability = authority.issue_capability(
            operation_id="network:nmap",
            tool_id="nmap",
            operation_family="network_assessment",
            operation_options={},
            command=["/managed/nmap", "--test-only"],
        )
        capability.revalidate_and_claim(
            tool_id="nmap",
            operation_family="network_assessment",
            operation_options={},
            command=["/managed/nmap", "--test-only"],
            worker_identity=seeded.worker_identity,
            timeout=30,
            max_output_bytes=1024,
        )
        from app.core.execution_service import record_posix_launch

        start_token = f"posix:{uuid.uuid4()}:{12345}"
        record_posix_launch(
            capability,
            pid=4242,
            process_group_id=4242,
            session_id=4242,
            start_token=start_token,
            member_snapshot=(SimpleNamespace(
                pid=4242,
                process_group_id=4242,
                session_id=4242,
                start_token=start_token,
            ),),
        )
        capability.mark_started(process_id=4242, process_group_id="4242")
        from app.core.execution_service import settle_execution

        assert settle_execution(
            capability,
            terminal_state="FAILED",
            reason_code="PROCESS_EXIT_NONZERO",
            process_id=4242,
            process_group_id="4242",
            process_start_token=start_token,
            session_id=4242,
            termination_status="ALREADY_EXITED",
        )
        await kwargs["emit_tool_execution_state"]("nmap", "FAILED")
        return []

    engine.run = fake_engine_run
    worker = ScanOrchestrator()
    worker.register_engine(engine)

    from app.core.queue import ScanQueueManager

    return worker, ScanQueueManager(durable_backend=None), engine_calls


async def _run_real_no_process_terminal(seeded: SeededManifest, monkeypatch):
    child_execution_id = _approve_seeded_manifest(seeded, monkeypatch)
    worker, executor, engine_calls = _prepare_real_no_process_worker(seeded, monkeypatch)
    await worker.execute_dispatched_scan(
        seeded.scan_id,
        seeded.organization_id,
        seeded.scan_request_id,
        executor=executor,
    )
    assert engine_calls["count"] == 1
    return child_execution_id, worker, executor, engine_calls


async def _run_real_posix_terminal(seeded: SeededManifest, monkeypatch):
    child_execution_id = _approve_seeded_manifest(seeded, monkeypatch)
    worker, executor, engine_calls = _prepare_real_posix_worker(seeded, monkeypatch)
    await worker.execute_dispatched_scan(
        seeded.scan_id,
        seeded.organization_id,
        seeded.scan_request_id,
        executor=executor,
    )
    assert engine_calls["count"] == 1
    return child_execution_id, worker, executor, engine_calls


@pytest.mark.asyncio
async def test_approved_dispatch_publishes_the_authoritative_queue_binding(
    seeded_manifest: SeededManifest,
    monkeypatch,
):
    """The production dispatch path publishes the DB-derived typed binding."""
    _approve_seeded_manifest(seeded_manifest, monkeypatch)
    worker, _executor, _engine_calls = _prepare_real_no_process_worker(
        seeded_manifest,
        monkeypatch,
    )

    class DurableQueue:
        durable_enabled = True

        def __init__(self):
            self.received = None

        async def enqueue_only(
            self,
            scan_id,
            organization_id,
            cloud_credentials,
            authorization_request_id,
            *,
            queue_binding,
        ):
            self.received = (
                scan_id,
                organization_id,
                cloud_credentials,
                authorization_request_id,
                queue_binding,
            )
            return "message-authoritative"

    from app.core import queue as queue_module

    durable_queue = DurableQueue()
    monkeypatch.setattr(queue_module, "queue_manager", durable_queue)
    await worker.dispatch_approved_scan(seeded_manifest.job)

    assert durable_queue.received is not None
    scan_id, organization_id, _credentials, request_id, binding = durable_queue.received
    assert (scan_id, organization_id, request_id) == (
        seeded_manifest.scan_id,
        seeded_manifest.organization_id,
        seeded_manifest.scan_request_id,
    )
    assert binding.scan_id == seeded_manifest.scan_id
    assert binding.organization_id == seeded_manifest.organization_id
    assert binding.authorization_request_id == seeded_manifest.scan_request_id
    assert binding.manifest_hash == seeded_manifest.manifest_hash
    assert binding.operation_ids == (seeded_manifest.operation_id,)
    assert len(binding.execution_ids) == 1


@pytest.mark.asyncio
async def test_real_queue_consumer_handoff_is_idempotent_and_rejects_tampered_binding(
    seeded_manifest: SeededManifest,
    monkeypatch,
):
    """Exercise authoritative publication, real consumer code, and worker handoff.

    The double below models only Redis Streams transport operations. The
    production ``RedisDurableQueue.consume_once`` implementation, the
    production worker callback boundary, and the production orchestrator are
    all executed. Live Redis service execution is reserved for the CI service
    job; this local vector does not claim live-Redis coverage.
    """
    _approve_seeded_manifest(seeded_manifest, monkeypatch)
    worker, local_executor, engine_calls = _prepare_real_no_process_worker(
        seeded_manifest,
        monkeypatch,
    )

    class DurableQueue:
        durable_enabled = True

        def __init__(self):
            self.received = None

        async def enqueue_only(
            self,
            scan_id,
            organization_id,
            cloud_credentials,
            authorization_request_id,
            *,
            queue_binding,
        ):
            self.received = (
                scan_id,
                organization_id,
                cloud_credentials,
                authorization_request_id,
                queue_binding,
            )
            return "message-authoritative-handoff"

    from app.core import queue as queue_module
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue
    from run_worker import handle_consumed_scan

    publisher = DurableQueue()
    monkeypatch.setattr(queue_module, "queue_manager", publisher)
    await worker.dispatch_approved_scan(seeded_manifest.job)
    assert publisher.received is not None
    scan_id, organization_id, _credentials, request_id, published_binding = publisher.received
    assert (scan_id, organization_id, request_id) == (
        seeded_manifest.scan_id,
        seeded_manifest.organization_id,
        seeded_manifest.scan_request_id,
    )

    def fields_for(binding):
        return {
            "message_kind": "AUTHORITATIVE_EXECUTION",
            "enqueued_at": "2026-09-11T00:00:00+00:00",
            "scan_id": binding.scan_id,
            "organization_id": binding.organization_id,
            "authorization_request_id": binding.authorization_request_id,
            "queue_binding_digest": binding.queue_binding_digest,
            "manifest_hash": binding.manifest_hash,
            "execution_ids_json": binding.execution_ids_json,
            "operation_ids_json": binding.operation_ids_json,
            "queue_binding_schema_version": binding.schema_version,
        }

    tampered_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash="0" * 64,
        execution_ids=published_binding.execution_ids,
        operation_ids=published_binding.operation_ids,
    )

    class ConsumerRedis:
        def __init__(self, deliveries):
            self.deliveries = list(deliveries)
            self.acks = []
            self.failures = []
            self.markers = {}

        async def xautoclaim(self, *_args, **_kwargs):
            if not self.deliveries:
                return ("0-0", [], [])
            return ("0-0", [self.deliveries.pop(0)], [])

        async def xreadgroup(self, *_args, **_kwargs):
            return []

        async def xack(self, _stream, _group, message_id):
            self.acks.append(message_id)

        async def get(self, key):
            return self.markers.get(key)

        async def xpending_range(self, *_args, **_kwargs):
            return [{"times_delivered": 1}]

        async def xadd(self, stream, payload):
            assert stream == "cyberassess:scan-execution:failures"
            self.failures.append(dict(payload))
            return f"failure-{len(self.failures)}"

    redis = ConsumerRedis([
        # Reject a digest-valid but database-inconsistent envelope before the
        # first engine entry point is reached.
        ("message-handoff-tampered-before-launch", fields_for(tampered_binding)),
        ("message-handoff-1", fields_for(published_binding)),
        ("message-handoff-1-redelivery", fields_for(published_binding)),
        # The same class of tampering must also remain rejected after the
        # child has become terminal; it must not be treated as a replay.
        ("message-handoff-tampered-after-terminal", fields_for(tampered_binding)),
    ])
    queue = object.__new__(RedisDurableQueue)
    queue._redis = redis
    queue._consumer_name = "worker-real-handoff"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    async def handler(
        delivered_scan_id,
        delivered_organization_id,
        delivered_request_id,
        delivered_credentials,
        delivered_binding,
    ):
        await handle_consumed_scan(
            worker,
            local_executor,
            delivered_scan_id,
            delivered_organization_id,
            delivered_request_id,
            delivered_credentials,
            delivered_binding,
        )

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert engine_calls["count"] == 0
    assert redis.acks == []
    assert redis.failures[-1]["failure_category"] == "AUTHORITATIVE_DISPATCH"
    assert redis.failures[-1]["queue_binding_digest"] == tampered_binding.queue_binding_digest

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert engine_calls["count"] == 1
    first_snapshot = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert engine_calls["count"] == 1
    assert _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    ) == first_snapshot
    assert redis.acks == ["message-handoff-1", "message-handoff-1-redelivery"]

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert engine_calls["count"] == 1
    assert redis.acks == ["message-handoff-1", "message-handoff-1-redelivery"]
    assert redis.failures[-1]["failure_category"] == "AUTHORITATIVE_DISPATCH"
    assert redis.failures[-1]["authorization_request_id"] == seeded_manifest.scan_request_id
    assert redis.failures[-1]["queue_binding_digest"] == tampered_binding.queue_binding_digest


@pytest.mark.asyncio
async def test_live_redis_stream_transport_enforces_authoritative_delivery_boundary(
    monkeypatch,
):
    """Exercise the production queue against a real Redis Streams service.

    This vector intentionally covers transport behavior that a faithful fake
    cannot establish: Redis PEL delivery counters, redelivery, persistent
    quarantine state, explicit tenant-bound recovery, Lua-backed idempotency,
    and an on-wire binding tamper before handler entry.  It never invokes an
    assessment engine or an external scanner.
    """
    if not LIVE_REDIS_TEST_URL:
        if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
            pytest.fail("CYBERASSESS_LIVE_REDIS_TEST_URL is required in GitHub Actions")
        pytest.skip("CYBERASSESS_LIVE_REDIS_TEST_URL is required for live Redis Streams assurance")

    from app.core import queue as queue_module
    from app.core.queue import (
        DurableQueueIdentityConflict,
        _issue_authenticated_quarantine_authorization,
        QueueDispatchBinding,
        RedisDurableQueue,
    )

    queue = RedisDurableQueue(LIVE_REDIS_TEST_URL)
    suffix = uuid.uuid4().hex
    queue.stream_name = f"cyberassess:test:section-b:{suffix}"
    queue.consumer_group = f"cyberassess-test-workers-{suffix}"
    redis = queue._redis
    organization_id = f"org-live-redis-{suffix}"

    try:
        try:
            await redis.ping()
        except Exception as exc:
            pytest.fail(f"live Redis Streams assurance could not connect: {type(exc).__name__}")

        await queue._ensure_group()
        success_request_id = f"request-live-success-{suffix}"
        success_binding = QueueDispatchBinding.create(
            scan_id=f"scan-live-success-{suffix}",
            organization_id=organization_id,
            authorization_request_id=success_request_id,
            manifest_hash="a" * 64,
            execution_ids=(f"execution-live-success-{suffix}",),
            operation_ids=(f"operation-live-success-{suffix}",),
        )
        first_message_id = await queue.enqueue(
            success_binding.scan_id,
            organization_id,
            authorization_request_id=success_request_id,
            queue_binding=success_binding,
        )
        assert await queue.enqueue(
            success_binding.scan_id,
            organization_id,
            authorization_request_id=success_request_id,
            queue_binding=success_binding,
        ) == first_message_id

        conflicting_binding = QueueDispatchBinding.create(
            scan_id=success_binding.scan_id,
            organization_id=organization_id,
            authorization_request_id=success_request_id,
            manifest_hash="b" * 64,
            execution_ids=success_binding.execution_ids,
            operation_ids=success_binding.operation_ids,
        )
        with pytest.raises(DurableQueueIdentityConflict):
            await queue.enqueue(
                success_binding.scan_id,
                organization_id,
                authorization_request_id=success_request_id,
                queue_binding=conflicting_binding,
            )

        success_calls = []

        async def success_handler(*args):
            success_calls.append(args)

        assert await queue.consume_once(success_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert len(success_calls) == 1
        assert await queue.consume_once(success_handler, block_ms=0, reclaim_idle_ms=0) is False
        assert not await redis.xpending_range(
            queue.stream_name,
            queue.consumer_group,
            min=first_message_id,
            max=first_message_id,
            count=1,
        )

        monkeypatch.setattr(queue_module, "_QUEUE_MAX_DELIVERY_ATTEMPTS", 2)
        failure_request_id = f"request-live-failure-{suffix}"
        failure_binding = QueueDispatchBinding.create(
            scan_id=f"scan-live-failure-{suffix}",
            organization_id=organization_id,
            authorization_request_id=failure_request_id,
            manifest_hash="c" * 64,
            execution_ids=(f"execution-live-failure-{suffix}",),
            operation_ids=(f"operation-live-failure-{suffix}",),
        )
        failure_message_id = await queue.enqueue(
            failure_binding.scan_id,
            organization_id,
            authorization_request_id=failure_request_id,
            queue_binding=failure_binding,
        )
        failure_calls = []

        async def failing_handler(*args):
            failure_calls.append(args)
            raise RuntimeError("bounded live Redis handler failure")

        assert await queue.consume_once(failing_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert await queue.consume_once(failing_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert len(failure_calls) == 2
        pending = await redis.xpending_range(
            queue.stream_name,
            queue.consumer_group,
            min=failure_message_id,
            max=failure_message_id,
            count=1,
        )
        assert pending and pending[0]["times_delivered"] == 2
        quarantine_state_key = queue._quarantine_state_key(failure_message_id)
        quarantine_marker_key = queue._quarantine_key(failure_message_id)
        state = json.loads(await redis.get(quarantine_state_key))
        assert state["organization_id"] == organization_id
        assert state["authorization_request_id"] == failure_request_id
        assert await redis.get(quarantine_marker_key)
        failure_events = [
            fields
            for _event_id, fields in await redis.xrange(
                f"{queue.stream_name}:failures", min="-", max="+"
            )
            if fields.get("message_id") == failure_message_id
        ]
        assert len(failure_events) == 2
        quarantine_events = [
            fields for fields in failure_events if fields.get("quarantined") == "1"
        ]
        assert len(quarantine_events) == 1
        assert quarantine_events[0]["organization_id"] == organization_id
        assert quarantine_events[0]["authorization_request_id"] == failure_request_id
        assert quarantine_events[0]["queue_binding_digest"] == failure_binding.queue_binding_digest
        assert "credential_envelope" not in quarantine_events[0]

        await redis.delete(quarantine_marker_key)
        assert await queue.consume_once(failing_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert len(failure_calls) == 2
        assert await queue.acknowledge_quarantined(
            failure_message_id,
        operator=_issue_authenticated_quarantine_authorization(
                actor_id="live-redis-operator",
                organization_id=f"wrong-tenant-{suffix}",
                session_binding=f"session-{suffix}",
            ),
            authorization_request_id=failure_request_id,
        ) is False
        assert await queue.acknowledge_quarantined(
            failure_message_id,
        operator=_issue_authenticated_quarantine_authorization(
                actor_id="live-redis-operator",
                organization_id=organization_id,
                session_binding=f"session-{suffix}",
            ),
            authorization_request_id=failure_request_id,
        ) is True
        assert await redis.get(quarantine_state_key) is None
        recovery_events = [
            fields
            for _event_id, fields in await redis.xrange(
                f"{queue.stream_name}:failures", min="-", max="+"
            )
            if fields.get("message_id") == failure_message_id
            and fields.get("failure_category") == "AUTHORITATIVE_DISPATCH_RECOVERY"
        ]
        assert len(recovery_events) == 1
        assert recovery_events[0]["recovery_action"] == "ACKNOWLEDGED_AFTER_QUARANTINE"
        assert recovery_events[0]["recovery_actor"] == "live-redis-operator"
        assert recovery_events[0]["organization_id"] == organization_id
        assert recovery_events[0]["authorization_request_id"] == failure_request_id
        assert not await redis.xpending_range(
            queue.stream_name,
            queue.consumer_group,
            min=failure_message_id,
            max=failure_message_id,
            count=1,
        )

        tampered_request_id = f"request-live-tampered-{suffix}"
        tampered_binding = QueueDispatchBinding.create(
            scan_id=f"scan-live-tampered-{suffix}",
            organization_id=organization_id,
            authorization_request_id=tampered_request_id,
            manifest_hash="d" * 64,
            execution_ids=(f"execution-live-tampered-{suffix}",),
            operation_ids=(f"operation-live-tampered-{suffix}",),
        )
        tampered_message_id = await redis.xadd(
            queue.stream_name,
            {
                "message_kind": "AUTHORITATIVE_EXECUTION",
                "enqueued_at": "2026-09-11T00:00:00+00:00",
                "scan_id": tampered_binding.scan_id,
                "organization_id": organization_id,
                "authorization_request_id": tampered_request_id,
                "queue_binding_digest": tampered_binding.queue_binding_digest,
                "manifest_hash": "e" * 64,
                "execution_ids_json": tampered_binding.execution_ids_json,
                "operation_ids_json": tampered_binding.operation_ids_json,
                "queue_binding_schema_version": tampered_binding.schema_version,
            },
        )
        tamper_calls = []

        async def tamper_handler(*args):
            tamper_calls.append(args)

        assert await queue.consume_once(tamper_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert await queue.consume_once(tamper_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert not tamper_calls
        tampered_state_key = queue._quarantine_state_key(tampered_message_id)
        tampered_state = json.loads(await redis.get(tampered_state_key))
        assert tampered_state["message_kind"] == "AMBIGUOUS_UNCLASSIFIED"
        assert tampered_state["reason"] == "QUEUE_BINDING_REJECTED"
        assert all(
            field_name not in tampered_state
            for field_name in (
                "queue_binding_digest",
                "manifest_hash",
                "execution_ids",
                "operation_ids",
            )
        )
        await redis.delete(queue._quarantine_key(tampered_message_id))
        assert await queue.consume_once(tamper_handler, block_ms=0, reclaim_idle_ms=0) is True
        assert not tamper_calls
        assert await redis.xpending_range(
            queue.stream_name,
            queue.consumer_group,
            min=tampered_message_id,
            max=tampered_message_id,
            count=1,
        )
        assert await redis.get(tampered_state_key)
        assert await queue.acknowledge_quarantined(
            tampered_message_id,
            operator=_issue_authenticated_quarantine_authorization(
                actor_id="live-redis-operator",
                organization_id=f"wrong-tenant-{suffix}",
                session_binding=f"session-{suffix}",
            ),
            authorization_request_id=tampered_request_id,
        ) is False
        assert await redis.xpending_range(
            queue.stream_name,
            queue.consumer_group,
            min=tampered_message_id,
            max=tampered_message_id,
            count=1,
        )
        assert await redis.get(tampered_state_key)
        assert await queue.acknowledge_quarantined(
            tampered_message_id,
            operator=_issue_authenticated_quarantine_authorization(
                actor_id="live-redis-operator",
                organization_id=organization_id,
                session_binding=f"session-{suffix}",
            ),
            authorization_request_id=tampered_request_id,
        ) is True
        assert await redis.get(tampered_state_key) is None
        recovery_events = [
            fields for _event_id, fields in await redis.xrange(
                f"{queue.stream_name}:failures", min="-", max="+"
            )
            if fields.get("message_id") == tampered_message_id
            and fields.get("failure_category") == "AUTHORITATIVE_DISPATCH_RECOVERY"
        ]
        assert len(recovery_events) == 1
        assert recovery_events[0]["quarantine_reason"] == "QUEUE_BINDING_REJECTED"
        assert recovery_events[0]["queue_binding_digest"] == ""
        assert recovery_events[0]["manifest_hash"] == ""
        assert "credential_envelope" not in recovery_events[0]
        assert not await redis.xpending_range(
            queue.stream_name,
            queue.consumer_group,
            min=tampered_message_id,
            max=tampered_message_id,
            count=1,
        )
    finally:
        keys = [
            key async for key in redis.scan_iter(match=f"{queue.stream_name}:*")
        ]
        await redis.delete(queue.stream_name, *keys)
        await queue.close()


@pytest.mark.asyncio
async def test_real_worker_handoff_uses_manifest_authority_and_settles_without_external_process(
    seeded_manifest: SeededManifest,
    monkeypatch,
):
    """Exercise approval -> child claim -> worker handoff -> no-process settlement."""
    child_execution_id, worker, executor, engine_calls = await _run_real_no_process_terminal(
        seeded_manifest,
        monkeypatch,
    )
    run = seeded_manifest.database.get_execution_run(
        child_execution_id,
        seeded_manifest.organization_id,
    )
    ownership = seeded_manifest.database.get_process_ownership(
        child_execution_id,
        seeded_manifest.organization_id,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert run["state"] == "EXECUTION_BLOCKED"
    assert run["reason_code"] == "PROCESS_LAUNCH_REJECTED_SECURITY"
    assert run["process_id"] is None
    assert ownership["ownership_state"] == "NO_EXTERNAL_PROCESS"
    assert ownership["no_process_proof"].startswith("NO_EXTERNAL_PROCESS:v2:")
    assert binding["dispatch_state"] == "BLOCKED"
    persisted_scan = seeded_manifest.database.get_scan_record(
        seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
    )
    assert persisted_scan.status == ScanStatus.COMPLETED
    assert persisted_scan.summary.coverage.coverage_status == "COVERAGE_DEGRADED"
    assert "nmap: BLOCKED" in persisted_scan.summary.coverage.coverage_limitations

    from app.core.queue import QueueDispatchBinding

    terminal_queue_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash=seeded_manifest.manifest_hash,
        execution_ids=(binding["child_execution_id"],),
        operation_ids=(seeded_manifest.operation_id,),
    )

    # A second delivery of the same terminal child must be fenced before the
    # engine entry point.  The terminal dispatch state is authoritative and
    # must not be reinterpreted as a new execution opportunity.
    await worker.execute_dispatched_scan(
        seeded_manifest.scan_id,
        seeded_manifest.organization_id,
        seeded_manifest.scan_request_id,
        executor=executor,
        queue_binding=terminal_queue_binding,
    )
    assert engine_calls["count"] == 1


@pytest.mark.asyncio
async def test_real_worker_handoff_replays_posix_termination_proof_read_only(
    seeded_manifest: SeededManifest,
    monkeypatch,
):
    """A supported POSIX termination proof is replayed without re-execution."""
    child_execution_id, worker, _executor, engine_calls = await _run_real_posix_terminal(
        seeded_manifest,
        monkeypatch,
    )
    run = seeded_manifest.database.get_execution_run(
        child_execution_id,
        seeded_manifest.organization_id,
    )
    ownership = seeded_manifest.database.get_process_ownership(
        child_execution_id,
        seeded_manifest.organization_id,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert run["state"] == "FAILED"
    assert run["reason_code"] == "PROCESS_EXIT_NONZERO"
    assert run["process_id"] == 4242
    assert run["process_group_id"] == "4242"
    assert ownership["ownership_state"] == "TERMINAL"
    assert ownership["container_type"] == "POSIX_SESSION"
    assert ownership["launch_commit_state"] == "COMMITTED"
    assert ownership["identity_attestation"]
    assert ownership["no_process_proof"].startswith("TERMINATION_CONFIRMED:v2:")
    assert binding["dispatch_state"] == "FAILED"

    from app.core.queue import QueueDispatchBinding

    queue_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash=seeded_manifest.manifest_hash,
        execution_ids=(binding["child_execution_id"],),
        operation_ids=(seeded_manifest.operation_id,),
    )
    before_replay = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    await worker.execute_dispatched_scan(
        seeded_manifest.scan_id,
        seeded_manifest.organization_id,
        seeded_manifest.scan_request_id,
        executor=object(),
        queue_binding=queue_binding,
    )
    assert _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    ) == before_replay
    assert engine_calls["count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    ("attestation_payload_mismatch", "attestation_digest_mismatch"),
)
async def test_posix_terminal_replay_rejects_attestation_tampering_without_mutation(
    seeded_manifest: SeededManifest,
    monkeypatch,
    tamper: str,
):
    """POSIX replay requires both canonical attestation content and digest."""
    _child_execution_id, worker, _executor, engine_calls = await _run_real_posix_terminal(
        seeded_manifest,
        monkeypatch,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert binding is not None
    from app.core.queue import QueueDispatchBinding

    queue_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash=seeded_manifest.manifest_hash,
        execution_ids=(binding["child_execution_id"],),
        operation_ids=(seeded_manifest.operation_id,),
    )
    with seeded_manifest.database._connection_scope() as connection:
        ownership = connection.execute(
            "SELECT identity_attestation, no_process_proof "
            "FROM execution_process_ownership WHERE execution_id=? AND organization_id=?",
            (binding["child_execution_id"], seeded_manifest.organization_id),
        ).fetchone()
        assert ownership is not None
        if tamper == "attestation_payload_mismatch":
            attestation = json.loads(ownership["identity_attestation"])
            attestation["session_id"] = 4243
            connection.execute(
                "UPDATE execution_process_ownership SET identity_attestation=? "
                "WHERE execution_id=? AND organization_id=?",
                (
                    json.dumps(attestation, sort_keys=True, separators=(",", ":")),
                    binding["child_execution_id"],
                    seeded_manifest.organization_id,
                ),
            )
        elif tamper == "attestation_digest_mismatch":
            from app.core.execution_context import decode_execution_proof, encode_execution_proof

            proof_payload = decode_execution_proof(
                ownership["no_process_proof"],
                expected_proof_type="TERMINATION_CONFIRMED",
            )
            proof_payload["identity_attestation_digest"] = "0" * 64
            connection.execute(
                "UPDATE execution_process_ownership SET no_process_proof=? "
                "WHERE execution_id=? AND organization_id=?",
                (
                    encode_execution_proof("TERMINATION_CONFIRMED", proof_payload),
                    binding["child_execution_id"],
                    seeded_manifest.organization_id,
                ),
            )
        else:
            raise AssertionError(f"unknown POSIX replay tamper case: {tamper}")

    before_replay = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    with pytest.raises(RuntimeError, match="terminal replay proof"):
        await worker.execute_dispatched_scan(
            seeded_manifest.scan_id,
            seeded_manifest.organization_id,
            seeded_manifest.scan_request_id,
            executor=object(),
            queue_binding=queue_binding,
        )
    assert _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    ) == before_replay
    assert engine_calls["count"] == 1


def _empty_capabilities() -> SystemCapabilities:
    return SystemCapabilities(tools=[])


@pytest.mark.asyncio
async def test_terminal_replay_is_read_only_after_authority_expiry_consumption_and_revocation(
    seeded_manifest: SeededManifest,
    monkeypatch,
):
    """An exact terminal replay observes durable proof without active authority."""
    child_execution_id, worker, _executor, engine_calls = await _run_real_no_process_terminal(
        seeded_manifest,
        monkeypatch,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert binding is not None
    past = (utc_now() - timedelta(minutes=1)).isoformat()
    seeded_manifest.database.revoke_token(
        binding["child_decision_session_jti"],
        token_hash="terminal-replay-test-token",
        expires_at=past,
    )
    assert seeded_manifest.database.transition_scan_authorization_request(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        "REVOKED",
        seeded_manifest.user_id,
        reason_code="EXECUTION_CANCELLED",
    ) is True

    before_replay = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    from app.core.queue import QueueDispatchBinding

    terminal_queue_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash=seeded_manifest.manifest_hash,
        execution_ids=(binding["child_execution_id"],),
        operation_ids=(seeded_manifest.operation_id,),
    )
    await worker.execute_dispatched_scan(
        seeded_manifest.scan_id,
        seeded_manifest.organization_id,
        seeded_manifest.scan_request_id,
        executor=object(),
        queue_binding=terminal_queue_binding,
    )
    after_replay = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    assert after_replay == before_replay
    before_concurrent_replay = after_replay
    await asyncio.gather(
        worker.execute_dispatched_scan(
            seeded_manifest.scan_id,
            seeded_manifest.organization_id,
            seeded_manifest.scan_request_id,
            executor=object(),
            queue_binding=terminal_queue_binding,
        ),
        worker.execute_dispatched_scan(
            seeded_manifest.scan_id,
            seeded_manifest.organization_id,
            seeded_manifest.scan_request_id,
            executor=object(),
            queue_binding=terminal_queue_binding,
        ),
    )
    assert _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    ) == before_concurrent_replay
    assert child_execution_id == binding["child_execution_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("invalidating_state", ("REVOKED", "EXPIRED", "CONSUMED"))
async def test_terminal_replay_uses_durable_parent_lifecycle_and_fresh_repository(
    seeded_manifest: SeededManifest,
    monkeypatch,
    invalidating_state: str,
):
    """Replay remains read-only after each durable parent invalidation state."""
    _child_execution_id, worker, _executor, engine_calls = await _run_real_no_process_terminal(
        seeded_manifest,
        monkeypatch,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert binding is not None
    from app.core.queue import QueueDispatchBinding

    queue_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash=seeded_manifest.manifest_hash,
        execution_ids=(binding["child_execution_id"],),
        operation_ids=(seeded_manifest.operation_id,),
    )
    if invalidating_state == "REVOKED":
        seeded_manifest.database.revoke_token(
            binding["child_decision_session_jti"],
            token_hash="durable-parent-lifecycle-token",
        )
    assert seeded_manifest.database.transition_scan_authorization_request(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        invalidating_state,
        seeded_manifest.user_id,
    ) is True

    with _fresh_database_manager(seeded_manifest.database) as fresh_database:
        fresh_parent = fresh_database.get_scan_authorization_request(
            seeded_manifest.scan_request_id,
            seeded_manifest.organization_id,
        )
        assert fresh_parent is not None
        assert fresh_parent["state"] == invalidating_state
        if invalidating_state == "REVOKED":
            assert fresh_database.is_token_revoked(binding["child_decision_session_jti"]) is True
        fresh_snapshot = _execution_lifecycle_snapshot(
            fresh_database,
            seeded_manifest.organization_id,
        )

        import app.core.orchestrator as orchestrator_module

        monkeypatch.setattr(orchestrator_module, "db_manager", fresh_database)
        monkeypatch.setattr(
            orchestrator_module,
            "get_scan",
            lambda scan_id, organization_id=None: fresh_database.get_scan_record(
                scan_id,
                organization_id=organization_id,
            ),
        )
        monkeypatch.setattr(orchestrator_module, "save_scan", fresh_database.save_scan_record)
        await worker.execute_dispatched_scan(
            seeded_manifest.scan_id,
            seeded_manifest.organization_id,
            seeded_manifest.scan_request_id,
            executor=object(),
            queue_binding=queue_binding,
        )
        assert engine_calls["count"] == 1
        assert _execution_lifecycle_snapshot(
            fresh_database,
            seeded_manifest.organization_id,
        ) == fresh_snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    (
        "missing_no_process_proof",
        "proof_version_mismatch",
        "proof_payload_mismatch",
        "proof_digest_mismatch",
        "ownership_generation_mismatch",
        "worker_identity_mismatch",
        "correlation_mismatch",
        "tenant_binding_mismatch",
        "manifest_binding_mismatch",
        "target_binding_mismatch",
        "recovery_last_error",
        "recovery_owner",
        "recovery_attempt_number",
        "recovery_last_outcome",
        "recovery_escalation_level",
        "missing_queue_binding",
        "queue_binding_mismatch",
    ),
)
async def test_terminal_replay_rejects_missing_or_mismatched_proof_without_mutation(
    seeded_manifest: SeededManifest,
    monkeypatch,
    tamper: str,
):
    """A terminal-looking delivery cannot bypass the complete proof tuple."""
    _child_execution_id, worker, _executor, engine_calls = await _run_real_no_process_terminal(
        seeded_manifest,
        monkeypatch,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert binding is not None
    from app.core.queue import QueueDispatchBinding

    queue_binding = QueueDispatchBinding.create(
        scan_id=seeded_manifest.scan_id,
        organization_id=seeded_manifest.organization_id,
        authorization_request_id=seeded_manifest.scan_request_id,
        manifest_hash=seeded_manifest.manifest_hash,
        execution_ids=(binding["child_execution_id"],),
        operation_ids=(seeded_manifest.operation_id,),
    )
    expected_error = "terminal replay proof"
    if tamper in {
        "missing_no_process_proof",
        "proof_version_mismatch",
        "proof_payload_mismatch",
        "proof_digest_mismatch",
    }:
        with seeded_manifest.database._connection_scope() as connection:
            if tamper == "missing_no_process_proof":
                altered_proof = None
            else:
                proof_row = connection.execute(
                    "SELECT no_process_proof FROM execution_process_ownership "
                    "WHERE execution_id=? AND organization_id=?",
                    (binding["child_execution_id"], seeded_manifest.organization_id),
                ).fetchone()
                assert proof_row is not None and proof_row["no_process_proof"]
                proof = str(proof_row["no_process_proof"])
                if tamper == "proof_version_mismatch":
                    altered_proof = proof.replace(":v2:", ":v1:", 1)
                elif tamper == "proof_digest_mismatch":
                    segments = proof.split(":", 3)
                    assert len(segments) == 4
                    digest_head = "0" if segments[2][0] != "0" else "1"
                    segments[2] = digest_head + segments[2][1:]
                    altered_proof = ":".join(segments)
                else:
                    from app.core.execution_context import decode_execution_proof, encode_execution_proof

                    payload = decode_execution_proof(
                        proof,
                        expected_proof_type="NO_EXTERNAL_PROCESS",
                    )
                    payload["correlation_id"] = "tampered-proof-correlation"
                    altered_proof = encode_execution_proof("NO_EXTERNAL_PROCESS", payload)
            connection.execute(
                "UPDATE execution_process_ownership SET no_process_proof=? "
                "WHERE execution_id=? AND organization_id=?",
                (altered_proof, binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif tamper == "ownership_generation_mismatch":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_process_ownership SET worker_generation=? "
                "WHERE execution_id=? AND organization_id=?",
                (
                    "different-worker-generation",
                    binding["child_execution_id"],
                    seeded_manifest.organization_id,
                ),
            )
    elif tamper == "worker_identity_mismatch":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_runs SET worker_identity=? "
                "WHERE execution_id=? AND organization_id=?",
                (
                    "tampered-worker-identity",
                    binding["child_execution_id"],
                    seeded_manifest.organization_id,
                ),
            )
        expected_error = "worker identity"
    elif tamper == "correlation_mismatch":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_process_ownership SET correlation_id=? "
                "WHERE execution_id=? AND organization_id=?",
                (
                    "tampered-replay-correlation",
                    binding["child_execution_id"],
                    seeded_manifest.organization_id,
                ),
            )
    elif tamper == "tenant_binding_mismatch":
        queue_binding = QueueDispatchBinding.create(
            scan_id=seeded_manifest.scan_id,
            organization_id="org-replay-attacker",
            authorization_request_id=seeded_manifest.scan_request_id,
            manifest_hash=seeded_manifest.manifest_hash,
            execution_ids=(binding["child_execution_id"],),
            operation_ids=(seeded_manifest.operation_id,),
        )
        expected_error = "queue dispatch binding"
    elif tamper == "manifest_binding_mismatch":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE scan_authorization_requests SET manifest_hash=? "
                "WHERE scan_request_id=? AND organization_id=?",
                (
                    "0" * 64,
                    seeded_manifest.scan_request_id,
                    seeded_manifest.organization_id,
                ),
            )
        expected_error = "manifest identity"
    elif tamper == "target_binding_mismatch":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE scan_authorization_requests SET target_id=? "
                "WHERE scan_request_id=? AND organization_id=?",
                (
                    "tampered-target-id",
                    seeded_manifest.scan_request_id,
                    seeded_manifest.organization_id,
                ),
            )
    elif tamper == "recovery_last_error":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_recovery_state SET last_error=? "
                "WHERE execution_id=? AND organization_id=?",
                ("tampered-recovery-error", binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif tamper == "recovery_owner":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_recovery_state SET owner=? "
                "WHERE execution_id=? AND organization_id=?",
                ("tampered-recovery-owner", binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif tamper == "recovery_attempt_number":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_recovery_state SET attempt_number=? "
                "WHERE execution_id=? AND organization_id=?",
                (1, binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif tamper == "recovery_last_outcome":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_recovery_state SET last_outcome=? "
                "WHERE execution_id=? AND organization_id=?",
                ("tampered-recovery-outcome", binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif tamper == "recovery_escalation_level":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_recovery_state SET escalation_level=? "
                "WHERE execution_id=? AND organization_id=?",
                (1, binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif tamper == "missing_queue_binding":
        queue_binding = None
        expected_error = "queue dispatch binding"
    elif tamper == "queue_binding_mismatch":
        queue_binding = QueueDispatchBinding.create(
            scan_id=seeded_manifest.scan_id,
            organization_id=seeded_manifest.organization_id,
            authorization_request_id=seeded_manifest.scan_request_id,
            manifest_hash="0" * 64,
            execution_ids=(binding["child_execution_id"],),
            operation_ids=(seeded_manifest.operation_id,),
        )
        expected_error = "queue dispatch binding"
    else:
        raise AssertionError(f"unknown replay tamper case: {tamper}")

    before_replay = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    with pytest.raises(RuntimeError, match=expected_error):
        await worker.execute_dispatched_scan(
            seeded_manifest.scan_id,
            seeded_manifest.organization_id,
            seeded_manifest.scan_request_id,
            executor=object(),
            queue_binding=queue_binding,
        )
    after_replay = _execution_lifecycle_snapshot(
        seeded_manifest.database,
        seeded_manifest.organization_id,
    )
    assert after_replay == before_replay
    assert engine_calls["count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_state",
    (
        "nonterminal_run",
        "partial_terminal_mapping",
        "uncertain_ownership",
        "recovery_blocked",
        "missing_ownership",
        "ambiguous_process_identity",
    ),
)
async def test_invalid_nonterminal_or_uncertain_replay_fails_closed(
    seeded_manifest: SeededManifest,
    monkeypatch,
    invalid_state: str,
):
    """Partial and uncertain lifecycle records never become replay no-ops."""
    _child_execution_id, worker, _executor, engine_calls = await _run_real_no_process_terminal(
        seeded_manifest,
        monkeypatch,
    )
    binding = seeded_manifest.database.get_scan_authorization_launch_binding(
        seeded_manifest.scan_request_id,
        seeded_manifest.organization_id,
        seeded_manifest.operation_id,
    )
    assert binding is not None
    if invalid_state == "nonterminal_run":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_runs SET state='RUNNING' "
                "WHERE execution_id=? AND organization_id=?",
                (binding["child_execution_id"], seeded_manifest.organization_id),
            )
    elif invalid_state == "partial_terminal_mapping":
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_dispatch_intents SET state='PENDING' "
                "WHERE execution_id=? AND organization_id=?",
                (binding["child_execution_id"], seeded_manifest.organization_id),
            )
    else:
        with seeded_manifest.database._connection_scope() as connection:
            if invalid_state == "uncertain_ownership":
                connection.execute(
                    "UPDATE execution_process_ownership "
                    "SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN', "
                    "no_process_proof=NULL "
                    "WHERE execution_id=? AND organization_id=?",
                    (binding["child_execution_id"], seeded_manifest.organization_id),
                )
            elif invalid_state == "recovery_blocked":
                connection.execute(
                    "UPDATE execution_process_ownership "
                    "SET ownership_state='RECOVERY_BLOCKED', launch_commit_state='UNCERTAIN', "
                    "no_process_proof=NULL "
                    "WHERE execution_id=? AND organization_id=?",
                    (binding["child_execution_id"], seeded_manifest.organization_id),
                )
            elif invalid_state == "missing_ownership":
                connection.execute(
                    "DELETE FROM execution_process_ownership "
                    "WHERE execution_id=? AND organization_id=?",
                    (binding["child_execution_id"], seeded_manifest.organization_id),
                )
            else:
                connection.execute(
                    "UPDATE execution_process_ownership "
                    "SET ownership_state='NO_EXTERNAL_PROCESS', root_process_id=? "
                    "WHERE execution_id=? AND organization_id=?",
                    (
                        4242,
                        binding["child_execution_id"],
                        seeded_manifest.organization_id,
                    ),
                )

    with pytest.raises(RuntimeError):
        await worker.execute_dispatched_scan(
            seeded_manifest.scan_id,
            seeded_manifest.organization_id,
            seeded_manifest.scan_request_id,
            executor=object(),
        )
    assert engine_calls["count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("negative", ("tenant_mismatch", "generation_mismatch", "revoked_child"))
async def test_real_worker_handoff_rejects_authority_fence_failures_before_engine(
    seeded_manifest: SeededManifest,
    monkeypatch,
    negative: str,
):
    child_execution_id = _approve_seeded_manifest(seeded_manifest, monkeypatch)
    import app.core.orchestrator as orchestrator_module
    from app.core.orchestrator import ScanOrchestrator

    monkeypatch.setattr(orchestrator_module, "db_manager", seeded_manifest.database)
    monkeypatch.setattr(
        orchestrator_module,
        "get_scan",
        lambda scan_id, organization_id=None: seeded_manifest.database.get_scan_record(
            scan_id,
            organization_id=organization_id,
        ),
    )
    monkeypatch.setattr(orchestrator_module, "save_scan", seeded_manifest.database.save_scan_record)
    engine_calls = 0
    engine = NetworkAssessmentEngine()

    async def unexpected_engine_run(*args, **kwargs):
        nonlocal engine_calls
        engine_calls += 1
        raise AssertionError("authority rejection must happen before engine execution")

    engine.run = unexpected_engine_run
    worker = ScanOrchestrator()
    worker.register_engine(engine)

    if negative == "tenant_mismatch":
        with pytest.raises(RuntimeError, match="no longer exists"):
            await worker.execute_dispatched_scan(
                seeded_manifest.scan_id,
                "org-not-authorized",
                seeded_manifest.scan_request_id,
                executor=object(),
            )
    elif negative == "generation_mismatch":
        import app.core.execution_service as execution_service

        monkeypatch.setattr(execution_service, "_PROCESS_WORKER_GENERATION", "stale-generation")
        with pytest.raises(RuntimeError, match="another worker generation"):
            await worker.execute_dispatched_scan(
                seeded_manifest.scan_id,
                seeded_manifest.organization_id,
                seeded_manifest.scan_request_id,
                executor=object(),
            )
    else:
        with seeded_manifest.database._connection_scope() as connection:
            connection.execute(
                "UPDATE execution_decisions SET revoked_at=? WHERE organization_id=? AND id=(SELECT approved_decision_id FROM execution_runs WHERE execution_id=?)",
                (utc_now().isoformat(), seeded_manifest.organization_id, child_execution_id),
            )
        with pytest.raises(RuntimeError, match="child execution decision is revoked"):
            await worker.execute_dispatched_scan(
                seeded_manifest.scan_id,
                seeded_manifest.organization_id,
                seeded_manifest.scan_request_id,
                executor=object(),
            )

    assert engine_calls == 0
