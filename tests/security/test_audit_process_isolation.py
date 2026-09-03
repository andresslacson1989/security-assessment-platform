"""Process ownership assurance for the 2026-09-03 audit closure."""

from __future__ import annotations

import asyncio

import pytest

from app.core.process_supervisor import (
    ProcessSupervisor,
    current_execution_context_id,
    process_execution_context,
)
from app.core.queue import ScanQueueManager


def test_kill_context_never_targets_another_scan(monkeypatch):
    supervisor = ProcessSupervisor()
    killed = []
    monkeypatch.setattr(supervisor, "kill_process_tree", lambda pid: killed.append(pid))

    supervisor._register_pid(101, "scan-a")
    supervisor._register_pid(102, "scan-a")
    supervisor._register_pid(201, "scan-b")

    supervisor.kill_context("scan-a")
    assert set(killed) == {101, 102}
    assert 201 not in killed


def test_global_shutdown_is_explicit_and_can_target_all_contexts(monkeypatch):
    supervisor = ProcessSupervisor()
    killed = []
    monkeypatch.setattr(supervisor, "kill_process_tree", lambda pid: killed.append(pid))
    supervisor._register_pid(101, "scan-a")
    supervisor._register_pid(201, "scan-b")

    supervisor.kill_all_processes()
    assert set(killed) == {101, 201}


def test_nested_process_context_restores_previous_owner():
    assert current_execution_context_id() is None
    with process_execution_context("scan-a"):
        assert current_execution_context_id() == "scan-a"
        with process_execution_context("scan-b"):
            assert current_execution_context_id() == "scan-b"
        assert current_execution_context_id() == "scan-a"
    assert current_execution_context_id() is None


@pytest.mark.asyncio
async def test_scan_queue_propagates_scan_id_as_process_owner():
    queue = ScanQueueManager(max_concurrent=2, max_concurrent_per_tenant=2)

    async def task():
        await asyncio.sleep(0)
        return current_execution_context_id()

    owner = await queue.execute_bounded(
        "scan-owned-context",
        task,
        organization_id="org-one",
    )
    assert owner == "scan-owned-context"


def test_pid_registry_removes_context_when_last_pid_finishes():
    supervisor = ProcessSupervisor()
    supervisor._register_pid(101, "scan-a")
    supervisor._register_pid(102, "scan-a")
    supervisor._unregister_pid(101)
    assert supervisor.active_pids_for_context("scan-a") == {102}
    supervisor._unregister_pid(102)
    assert supervisor.active_pids_for_context("scan-a") == set()
