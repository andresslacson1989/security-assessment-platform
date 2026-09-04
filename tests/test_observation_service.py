import asyncio

import pytest

from app.core.observation_service import BackendObservationService


@pytest.mark.asyncio
async def test_refresh_once_is_single_flight(monkeypatch):
    calls = 0

    async def fake_capabilities(**kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)

    class FakeManager:
        @classmethod
        def get_instance(cls):
            return cls()

        async def get_all_tools_info(self, **kwargs):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.02)

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", fake_capabilities)
    monkeypatch.setattr("app.core.observation_service.ToolInstallationManager", FakeManager)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    results = await asyncio.gather(service.refresh_once(), service.refresh_once())

    assert sum(results) == 1
    assert calls == 2
    assert service.state.last_completed_at is not None
    assert service.state.last_error is None


@pytest.mark.asyncio
async def test_refresh_failure_is_recorded_and_does_not_raise(monkeypatch):
    async def failed_capabilities(**kwargs):
        raise RuntimeError("probe unavailable")

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", failed_capabilities)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.refresh_once() is False
    assert service.state.last_completed_at is None
    assert "RuntimeError" in service.state.last_error


@pytest.mark.asyncio
async def test_service_stops_and_awaits_task(monkeypatch):
    async def successful_refresh(**kwargs):
        return None

    class FakeManager:
        @classmethod
        def get_instance(cls):
            return cls()

        async def get_all_tools_info(self, **kwargs):
            return []

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", successful_refresh)
    monkeypatch.setattr("app.core.observation_service.ToolInstallationManager", FakeManager)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)
    task = service.start()
    await asyncio.sleep(0)
    await service.stop()

    assert task.done()
    assert not service.running


@pytest.mark.asyncio
async def test_application_lifespan_owns_observation_service(monkeypatch):
    from app import main

    events = []

    class FakeService:
        def __init__(self):
            events.append("constructed")

        def start(self):
            events.append("started")
            return None

        async def stop(self):
            events.append("stopped")

    monkeypatch.setattr(main, "BackendObservationService", FakeService)
    async with main.lifespan(main.app):
        assert events == ["constructed", "started"]
    assert events == ["constructed", "started", "stopped"]
