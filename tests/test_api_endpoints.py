"""
Integration test suite for FastAPI REST endpoints and SSE streaming (v10.0.0).
"""

import asyncio
import json
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.version import APP_VERSION
from app.core.models import (
    TargetType,
    ScanProfile,
    ScanStatus,
    ScanJob,
    Target,
    Severity,
    AuthType,
    AuthConfig,
    CrawlerConfig,
    DiscoveredEndpoint,
    UserProfile,
    UserRole,
    calculate_fingerprint,
)
from app.core.auth import create_access_token
from app.core.storage import save_scan
from app.core.orchestrator import orchestrator


@pytest.fixture
def auth_headers():
    user = UserProfile(id="usr-test-01", username="admin", email="admin@sec.local", role=UserRole.ADMIN)
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_system_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Health check
        resp = await ac.get("/api/system/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "HEALTHY"
        assert data["version"] == APP_VERSION
        assert "uptime_seconds" in data
        assert "storage" in data
        assert data["storage"]["status"] == "OK"

        # 2. Engines catalog
        resp_eng = await ac.get("/api/system/engines")
        assert resp_eng.status_code == 200
        data_eng = resp_eng.json()
        assert data_eng["count"] == 5


@pytest.mark.asyncio
async def test_scan_lifecycle_api(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Start scan with invalid URL
        bad_resp = await ac.post("/api/scans/start", json={
            "target_type": "URL",
            "target_value": "not-a-url",
        }, headers=auth_headers)
        assert bad_resp.status_code == 400

        # 2. Start valid scan with crawler & auth config
        start_resp = await ac.post("/api/scans/start", json={
            "target_type": "URL",
            "target_value": "https://example.com",
            "target_name": "Test Site",
            "profile": "CUSTOM",
            "enabled_engines": [],
            "config": {
                "crawler": {
                    "enabled": True,
                    "max_depth": 2,
                    "max_pages": 15,
                },
                "auth": {
                    "auth_type": "HEADER",
                    "headers": {"Authorization": "Bearer test-token"},
                }
            }
        }, headers=auth_headers)
        assert start_resp.status_code == 201
        start_data = start_resp.json()
        scan_id = start_data["scan_id"]
        assert scan_id is not None

        # Give orchestrator task a moment to update
        await asyncio.sleep(0.05)

        # 3. Get scan details snapshot
        get_resp = await ac.get(f"/api/scans/{scan_id}", headers=auth_headers)
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert get_data["id"] == scan_id
        assert get_data["target"]["name"] == "Test Site"
        assert "discovered_endpoints" in get_data
        assert "pages_crawled" in get_data["summary"]
        assert "authenticated_session_active" in get_data["summary"]

        # 4. List scan history
        hist_resp = await ac.get("/api/scans/history?limit=10&offset=0", headers=auth_headers)
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert hist_data["total"] >= 1

        # 5. Cancel scan endpoint
        cancel_resp = await ac.post(f"/api/scans/{scan_id}/cancel", headers=auth_headers)
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "CANCELLED"

        # 6. Delete scan
        del_resp = await ac.delete(f"/api/scans/{scan_id}", headers=auth_headers)
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted"] is True


@pytest.mark.asyncio
async def test_export_endpoints(auth_headers):
    target = Target(name="Export Test App", type=TargetType.URL, value="https://example.com")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. HTML export
        html_resp = await ac.get(f"/api/scans/{job.id}/export/html", headers=auth_headers)
        assert html_resp.status_code == 200
        assert "text/html" in html_resp.headers["content-type"]
        assert "attachment;" in html_resp.headers["content-disposition"]
        assert "<!DOCTYPE html>" in html_resp.text

        # 2. SARIF export
        sarif_resp = await ac.get(f"/api/scans/{job.id}/export/sarif", headers=auth_headers)
        assert sarif_resp.status_code == 200
        assert "application/json" in sarif_resp.headers["content-type"]
        sarif_json = sarif_resp.json()
        assert sarif_json["version"] == "2.1.0"

        # 3. JSON export
        json_resp = await ac.get(f"/api/scans/{job.id}/export/json", headers=auth_headers)
        assert json_resp.status_code == 200
        raw_json = json_resp.json()
        assert raw_json["id"] == job.id


@pytest.mark.asyncio
async def test_sse_streaming_endpoint(auth_headers):
    from app.core.grading import calculate_scan_grade
    target = Target(name="SSE Target", type=TargetType.URL, value="https://example.com")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
    )
    job.summary = calculate_scan_grade([], duration_seconds=1.0)
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        async with ac.stream("GET", f"/api/scans/{job.id}/events", headers=auth_headers) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            
            lines = []
            async for line in resp.aiter_lines():
                if line:
                    lines.append(line)
            
            assert len(lines) >= 2
            assert any("event: completed" in l or "event: connected" in l for l in lines)
