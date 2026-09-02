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
    LogLevel,
    Finding,
    Evidence,
    RejectedDiscovery,
    calculate_fingerprint,
)
from app.core.auth import create_access_token
from app.core.storage import save_scan
from app.core.db import db_manager
from app.core.orchestrator import orchestrator
from starlette.requests import Request


@pytest.fixture
def auth_headers():
    user = UserProfile(id="usr-test-01", username="admin", email="admin@sec.local", role=UserRole.ADMIN)
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_system_endpoints(auth_headers):
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
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert "default-src 'self'" in resp.headers["content-security-policy"]

        # 2. Engines catalog
        assert (await ac.get("/api/system/engines")).status_code == 401
        resp_eng = await ac.get("/api/system/engines", headers=auth_headers)
        assert resp_eng.status_code == 200
        data_eng = resp_eng.json()
        assert data_eng["count"] == 5


@pytest.mark.asyncio
async def test_scan_correlation_id_propagates_to_job_logs_telemetry_and_audit(monkeypatch, auth_headers):
    """Contract 04: request correlation is retained across scan evidence surfaces."""
    captured = {}

    async def fake_start_scan(job):
        captured["job"] = job
        orchestrator._active_jobs[job.id] = job
        await orchestrator.emit_log(job.id, LogLevel.INFO, "test", "scan created")
        return asyncio.create_task(asyncio.sleep(0))

    monkeypatch.setattr(orchestrator, "start_scan", fake_start_scan)
    correlation_id = "corr-contract-04"
    payload = {
        "target_type": "DOMAIN",
        "target_value": "example.com",
        "profile": "QUICK",
        "enabled_engines": [],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/scans/start",
            json=payload,
            headers={**auth_headers, "X-Correlation-ID": correlation_id},
        )
        assert response.status_code == 201
        job = captured["job"]
        assert job.correlation_id == correlation_id
        assert job.logs[0].correlation_id == correlation_id

        telemetry = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert telemetry.status_code == 200
        assert telemetry.json()["correlation_id"] == correlation_id

        audit_events, _ = db_manager.list_audit_events(organization_id=job.organization_id)
        scan_events = [event for event in audit_events if event.object_id == job.id]
        assert scan_events
        assert all(event.correlation_id == correlation_id for event in scan_events)

    orchestrator._active_jobs.pop(job.id, None)


@pytest.mark.asyncio
async def test_scan_asset_binding_carries_explicit_intrusive_authorization(monkeypatch, auth_headers):
    captured = {}

    async def fake_start_scan(job):
        captured["job"] = job
        return asyncio.create_task(asyncio.sleep(0))

    monkeypatch.setattr(orchestrator, "start_scan", fake_start_scan)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={
                "name": "Authorized probe target",
                "type": "IP_ADDRESS",
                "target_value": "192.168.1.50",
                "active_probing_granted": True,
            },
            headers=auth_headers,
        )
        assert asset_response.status_code == 201
        asset_id = asset_response.json()["id"]

        start_response = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "IP",
                "target_value": "192.168.1.50",
                "asset_id": asset_id,
                "enabled_engines": [],
            },
            headers=auth_headers,
        )
        assert start_response.status_code == 201
        job = captured["job"]
        assert job.asset_id == asset_id
        assert job.active_probing_granted is True

        mismatch = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "IP",
                "target_value": "192.168.1.51",
                "asset_id": asset_id,
                "enabled_engines": [],
            },
            headers=auth_headers,
        )
        assert mismatch.status_code == 400


@pytest.mark.asyncio
async def test_unexpected_api_errors_are_generic_and_correlated():
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/test",
        "headers": [(b"x-correlation-id", b"corr-test-123")],
        "query_string": b"",
        "server": ("test", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 1),
    })
    request.state.correlation_id = "corr-test-123"
    from app.main import handle_unexpected_exception

    response = await handle_unexpected_exception(request, RuntimeError("secret filesystem path"))
    assert response.status_code == 500
    assert response.body == b'{"error_code":"INTERNAL_ERROR","message":"An internal server error occurred.","correlation_id":"corr-test-123"}'
    assert b"secret filesystem path" not in response.body


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
        rejected_discoveries=[RejectedDiscovery(
            domain="outside.example.net",
            reason="OUT_OF_SCOPE",
            sources=["crtsh"],
            authorized_root="example.com",
            assessment_id="sse-rejected-evidence",
            organization_id="org-default",
        )],
    )
    job.summary = calculate_scan_grade([], duration_seconds=1.0)
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        query_token_resp = await ac.get(f"/api/scans/{job.id}/events?token={auth_headers['Authorization'].split(' ', 1)[1]}")
        assert query_token_resp.status_code == 401

        async with ac.stream("GET", f"/api/scans/{job.id}/events", headers=auth_headers) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            
            lines = []
            async for line in resp.aiter_lines():
                if line:
                    lines.append(line)
            
            assert len(lines) >= 2
            assert any("event: completed" in l or "event: connected" in l for l in lines)
            assert any("event: discovery_rejected" in l for l in lines)


@pytest.mark.asyncio
async def test_live_scan_sse_streaming(auth_headers):
    from app.core.orchestrator import orchestrator
    from app.core.models import LogLevel
    scan_id = "test-live-sse-stream"
    job = ScanJob(
        id=scan_id,
        target=Target(name="Live SSE", type=TargetType.URL, value="https://live.test"),
        status=ScanStatus.RUNNING,
    )
    orchestrator._active_jobs[scan_id] = job

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Start SSE stream in background
        async def read_stream():
            received = []
            async with ac.stream("GET", f"/api/scans/{scan_id}/events", headers=auth_headers) as resp:
                assert resp.status_code == 200
                async for line in resp.aiter_lines():
                    if line:
                        received.append(line)
                    if "event: completed" in line or "event: cancelled" in line:
                        break
            return received

        stream_task = asyncio.create_task(read_stream())
        await asyncio.sleep(0.05)

        # Broadcast live progress, log, and cancelled
        await orchestrator.emit_progress(scan_id, 25, "Running network scanner...")
        await orchestrator.emit_log(scan_id, LogLevel.INFO, "network", "Port 80 is open")
        await orchestrator.emit_cancelled(scan_id, "Scan cancelled by user.")

        lines = await asyncio.wait_for(stream_task, timeout=5.0)
        assert any("event: progress" in l for l in lines)
        assert any("Running network scanner" in l for l in lines)
        assert any("event: log" in l for l in lines)
        assert any("Port 80 is open" in l for l in lines)
        assert any("event: cancelled" in l for l in lines)



@pytest.mark.asyncio
async def test_telemetry_endpoint_structure_and_filters(auth_headers):
    from app.core.models import LogEntry, LogLevel, Finding, Evidence, DiscoveredEndpoint, DiscoveredSubdomain, ToolFailureEvent
    target = Target(name="Telemetry Target", type=TargetType.URL, value="https://telemetry-test.local")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        active_adapters=["nmap", "nuclei", "katana"],
        tool_execution_states={"schemathesis": "TOOL_EXECUTION_FAILED"},
        tool_failure_events=[ToolFailureEvent(tool_name="schemathesis", engine="web_dast", state="TOOL_EXECUTION_FAILED")],
        logs=[
            LogEntry(level=LogLevel.INFO, engine="network", tool="nmap", message="Nmap detected open port 443"),
            LogEntry(level=LogLevel.WARNING, engine="web_dast", tool="nuclei", message="Nuclei detected CVE-2024-9999"),
            LogEntry(level=LogLevel.ERROR, engine="code_sast", tool="semgrep", message="Semgrep parse failure in file"),
        ],
        discovered_endpoints=[
            DiscoveredEndpoint(url="https://telemetry-test.local/login", method="GET", status_code=200, depth=1)
        ],
        discovered_subdomains=[
            DiscoveredSubdomain(domain="api.telemetry-test.local", ip_addresses=["10.0.0.1"], is_takeover_vulnerable=False)
        ],
        findings=[
            Finding(
                scan_id="scan-telemetry-run",
                engine="web_dast",
                source_tool="nuclei",
                check_id="CVE-2024-9999",
                category="Injection",
                title="SQL Injection Vulnerability",
                severity=Severity.HIGH,
                cvss_score=8.5,
                description="SQLi vulnerability detected",
                impact="Database compromise",
                remediation="Use parameterized queries",
                evidence=Evidence(location="https://telemetry-test.local/api/users", observed_value="error in SQL", expected_value="clean")
            )
        ]
    )
    job.summary.coverage.coverage_status = "COVERAGE_DEGRADED"
    job.summary.coverage.is_fully_assessed = False
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Unauthenticated request -> 401
        res_unauth = await ac.get(f"/api/scans/{job.id}/telemetry")
        assert res_unauth.status_code == 401

        # 2. Authenticated request -> 200 with full structure
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["scan_id"] == job.id
        assert data["target_value"] == "https://telemetry-test.local"
        assert data["total_logs"] == 3
        assert len(data["logs"]) == 3
        assert len(data["discovered_endpoints"]) == 1
        assert len(data["discovered_subdomains"]) == 1
        # Host availability is not proof of execution. Only recorded tool
        # states or findings belong in executed-tool telemetry.
        assert {item["tool_name"] for item in data["tools_executed"]} == {"nuclei", "schemathesis"}
        schemathesis = next(item for item in data["tools_executed"] if item["tool_name"] == "schemathesis")
        assert schemathesis["status"] == "FAILED"
        assert schemathesis["normalized_state"] == "TOOL_EXECUTION_FAILED"
        nuclei = next(item for item in data["tools_executed"] if item["tool_name"] == "nuclei")
        assert nuclei["status"] == "FINDINGS"
        assert nuclei["engine"] == "web_dast"
        assert data["coverage"]["coverage_status"] == "COVERAGE_DEGRADED"
        assert data["tool_failure_events"] == [
            {
                "tool_name": "schemathesis",
                "engine": "web_dast",
                "state": "TOOL_EXECUTION_FAILED",
                "correlation_id": None,
                "occurred_at": data["tool_failure_events"][0]["occurred_at"],
            }
        ]

        # A finding emitted before a later tool failure is partial evidence;
        # it must not make the failed execution look successful.
        job.tool_execution_states["nuclei"] = "TOOL_EXECUTION_FAILED"
        save_scan(job)
        degraded = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        degraded_nuclei = next(
            item for item in degraded.json()["tools_executed"] if item["tool_name"] == "nuclei"
        )
        assert degraded_nuclei["status"] == "FAILED"

        # 3. Filter by tool=nuclei
        res_tool = await ac.get(f"/api/scans/{job.id}/telemetry?tool=nuclei", headers=auth_headers)
        assert res_tool.status_code == 200
        data_tool = res_tool.json()
        assert len(data_tool["logs"]) == 1
        assert "Nuclei detected" in data_tool["logs"][0]["message"]

        # 4. Filter by level=ERROR
        res_lvl = await ac.get(f"/api/scans/{job.id}/telemetry?level=ERROR", headers=auth_headers)
        assert res_lvl.status_code == 200
        data_lvl = res_lvl.json()
        assert len(data_lvl["logs"]) == 1
        assert "Semgrep parse failure" in data_lvl["logs"][0]["message"]

        # 5. Search query
        res_search = await ac.get(f"/api/scans/{job.id}/telemetry?search=open port", headers=auth_headers)
        assert res_search.status_code == 200
        data_search = res_search.json()
        assert len(data_search["logs"]) == 1
        assert "open port 443" in data_search["logs"][0]["message"]


@pytest.mark.asyncio
async def test_finding_occurrences_endpoint_is_tenant_scoped(auth_headers):
    """Contract 04 §1.4: occurrence history is durable and cannot cross tenants."""
    from app.core.db import db_manager

    scan_id = "occurrence-api-scan"
    job = ScanJob(
        id=scan_id,
        organization_id="org-default",
        target=Target(name="Occurrence API", type=TargetType.URL, value="https://occurrence.test"),
        profile=ScanProfile.FULL_STACK,
        findings=[
            Finding(
                scan_id=scan_id,
                engine="web_dast",
                source_tool="nuclei",
                check_id="DAST-OCC-001",
                category="Test",
                title="Occurrence API finding",
                severity=Severity.MEDIUM,
                cvss_score=5.0,
                description="Test finding",
                impact="Test impact",
                remediation="Test remediation",
                evidence=Evidence(
                    location="https://occurrence.test",
                    observed_value="observed",
                    expected_value="expected",
                ),
            )
        ],
    )
    save_scan(job)
    with db_manager._connection_scope() as conn:
        row = conn.execute(
            "SELECT id FROM findings WHERE scan_id = ? AND organization_id = ?",
            (scan_id, "org-default"),
        ).fetchone()
    assert row is not None
    finding_id = row["id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(f"/api/findings/{finding_id}/occurrences", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == finding_id
        assert data["total"] == 1
        assert data["items"][0]["organization_id"] == "org-default"
        assert data["items"][0]["source_tool"] == "nuclei"

        other_tenant = UserProfile(
            id="usr-occurrence-other",
            username="other-tenant",
            email="other-tenant@example.test",
            role=UserRole.ADMIN,
            organization_id="org-other",
        )
        other_headers = {"Authorization": f"Bearer {create_access_token(other_tenant)}"}
        denied = await ac.get(f"/api/findings/{finding_id}/occurrences", headers=other_headers)
        assert denied.status_code == 404


@pytest.mark.asyncio
async def test_asset_creation_all_supported_types(auth_headers):
    """
    Verifies that all supported AssetType values (WEB_APPLICATION, API_ENDPOINT,
    DOMAIN, IP_ADDRESS, GIT_REPOSITORY, CONTAINER_IMAGE) pass security policy validation.
    """
    test_cases = [
        ("virtualhymn", "WEB_APPLICATION", "https://vh.pixelretrobooth.com"),
        ("users-api", "API_ENDPOINT", "https://api.pixelretrobooth.com/v1"),
        ("main-domain", "DOMAIN", "pixelretrobooth.com"),
        ("production-node", "IP_ADDRESS", "93.184.216.34"),
        ("backend-repo", "GIT_REPOSITORY", "https://github.com/example/security-platform.git"),
        ("api-container", "CONTAINER_IMAGE", "cyberassess/core-engine:v13.0.0"),
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for name, a_type, target_val in test_cases:
            payload = {
                "name": name,
                "type": a_type,
                "target_value": target_val,
                "criticality": "HIGH",
            }
            res = await ac.post("/api/assets", json=payload, headers=auth_headers)
            assert res.status_code == 201, f"Failed for {a_type}: {res.text}"
            data = res.json()
            assert data["name"] == name
            assert data["type"] == a_type
            assert data["target_value"] == target_val


@pytest.mark.asyncio
async def test_per_link_assessment_dossier_structure(auth_headers):
    """
    Verifies that the /telemetry endpoint enriches discovered endpoints with:
    1. Executed tools per link.
    2. Performed security test records (SQLi, XSS, Headers, CORS, CSRF).
    3. Finding ID correlations for that specific URL.
    """
    target = Target(name="Dossier App", type=TargetType.URL, value="https://dossier-test.local")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        active_adapters=["nuclei"],
        discovered_endpoints=[
            DiscoveredEndpoint(
                url="https://dossier-test.local/admin/settings",
                method="GET",
                depth=1,
                status_code=200,
                content_type="text/html",
                is_authenticated=True,
                has_forms=True,
                discovered_forms=2,
            )
        ],
        findings=[
            Finding(
                scan_id="scan-dossier-1",
                engine="web_dast",
                source_tool="native_dast",
                check_id="DAST-HDR-001",
                category="Configuration",
                title="Missing Content Security Policy (CSP)",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description="No CSP header found",
                impact="XSS vulnerability",
                remediation="Configure CSP header",
                evidence=Evidence(location="https://dossier-test.local/admin/settings", observed_value="No CSP", expected_value="CSP present")
            )
        ]
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        endpoints = data["discovered_endpoints"]
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep["url"] == "https://dossier-test.local/admin/settings"
        assert len(ep["finding_ids"]) == 1
        assert len(ep["tools_executed"]) >= 3
        assert "nuclei" not in ep["tools_executed"], "availability must not masquerade as endpoint execution"
        assert len(ep["tests_performed"]) >= 4
        # Verify test records contain test name, category, tool, and status
        test_names = [t["test_name"] for t in ep["tests_performed"]]
        assert any("Security Headers" in name for name in test_names)
        assert any("CORS" in name for name in test_names)
        assert any("Injection" in name for name in test_names)


@pytest.mark.asyncio
async def test_subfinder_discovery_remains_passive_and_unresolved():
    """Subfinder discovery must not perform DNS resolution or claim active state."""
    from unittest.mock import AsyncMock, patch
    from app.adapters.subfinder_adapter import SubfinderAdapter
    from app.core.models import TargetType, ScanConfig

    adapter = SubfinderAdapter()
    target = Target(name="Passive discovery", type=TargetType.DOMAIN, value="dns.google")
    config = ScanConfig()
    discovered = []

    async def capture_discovery(item):
        discovered.append(item)

    with patch.object(adapter, "resolve_binary_path", return_value="/managed/subfinder"), \
         patch.object(adapter, "verify_managed_binary", return_value=True), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="subfinder v2.6.5")), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(
             0, '{"host":"api.dns.google","sources":["crtsh"]}\n', ""
         ))):
        findings = await adapter.run(target, config, AsyncMock(), AsyncMock(), emit_subdomain=capture_discovery)

    assert len(findings) == 1
    assert discovered[0].dns_status == "UNRESOLVED"
    assert discovered[0].ip_addresses == []
    assert not hasattr(adapter, "_resolve_host_dns")
