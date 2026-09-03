"""
E13.6 — Adversarial Acceptance Tests for Enterprise Execution Egress Closure & Subprocess Env Sanitization.
Validates:
- Subprocess environment contains NO application or cloud secrets (JWT_SECRET, DATABASE_URL, etc.).
- Subprocess environment contains only whitelisted safe system variables.
- SCANNER_EGRESS_PROXY is properly propagated to subprocess proxy variables when set.
- Ambient host proxy variables are purged and NOT inherited when SCANNER_EGRESS_PROXY is unset.
- Real subprocess execution receives only sanitized environment.
- Docker Compose enforces network segmentation (data-plane internal: true, no published DB/cache ports).
"""

import os
import sys
import json
import yaml
from unittest.mock import patch
import pytest

from app.core.process_supervisor import ProcessSupervisor
from app.adapters.base_adapter import BaseToolAdapter


def test_supervisor_environment_sanitization_blocks_secrets():
    """Environment sanitization strictly purges application secrets and credentials."""
    # Set simulated sensitive variables in ambient os.environ
    test_secrets = {
        "JWT_SECRET": "ultra-sensitive-jwt-secret-do-not-leak",
        "DATABASE_URL": "postgresql://user:password@internal-db:5432/cyberassess",
        "REDIS_URL": "redis://:secretpassword@internal-redis:6379/0",
        "CLOUD_CREDENTIALS_ENCRYPTION_KEY": "base64secretkey1234567890=",
        "API_KEY_SECRET": "cyber_live_abcdef123456",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
    
    for k, v in test_secrets.items():
        os.environ[k] = v

    try:
        sanitized = ProcessSupervisor.sanitize_environment()

        # None of the secrets must appear in sanitized dict
        for k in test_secrets:
            assert k not in sanitized, f"Secret {k} leaked into sanitized environment!"

        # Essential runtime keys must be preserved
        assert "PATH" in sanitized
        if sys.platform == "win32":
            assert "SYSTEMROOT" in sanitized
    finally:
        for k in test_secrets:
            os.environ.pop(k, None)


def test_scanner_egress_proxy_propagation_when_configured():
    """When SCANNER_EGRESS_PROXY is configured, tools receive standard proxy variables."""
    os.environ["SCANNER_EGRESS_PROXY"] = "http://egress-proxy.corp.internal:8080"
    try:
        sanitized = ProcessSupervisor.sanitize_environment()
        assert sanitized.get("HTTP_PROXY") == "http://egress-proxy.corp.internal:8080"
        assert sanitized.get("HTTPS_PROXY") == "http://egress-proxy.corp.internal:8080"
        assert sanitized.get("ALL_PROXY") == "http://egress-proxy.corp.internal:8080"
        assert sanitized.get("http_proxy") == "http://egress-proxy.corp.internal:8080"
    finally:
        os.environ.pop("SCANNER_EGRESS_PROXY", None)


def test_ambient_host_proxy_purged_when_no_scanner_proxy():
    """Ambient host proxy variables must NOT leak to subprocess when SCANNER_EGRESS_PROXY is unset."""
    os.environ.pop("SCANNER_EGRESS_PROXY", None)
    os.environ["HTTP_PROXY"] = "http://rogue-host-proxy.local:3128"
    os.environ["http_proxy"] = "http://rogue-host-proxy.local:3128"
    try:
        sanitized = ProcessSupervisor.sanitize_environment()
        assert "HTTP_PROXY" not in sanitized
        assert "http_proxy" not in sanitized
        assert "HTTPS_PROXY" not in sanitized
    finally:
        os.environ.pop("HTTP_PROXY", None)
        os.environ.pop("http_proxy", None)


@pytest.mark.asyncio
async def test_real_subprocess_execution_does_not_receive_secrets():
    """A real subprocess execution receives zero application secrets."""
    os.environ["DATABASE_URL"] = "postgresql://attacker:injected@db.local/test"
    os.environ["JWT_SECRET"] = "super-secret-runtime-token"
    
    supervisor = ProcessSupervisor.get_instance()
    cmd = [sys.executable, "-c", "import os, json; print(json.dumps(dict(os.environ)))"]

    try:
        res = await supervisor.execute(cmd, timeout=10.0, execution_id="test-env-exec")
        assert res.returncode == 0
        child_env = json.loads(res.stdout)

        assert "DATABASE_URL" not in child_env
        assert "JWT_SECRET" not in child_env
        assert "PATH" in child_env
    finally:
        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("JWT_SECRET", None)


def test_docker_compose_network_segmentation():
    """Docker Compose configuration strictly isolates database and cache networks."""
    compose_path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    # 1. Verify networks definition
    networks = compose.get("networks", {})
    assert "data-plane" in networks
    assert networks["data-plane"].get("internal") is True, "data-plane network must be internal-only!"

    # 2. Verify postgres service isolation
    services = compose.get("services", {})
    assert "postgres" in services
    pg = services["postgres"]
    assert pg.get("networks") == ["data-plane"]
    assert "ports" not in pg, "Postgres must not publish host ports!"

    # 3. Verify redis service isolation
    assert "redis" in services
    redis = services["redis"]
    assert redis.get("networks") == ["data-plane"]
    assert "ports" not in redis, "Redis must not publish host ports!"


@pytest.mark.asyncio
async def test_enterprise_mode_fails_closed_without_verified_egress_facility():
    """
    R2.3 Invariant:
    Under ENTERPRISE mode / egress enforcement required, ProcessSupervisor MUST fail closed
    and reject process launch unless a verified egress facility is explicitly configured.
    """
    supervisor = ProcessSupervisor.get_instance()
    cmd = [sys.executable, "-c", "print('hello')"]

    # 1. Without verified egress facility configured -> MUST FAIL CLOSED
    with patch.dict(os.environ, {"OPERATING_MODE": "ENTERPRISE", "CYBERASSESS_VERIFIED_EGRESS_FACILITY": ""}):
        res = await supervisor.execute(cmd, timeout=5.0)
        assert res.returncode == -1
        assert "PROCESS_LAUNCH_REJECTED_SECURITY" in res.stderr
        assert "egress network enforcement facility is not configured" in res.stderr

    # 2. With verified egress facility configured -> Launch proceeds
    with patch.dict(os.environ, {"OPERATING_MODE": "ENTERPRISE", "CYBERASSESS_VERIFIED_EGRESS_FACILITY": "egress-gw-v1"}):
        res = await supervisor.execute(cmd, timeout=5.0)
        assert res.returncode == 0
        assert "hello" in res.stdout

