"""Ensure every external-tool launch remains behind ProcessSupervisor."""

from __future__ import annotations

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

from app.core.process_supervisor import (
    CredentialEnvironmentHandoff,
    ProcessExecutionStatus,
    ProcessSupervisor,
)


FORBIDDEN_IMPORTS = {"subprocess", "asyncio.subprocess"}
FORBIDDEN_CALLS = {
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("os", "system"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
}


def test_adapters_and_engines_have_no_direct_process_launches():
    repository_root = Path(__file__).resolve().parents[2]
    source_roots = (
        repository_root / "backend" / "app" / "adapters",
        repository_root / "backend" / "app" / "engines",
    )
    violations = []
    for source_root in source_roots:
        for path in source_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in FORBIDDEN_IMPORTS:
                            violations.append(f"{path}:{node.lineno}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if module in FORBIDDEN_IMPORTS:
                        violations.append(f"{path}:{node.lineno}: from {module} import ...")
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        call = (node.func.value.id, node.func.attr)
                        if call in FORBIDDEN_CALLS:
                            violations.append(f"{path}:{node.lineno}: call {call[0]}.{call[1]}")

    assert violations == [], "Direct process launch detected outside ProcessSupervisor: " + "; ".join(violations)


@pytest.mark.asyncio
async def test_supervisor_child_observes_only_reviewed_environment(monkeypatch):
    """Exercise the production launch boundary and inspect the child environment."""
    monkeypatch.delenv("OPERATING_MODE", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENTERPRISE_EGRESS_ENFORCEMENT_REQUIRED", raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://ambient.invalid:8080")
    monkeypatch.setenv("SCANNER_EGRESS_PROXY", "http://scanner.example:3128")

    dangerous = {
        "API_KEY": "secret",
        "AUTH_TOKEN": "secret",
        "JWT_SECRET": "secret",
        "DATABASE_URL": "postgres://secret",
        "LD_PRELOAD": "/tmp/inject.so",
        "LD_LIBRARY_PATH": "/tmp/inject",
        "PYTHONPATH": "/tmp/inject",
        "PYTHONHOME": "/tmp/python",
        "NODE_OPTIONS": "--require /tmp/inject.js",
        "HTTP_PROXY": "http://caller.invalid:8080",
        "HTTPS_PROXY": "http://caller.invalid:8080",
        "ALL_PROXY": "http://caller.invalid:8080",
        "ARBITRARY_CALLER_VARIABLE": "must-not-cross",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "GOTOOLCHAIN": "local",
    }
    child_code = "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))"
    result = await ProcessSupervisor.get_instance().execute(
        [sys.executable, "-c", child_code],
        env=dangerous,
        scanner_egress_proxy="http://scanner.example:3128",
        timeout=10.0,
        max_output_bytes=1024 * 1024,
    )

    assert result.execution_status is ProcessExecutionStatus.COMPLETED
    observed = json.loads(result.stdout)
    for key in dangerous:
        if key in {
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT",
            "NPM_CONFIG_IGNORE_SCRIPTS", "GOTOOLCHAIN",
        }:
            continue
        if key == "LANG":
            assert observed[key] == "C.UTF-8"
        else:
            assert key not in observed
    for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS"):
        assert key not in observed
    assert observed["GIT_CONFIG_NOSYSTEM"] == "1"
    assert observed["GIT_TERMINAL_PROMPT"] == "0"
    assert observed["NPM_CONFIG_IGNORE_SCRIPTS"] == "true"
    assert observed["GOTOOLCHAIN"] == "local"
    assert observed["HTTP_PROXY"] == "http://scanner.example:3128"
    assert observed["HTTPS_PROXY"] == "http://scanner.example:3128"
    assert observed["ALL_PROXY"] == "http://scanner.example:3128"


@pytest.mark.asyncio
async def test_typed_credential_handoff_reaches_child_without_env_allowlist_bypass():
    """Only an authorized typed handoff may provide credential variables."""
    handoff = CredentialEnvironmentHandoff(
        organization_id="org-test",
        asset_id="asset-test",
        provider="aws",
        authorization_decision_id="decision-test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        credentials={
            "AWS_ACCESS_KEY_ID": "AKIA_TEST",
            "AWS_SECRET_ACCESS_KEY": "secret-test",
            "AWS_SESSION_TOKEN": "session-test",
        },
        allowed_keys=frozenset({
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        }),
    )
    child_code = "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))"
    result = await ProcessSupervisor.get_instance().execute(
        [sys.executable, "-c", child_code],
        env={
            "AWS_ACCESS_KEY_ID": "caller-value",
            "AWS_SECRET_ACCESS_KEY": "caller-value",
            "DATABASE_URL": "caller-value",
        },
        credential_handoff=handoff,
        timeout=10.0,
        max_output_bytes=1024 * 1024,
    )

    assert result.execution_status is ProcessExecutionStatus.COMPLETED
    observed = json.loads(result.stdout)
    assert observed["AWS_ACCESS_KEY_ID"] == "AKIA_TEST"
    assert observed["AWS_SECRET_ACCESS_KEY"] == "secret-test"
    assert observed["AWS_SESSION_TOKEN"] == "session-test"
    assert "DATABASE_URL" not in observed


def test_caller_cannot_override_supervisor_baseline():
    """Caller env may not replace process-resolution or runtime directories."""
    sanitized = ProcessSupervisor.sanitize_environment({
        "PATH": "caller-controlled",
        "SYSTEMROOT": "caller-controlled",
        "TEMP": "caller-controlled",
        "HOME": "caller-controlled",
        "TMPDIR": "caller-controlled",
    })
    for key, value in sanitized.items():
        if key in {"PATH", "SYSTEMROOT", "TEMP", "HOME", "TMPDIR"}:
            assert value != "caller-controlled"


def test_direct_caller_environment_inputs_are_explicit():
    """Prevent callers from reintroducing ambient environment wholesale."""
    repository_root = Path(__file__).resolve().parents[2]
    caller_files = (
        repository_root / "backend/app/engines/code_sast/git_history_scanner.py",
        repository_root / "backend/app/core/binary_resolver.py",
        repository_root / "backend/app/installers/github_release_installer.py",
        repository_root / "backend/app/installers/nmap_artifact_installer.py",
        repository_root / "backend/app/installers/npm_installer.py",
        repository_root / "backend/app/installers/source_build_installer.py",
        repository_root / "backend/app/installers/system_installer.py",
        repository_root / "backend/app/installers/pip_installer.py",
        repository_root / "backend/app/adapters/base_adapter.py",
        repository_root / "backend/app/adapters/prowler_adapter.py",
    )
    for path in caller_files:
        source = path.read_text(encoding="utf-8")
        assert "{**os.environ" not in source
        assert "os.environ.items()" not in source
    source_build = (repository_root / "backend/app/installers/source_build_installer.py").read_text(encoding="utf-8")
    assert 'env = {"HOME": temp, "PATH": os.environ.get("PATH", "")}' not in source_build
