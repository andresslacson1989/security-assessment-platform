"""Deployment regression checks for the hardened execution containers."""

from pathlib import Path
import os
import re
import subprocess
import sys

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_all_runtime_services_use_hardened_container_defaults():
    compose = yaml.safe_load((REPOSITORY_ROOT / "docker-compose.yml").read_text())

    for service_name in ("cyberassess", "cyberassess-enterprise", "cyberassess-worker"):
        service = compose["services"][service_name]
        assert service["mem_limit"] == "2g"
        assert service["cpus"] == "2.0"
        assert service["pids_limit"] == 256
        assert service["ulimits"]["nofile"] == {"soft": 4096, "hard": 8192}
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["tmpfs"] == ["/tmp:rw,noexec,nosuid,nodev"]


def test_runtime_writable_state_is_explicitly_provisioned():
    compose = yaml.safe_load((REPOSITORY_ROOT / "docker-compose.yml").read_text())

    for service_name in ("cyberassess", "cyberassess-enterprise", "cyberassess-worker"):
        service = compose["services"][service_name]
        volumes = service["volumes"]
        assert any(str(volume).startswith("./data:/app/data") for volume in volumes)


def test_enterprise_compose_separates_data_and_execution_networks():
    compose = yaml.safe_load((REPOSITORY_ROOT / "docker-compose.yml").read_text())
    networks = compose["networks"]

    assert networks["data-plane"]["internal"] is True
    assert "ports" not in compose["services"]["postgres"]
    assert "ports" not in compose["services"]["redis"]

    worker_networks = set(compose["services"]["cyberassess-worker"]["networks"])
    assert worker_networks == {"data-plane", "execution-egress"}
    assert "ports" not in compose["services"]["cyberassess-worker"]

    api_networks = set(compose["services"]["cyberassess-enterprise"]["networks"])
    assert api_networks == {"control-plane", "data-plane", "provider-egress"}


def test_compose_documents_external_egress_control_as_required():
    deployment_doc = (REPOSITORY_ROOT / "docs" / "DOCKER_COMPOSE_DEPLOYMENT.md").read_text()
    assert "do not provide a dynamic, per-tenant" in deployment_doc
    assert "destination allowlist" in deployment_doc
    assert "assured external-tool execution" in deployment_doc
    assert "default-deny external traffic" in deployment_doc


def test_managed_artifacts_are_not_owned_by_runtime_user():
    """Trust records and executables must remain outside the worker's write set."""
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()
    ownership_line = next(
        line for line in dockerfile.splitlines() if "chown -R cyberassess:cyberassess" in line
    )
    assert ownership_line.strip() == "chown -R cyberassess:cyberassess /app/data"
    assert "/app/backend" not in ownership_line
    assert "/opt/cyberassess/tool-venvs" not in ownership_line


def test_managed_trust_records_are_readable_but_immutable():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()
    assert "find /app/backend /opt/cyberassess/tool-venvs -type f -name '*.trust.json' -exec chmod 0644 {} +" in dockerfile


def test_ci_verifies_the_hash_locked_runtime_dependency_set():
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "contract-verification.yml").read_text()
    assert 'python-version: "3.11"' in workflow
    assert "cache: pip" not in workflow
    assert "cache-dependency-path:" not in workflow
    assert "python -m pip install --no-cache-dir --require-hashes --requirement backend/requirements.lock" in workflow
    assert "backend/requirements.txt" not in workflow


def test_dockerfile_has_explicit_legacy_builder_platform_defaults():
    """The CT108 legacy builder must not receive an empty platform argument."""
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()
    first_from = dockerfile.index("FROM --platform=$BUILDPLATFORM")
    build_platform_arg = dockerfile.index("ARG BUILDPLATFORM=linux/amd64")
    target_arch_arg = dockerfile.index("ARG TARGETARCH=amd64")

    assert build_platform_arg < first_from
    assert target_arch_arg > first_from


def test_dockerfile_serializes_trivy_source_compilation():
    """The constrained deployment builder must bound Go compiler parallelism."""
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()
    trivy_build = dockerfile[
        dockerfile.index("go build") : dockerfile.index("go build") + 140
    ]

    assert "go build -p=1" in trivy_build


def test_ci_workflow_static_contract_is_complete():
    workflow_path = REPOSITORY_ROOT / ".github" / "workflows" / "contract-verification.yml"
    workflow_text = workflow_path.read_text().replace("\r\n", "\n")
    workflow = yaml.safe_load(workflow_text)
    triggers = workflow.get("on") or workflow.get(True) or {}

    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    for trigger_name in ("push", "pull_request"):
        assert triggers[trigger_name]["branches"] == ["security/nmap-installer-closure"]

    assert set(workflow["jobs"]) == {
        "compile-backend",
        "focused-contract-verification",
        "full-repository-verification",
        "postgres-schema-assurance",
        "container",
        "windows-job-object-assurance",
    }
    focused_job = workflow["jobs"]["focused-contract-verification"]
    assert focused_job["services"]["redis"]["image"] == "redis:7.2-alpine"
    assert focused_job["services"]["redis"]["ports"] == ["6379:6379"]
    assert focused_job["services"]["postgres"]["image"] == "postgres:16-alpine"
    assert focused_job["services"]["postgres"]["ports"] == ["5432:5432"]
    assert "--health-cmd=\"redis-cli ping\"" in workflow_text
    assert "--health-cmd=\"pg_isready -U cyberassess_ci -d cyberassess_ci\"" in workflow_text
    assert focused_job["env"]["CYBERASSESS_LIVE_REDIS_TEST_URL"] == "redis://127.0.0.1:6379/15"
    assert focused_job["env"]["CYBERASSESS_POSTGRES_TEST_URL"].endswith("/cyberassess_ci")
    assert focused_job["env"]["CYBERASSESS_POSTGRES_TEST_ACK"] == "I_UNDERSTAND_DISPOSABLE_DATABASE_MUTATION"
    assert workflow["jobs"]["full-repository-verification"]["services"]["postgres"]["image"] == "postgres:16-alpine"
    full_job = workflow["jobs"]["full-repository-verification"]
    assert full_job["services"]["redis"]["image"] == "redis:7.2-alpine"
    assert full_job["services"]["redis"]["ports"] == ["6379:6379"]
    assert full_job["env"]["CYBERASSESS_LIVE_REDIS_TEST_URL"] == "redis://127.0.0.1:6379/15"
    windows_job = workflow["jobs"]["windows-job-object-assurance"]
    assert windows_job["runs-on"] == "windows-2022"
    assert windows_job["timeout-minutes"] == 20
    assert windows_job["env"]["CYBERASSESS_WORKER_IDENTITY"] == "ci-windows-worker"
    assert "${{ github.run_id }}" in windows_job["env"]["CYBERASSESS_WORKER_GENERATION"]
    assert windows_job["env"]["CI_ROOT"].endswith("/windows-job-object-assurance")
    assert windows_job["env"]["CI_REPORT_DIR"].endswith("/windows-job-object-assurance/reports")
    assert windows_job["env"]["CI_PYTEST_BASETEMP"].endswith("/windows-job-object-assurance/pytest")
    assert windows_job["env"]["CYBERASSESS_DB_PATH"].endswith("/windows-job-object-assurance/cyberassess.db")
    assert any(
        step.get("name") == "Reject Windows assurance skips"
        for step in windows_job["steps"]
        if isinstance(step, dict)
    )
    assert any(
        step.get("name") == "Upload Windows assurance evidence"
        and step.get("if") == "${{ always() }}"
        for step in windows_job["steps"]
        if isinstance(step, dict)
    )
    assert "tests/security/test_real_dispatch_authority_assurance.py" in workflow_text
    for job_id in ("focused-contract-verification", "full-repository-verification"):
        checkout_step = next(
            step for step in workflow["jobs"][job_id]["steps"]
            if step.get("name") == "Check out source"
        )
        assert checkout_step.get("with", {}).get("fetch-depth") == 0
    assert re.search(r"^permissions:\s*$\n\s+contents:\s+read\s*$", workflow_text, re.MULTILINE)

    action_refs = re.findall(r"^\s+uses:\s+([^\s#]+)", workflow_text, re.MULTILINE)
    assert action_refs
    action_names_and_shas = [reference.rsplit("@", 1) for reference in action_refs]
    assert all(len(parts) == 2 for parts in action_names_and_shas)
    assert {parts[0] for parts in action_names_and_shas} == {
        "actions/checkout",
        "actions/setup-python",
        "actions/upload-artifact",
    }
    assert all(re.fullmatch(r"[0-9a-f]{40}", parts[1]) for parts in action_names_and_shas)

    assert "RUNNER_TEMP" not in workflow_text
    assert "runner.temp" not in workflow_text
    assert not re.search(r"^\s+cache:", workflow_text, re.MULTILINE)
    assert not re.search(r"^\s+cache-dependency-path:", workflow_text, re.MULTILINE)
    project_template = "${{ github.workspace }}/.project-temp/contract-verification-${{ github.run_id }}/"
    for job_id in (
        "compile-backend",
        "focused-contract-verification",
        "full-repository-verification",
        "postgres-schema-assurance",
    ):
        job_env = workflow["jobs"][job_id]["env"]
        job_root = project_template + job_id
        assert job_env["CI_ROOT"] == job_root
        assert job_env["CI_REPORT_DIR"] == f"{job_root}/reports"
        assert job_env["CI_PYTEST_BASETEMP"] == f"{job_root}/pytest"
        assert any(
            step.get("name") == "Set project-local CI paths"
            for step in workflow["jobs"][job_id]["steps"]
            if isinstance(step, dict)
        )
        for key, value in job_env.items():
            if key in {"CYBERASSESS_DB_PATH", "FULL_EVIDENCE_DIR", "POSTGRES_EVIDENCE_DIR"}:
                assert str(value).startswith(job_root + "/")
    assert workflow_text.count('>> "$GITHUB_ENV"') == 4
    assert workflow_text.count('python -m pytest -p no:cacheprovider -q') == 4
    assert workflow_text.count('--basetemp="$PYTEST_BASETEMP"') == 3
    assert workflow_text.count('path: ${{ env.CI_REPORT_DIR }}/') == 4
    assert "CYBERASSESS_POSTGRES_TEST_URL is required for the isolated PostgreSQL integration suite" not in workflow_text
    for line in workflow_text.splitlines():
        if "/tmp" in line:
            assert "--tmpfs /tmp:" in line or "$CI_ROOT/tmp" in line
    for job_id in (
        "focused-contract-verification",
        "full-repository-verification",
        "postgres-schema-assurance",
    ):
        assert any(
            step.get("name") == "Set project-local CI paths"
            for step in workflow["jobs"][job_id]["steps"]
            if isinstance(step, dict)
        )
    assert "CYBERASSESS_POSTGRES_TEST_URL: postgresql://" in workflow_text
    assert "focused-contract.xml" in workflow_text
    assert "full-suite.xml" in workflow_text
    assert "postgres-suite.xml" in workflow_text
    assert workflow_text.count("if-no-files-found: error") == 4
    assert workflow_text.count("retention-days: 14") == 4
    assert '"--basetemp=$env:CI_PYTEST_BASETEMP"' in workflow_text
    assert "test_windows_job_atomic_assignment_and_descendant_termination" in workflow_text
    assert "test_windows_worker_crash_kill_on_close_blocks_durable_reattachment" in workflow_text
    assert "test_windows_supervisor_cancellation_requires_attested_identity" in workflow_text


def _extract_workflow_guard(workflow: str, step_name: str) -> str:
    lines = workflow.replace("\r\n", "\n").splitlines()
    step_start = next(index for index, line in enumerate(lines) if line.strip() == f"- name: {step_name}")
    next_step = next(
        (index for index in range(step_start + 1, len(lines)) if lines[index].startswith("      - name:")),
        len(lines),
    )
    start = next(index for index in range(step_start, next_step) if lines[index].strip() == "python - <<'PY'")
    end = next(index for index in range(start + 1, next_step) if lines[index].strip() == "PY")
    return "\n".join(line[10:] if line.startswith("          ") else line for line in lines[start + 1:end])


def test_contract_workflow_has_governed_trigger_and_executable_postgres_skip_guard(tmp_path):
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "contract-verification.yml").read_text()
    assert "branches: [security/nmap-installer-closure]" in workflow
    assert "workflow_dispatch:" in workflow
    assert "raise SystemExit(f\"PostgreSQL assurance contained {skipped} skipped test(s)\") if skipped else None" not in workflow
    assert "Reject unexpected focused-test skips" in workflow
    assert "historical a1c4fc4 fixture is blocked by its committed v1 artifact mismatch" in workflow
    assert "backend/tests/test_execution_launch_inventory.py" in workflow
    assert "tests/security/test_execution_decision_authority.py" in workflow
    assert "tests/security/test_execution_cancellation_coordinator.py" in workflow
    assert "tests/security/test_scan_request_migration.py" in workflow

    guard = _extract_workflow_guard(workflow, "Reject dependency-gated PostgreSQL skips")
    compile(guard, "contract-verification-postgres-skip-guard", "exec")

    evidence_dir = tmp_path / "postgres-evidence"
    evidence_dir.mkdir()
    environment = os.environ.copy()
    environment["POSTGRES_EVIDENCE_DIR"] = str(evidence_dir)

    (evidence_dir / "postgres-suite.xml").write_text('<testsuite tests="1" skipped="0" failures="0"/>')
    zero_skips = subprocess.run(
        [sys.executable, "-c", guard],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert zero_skips.returncode == 0, zero_skips.stderr

    (evidence_dir / "postgres-suite.xml").write_text('<testsuite tests="1" skipped="1" failures="0"/>')
    one_skip = subprocess.run(
        [sys.executable, "-c", guard],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert one_skip.returncode != 0
    assert "PostgreSQL assurance contained 1 skipped test(s)" in one_skip.stderr

    focused_guard = _extract_workflow_guard(workflow, "Reject unexpected focused-test skips")
    compile(focused_guard, "contract-verification-focused-skip-guard", "exec")
    focused_dir = tmp_path / "cyberassess-focused-reports"
    focused_dir.mkdir()
    focused_environment = os.environ.copy()
    focused_environment["CI_REPORT_DIR"] = str(focused_dir)
    focused_report_dir = focused_dir
    (focused_report_dir / "focused-contract.xml").write_text(
        '<testsuite tests="1" skipped="1" failures="0"><testcase><skipped '
        'message="historical a1c4fc4 fixture is blocked by its committed v1 artifact mismatch"/>'
        "</testcase></testsuite>"
    )
    allowed_skip = subprocess.run(
        [sys.executable, "-c", focused_guard],
        env=focused_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed_skip.returncode == 0, allowed_skip.stderr

    (focused_report_dir / "focused-contract.xml").write_text(
        '<testsuite tests="1" skipped="1" failures="0"><testcase><skipped '
        'message="new unexpected skip"/></testcase></testsuite>'
    )
    unexpected_skip = subprocess.run(
        [sys.executable, "-c", focused_guard],
        env=focused_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert unexpected_skip.returncode != 0
    assert "new unexpected skip" in unexpected_skip.stderr

    full_guard = _extract_workflow_guard(workflow, "Classify full-suite skips")
    compile(full_guard, "contract-verification-full-skip-classifier", "exec")
    full_dir = tmp_path / "cyberassess-full-reports"
    full_dir.mkdir()
    full_environment = os.environ.copy()
    full_environment["FULL_EVIDENCE_DIR"] = str(full_dir)
    allowed_reasons = (
        "UNAVAILABLE: approved managed Subfinder v2.6.5 binary is not installed",
        "Managed nmap binary not present on this dev machine",
        "Symlinks require elevated privileges on Windows",
        "Symlink creation is unavailable in this environment",
        "Unix process sessions are not available on Windows",
        "historical a1c4fc4 fixture is blocked by its committed v1 artifact mismatch",
    )
    skipped_cases = "".join(
        f'<testcase><skipped message="{reason}"/></testcase>'
        for reason in allowed_reasons
    )
    (full_dir / "full-suite.xml").write_text(
        f"<testsuite tests=\"{len(allowed_reasons)}\" skipped=\"{len(allowed_reasons)}\">"
        f"{skipped_cases}</testsuite>"
    )
    classified = subprocess.run(
        [sys.executable, "-c", full_guard],
        env=full_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert classified.returncode == 0, classified.stderr
    classification = (full_dir / "full-suite-skip-classification.txt").read_text()
    assert "total_skips=6" in classification
    assert "PROVENANCE_BLOCKED_ESCALATION_REQUIRED" in classification

    (full_dir / "full-suite.xml").write_text(
        '<testsuite tests="1" skipped="1"><testcase><skipped '
        'message="CYBERASSESS_POSTGRES_TEST_URL is required for the isolated PostgreSQL integration suite"/>'
        "</testcase></testsuite>"
    )
    unclassified = subprocess.run(
        [sys.executable, "-c", full_guard],
        env=full_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert unclassified.returncode != 0
    assert "CYBERASSESS_POSTGRES_TEST_URL" in unclassified.stderr


def test_ci_builds_and_smoke_tests_the_hardened_production_image():
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "contract-verification.yml").read_text()
    assert "name: Hardened production image verification" in workflow
    assert "docker build --tag cyberassess-contract-runtime ." in workflow
    assert "--cap-drop=ALL" in workflow
    assert "--security-opt=no-new-privileges" in workflow
    assert "--user cyberassess" in workflow
    assert "-c 'test \"$(id -u)\" -ne 0" in workflow
    assert "test ! -w /app/backend/bin/subfinder.trust.json" in workflow


def test_schemathesis_isolated_environment_is_not_installed_in_app_runtime():
    requirements = (REPOSITORY_ROOT / "backend" / "requirements.txt").read_text()
    lock = (REPOSITORY_ROOT / "backend" / "requirements.lock").read_text()
    assert "schemathesis" not in requirements.lower()
    assert not any(line.startswith("schemathesis==") for line in lock.splitlines())
    assert (REPOSITORY_ROOT / "backend" / "tool-requirements" / "schemathesis.lock").is_file()
