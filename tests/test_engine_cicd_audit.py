"""
Unit tests for Engine 5: CI/CD Pipeline & Build Security Auditor.
"""

import shutil
import tempfile
from pathlib import Path
import pytest

from app.core.models import Target, TargetType, ScanConfig, Severity
from app.engines.cicd_audit.github_actions_auditor import audit_workflow_yaml, audit_github_workflows
from app.engines.cicd_audit.engine import CicdAuditAssessmentEngine


def test_workflow_auditor_rules():
    insecure_workflow = """
name: CI
on:
  pull_request_target:

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: "${{ github.event.pull_request.head.sha }}"

      - name: Untrusted echo
        run: echo "PR title: ${{ github.event.pull_request.title }}"
"""
    findings = audit_workflow_yaml(insecure_workflow, ".github/workflows/ci.yml")
    check_ids = [f.check_id for f in findings]

    assert "CICD-GHA-001" in check_ids  # pull_request_target checkout
    assert "CICD-GHA-002" in check_ids  # uses: actions/checkout@v3 (not 40-char SHA)
    assert "CICD-GHA-003" in check_ids  # Script injection via PR title
    assert "CICD-GHA-004" in check_ids  # permissions: write-all


@pytest.mark.asyncio
async def test_cicd_audit_engine_full_run():
    engine = CicdAuditAssessmentEngine()
    assert engine.name == "cicd_audit"
    assert engine.is_applicable(Target(name="Repo", type=TargetType.LOCAL_PATH, value=".")) is True
    assert engine.is_applicable(Target(name="URL", type=TargetType.URL, value="https://example.com")) is False

    temp_dir = Path(tempfile.mkdtemp())
    try:
        wf_dir = temp_dir / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        sample_wf = wf_dir / "secure_ci.yml"
        sample_wf.write_text("""
name: Secure CI
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@435614f15d18d09874e0d1647f299e31788b5f43 # v4.1.7
      - run: npm test
""", encoding="utf-8")

        target = Target(name="CI Repo", type=TargetType.LOCAL_PATH, value=str(temp_dir))
        config = ScanConfig()

        logs = []
        progress_updates = []
        findings_emitted = []

        async def log_cb(lvl, msg):
            logs.append((lvl, msg))

        async def prog_cb(pct, stg):
            progress_updates.append((pct, stg))

        async def find_cb(f):
            findings_emitted.append(f)

        findings = await engine.run(target, config, log_cb, prog_cb, find_cb)
        assert findings == []
        assert len(progress_updates) >= 2
        assert progress_updates[-1][0] == 100
    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_cicd_audit_engine_propagates_authoritative_scan_id(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        """
name: CI
on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo \"${{ github.event.pull_request.title }}\"
""",
        encoding="utf-8",
    )

    async def noop(*_args):
        return None

    findings = await CicdAuditAssessmentEngine().run(
        Target(name="CI Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path)),
        ScanConfig(),
        noop,
        noop,
        noop,
        scan_id="scan-cicd-propagation",
    )

    assert findings
    assert all(finding.scan_id == "scan-cicd-propagation" for finding in findings)
