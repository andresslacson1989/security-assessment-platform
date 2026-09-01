"""
Unit tests for Engine 4: Infrastructure-as-Code & Container Auditor.
"""

import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock
import pytest

from app.core.models import Target, TargetType, ScanConfig, Severity, NormalizedExecutionState
from app.engines.infra_iac.dockerfile_auditor import audit_dockerfile_content, audit_dockerfiles
from app.engines.infra_iac.compose_auditor import audit_compose_yaml, audit_compose_files
from app.engines.infra_iac.k8s_manifest_auditor import audit_k8s_yaml, audit_k8s_manifests
from app.engines.infra_iac.terraform_auditor import audit_terraform_file, audit_terraform_files
from app.engines.infra_iac.engine import InfraIacAssessmentEngine
from app.adapters.trivy_adapter import TrivyAdapter
from app.adapters.checkov_adapter import CheckovAdapter
from app.adapters.dockle_adapter import DockleAdapter
from app.adapters.kubebench_adapter import KubeBenchAdapter
from app.adapters.prowler_adapter import ProwlerAdapter


def test_dockerfile_auditor_rules():
    insecure_dockerfile = """
FROM node:latest
ENV DB_PASSWORD=supersecretpass
RUN apt-get update && apt-get install -y curl
RUN sudo make install
CMD ["node", "server.js"]
"""
    findings = audit_dockerfile_content(insecure_dockerfile, "Dockerfile")
    check_ids = [f.check_id for f in findings]

    assert "IAC-DOCK-001" in check_ids  # Missing non-root USER
    assert "IAC-DOCK-002" in check_ids  # Unpinned :latest
    assert "IAC-DOCK-003" in check_ids  # Missing HEALTHCHECK
    assert "IAC-DOCK-004" in check_ids  # Hardcoded secret in ENV
    assert "IAC-DOCK-005" in check_ids  # Apt cache retained
    assert "IAC-DOCK-006" in check_ids  # Sudo usage


def test_compose_auditor_rules():
    insecure_compose = """
version: '3.8'
services:
  app:
    image: myapp:1.0
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    image: mysql:8.0
    ports:
      - "3306:3306"
"""
    findings = audit_compose_yaml(insecure_compose, "docker-compose.yml")
    check_ids = [f.check_id for f in findings]

    assert "IAC-CMP-001" in check_ids  # privileged: true
    assert "IAC-CMP-002" in check_ids  # docker.sock mount
    assert "IAC-CMP-003" in check_ids  # 3306 exposed on 0.0.0.0


def test_k8s_manifest_auditor_rules():
    insecure_k8s = """
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: web
    image: nginx:1.21
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
"""
    findings = audit_k8s_yaml(insecure_k8s, "pod.yaml")
    check_ids = [f.check_id for f in findings]

    assert "IAC-K8S-001" in check_ids  # Privileged container
    assert "IAC-K8S-002" in check_ids  # hostPID / hostNetwork
    assert "IAC-K8S-003" in check_ids  # Missing readOnlyRootFilesystem
    assert "IAC-K8S-004" in check_ids  # Missing resource limits


def test_terraform_auditor_rules():
    insecure_tf = """
resource "aws_s3_bucket" "b" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_security_group" "allow_ssh" {
  name = "allow_ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "wildcard_admin" {
  name = "wildcard_admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
"""
    findings = audit_terraform_file(insecure_tf, "main.tf")
    check_ids = [f.check_id for f in findings]

    assert "IAC-TF-001" in check_ids  # Public S3 ACL
    assert "IAC-TF-002" in check_ids  # 0.0.0.0/0 on port 22
    assert "IAC-TF-003" in check_ids  # encrypted = false
    assert "IAC-TF-004" in check_ids  # Wildcard IAM Policy


@pytest.mark.asyncio
async def test_infra_iac_engine_full_run():
    engine = InfraIacAssessmentEngine()
    assert engine.name == "infra_iac"
    assert engine.is_applicable(Target(name="Manifest", type=TargetType.IAC_MANIFEST, value=".")) is True
    assert engine.is_applicable(Target(name="URL", type=TargetType.URL, value="https://example.com")) is False

    temp_dir = Path(tempfile.mkdtemp())
    try:
        # Create sample Dockerfile in temp dir
        df = temp_dir / "Dockerfile"
        df.write_text("FROM alpine:3.18\nUSER 1000\nHEALTHCHECK CMD true\n", encoding="utf-8")

        target = Target(name="IaC Repo", type=TargetType.LOCAL_PATH, value=str(temp_dir))
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
        assert len(progress_updates) >= 4
        assert progress_updates[-1][0] == 100
    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_infra_iac_trivy_uses_managed_execution_boundary(monkeypatch, tmp_path):
    """IaC execution must enforce the managed-tool trust boundary for Trivy."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:3.18\nUSER 1000\n", encoding="utf-8")
    config = ScanConfig(
        adapters={
            "enable_checkov": False,
            "enable_trivy": True,
            "enable_dockle": False,
            "enable_kube_bench": False,
            "enable_prowler": False,
            "enable_gtfobins": False,
        }
    )
    run_mock = AsyncMock(return_value=[])
    monkeypatch.setattr(TrivyAdapter, "is_available", AsyncMock(return_value=True))
    monkeypatch.setattr(TrivyAdapter, "run", run_mock)
    tool_states = []

    async def log_cb(*_args):
        return None

    async def progress_cb(*_args):
        return None

    async def finding_cb(*_args):
        return None

    async def tool_state_cb(tool, state):
        tool_states.append((tool, state))

    await InfraIacAssessmentEngine().run(
        Target(name="IaC Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path)),
        config,
        log_cb,
        progress_cb,
        finding_cb,
        emit_tool_execution_state=tool_state_cb,
    )

    assert run_mock.await_count == 1
    assert run_mock.await_args.kwargs["require_managed_binary"] is True
    assert tool_states == [("trivy", "COMPLETED_NO_FINDINGS")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "binary_name"),
    [
        (CheckovAdapter, "checkov"),
        (DockleAdapter, "dockle"),
        (KubeBenchAdapter, "kube-bench"),
        (ProwlerAdapter, "prowler"),
    ],
)
async def test_infra_iac_adapters_fail_closed_without_managed_identity(
    monkeypatch, tmp_path, adapter_type, binary_name
):
    """IaC tools must not execute an unmanaged host binary."""
    adapter = adapter_type()
    fake_binary = tmp_path / binary_name
    fake_binary.write_bytes(b"untrusted executable")
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: str(fake_binary))
    execute_mock = AsyncMock()
    monkeypatch.setattr(adapter, "execute_command", execute_mock)

    async def log_cb(*_args):
        return None

    async def finding_cb(*_args):
        return None

    await adapter.run(
        Target(name="IaC Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path)),
        ScanConfig(),
        log_cb,
        finding_cb,
        require_managed_binary=True,
    )

    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    execute_mock.assert_not_awaited()
