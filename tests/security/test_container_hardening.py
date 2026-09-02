"""Deployment regression checks for the hardened execution containers."""

from pathlib import Path

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
