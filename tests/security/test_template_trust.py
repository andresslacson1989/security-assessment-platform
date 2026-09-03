import hashlib
import json
from pathlib import Path

from app.core.template_trust import (
    NUCLEI_TEMPLATES_ARCHIVE_SHA256,
    NUCLEI_TEMPLATES_COMMIT,
    verify_managed_nuclei_templates,
)


def test_managed_nuclei_template_tree_requires_pinned_identity_and_digest(tmp_path: Path):
    root = tmp_path / "templates"
    root.mkdir()
    template = root / "http.yaml"
    template.write_text("id: approved-template\n", encoding="utf-8")
    digest = hashlib.sha256()
    digest.update(b"http.yaml\0")
    digest.update(hashlib.sha256(template.read_bytes()).digest())
    digest.update(b"\0")
    record = tmp_path / "templates.trust.json"
    record.write_text(json.dumps({
        "source_commit": NUCLEI_TEMPLATES_COMMIT,
        "archive_sha256": NUCLEI_TEMPLATES_ARCHIVE_SHA256,
        "template_tree_sha256": digest.hexdigest(),
        "trust_status": "VALID",
    }), encoding="utf-8")

    assert verify_managed_nuclei_templates(root, record) is True
    template.write_text("id: tampered-template\n", encoding="utf-8")
    assert verify_managed_nuclei_templates(root, record) is False
