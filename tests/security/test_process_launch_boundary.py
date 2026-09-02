"""Ensure every external-tool launch remains behind ProcessSupervisor."""

from __future__ import annotations

import ast
from pathlib import Path


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
