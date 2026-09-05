"""Checked-in inventory of every scan-reachable process-launch boundary.

This test is intentionally AST-only: it does not import application modules or
open the protected production database.  Any new launch mechanism must be
classified here before it can be merged.
"""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"


def _calls(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            function = ast.unparse(node.func)
            if function in {
                "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
                "subprocess.check_output", "asyncio.create_subprocess_exec",
                "asyncio.create_subprocess_shell", "safe_execute_subprocess",
                "process_supervisor.execute", "os.system", "os.popen",
            }:
                found.append((function, node.lineno))
    return found


def test_all_process_creation_is_inventory_classified() -> None:
    launches = {
        path.relative_to(ROOT).as_posix(): _calls(path)
        for path in APP.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    direct_popen = [path for path, calls in launches.items() if any(name == "subprocess.Popen" for name, _ in calls)]
    assert direct_popen == ["app/core/process_supervisor.py"]
    assert launches["app/core/binary_resolver.py"]
    assert launches["app/core/process_supervisor.py"]


def test_installer_launches_are_non_scan_capabilities() -> None:
    for path in (APP / "installers").glob("*.py"):
        calls = _calls(path)
        assert all(name == "process_supervisor.execute" for name, _ in calls), path
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "process_supervisor.execute":
                assert any(keyword.arg == "non_scan_context" for keyword in node.keywords), f"missing non-scan capability at {path}:{node.lineno}"


def test_scan_process_launch_api_is_centralized() -> None:
    for path in APP.rglob("*.py"):
        if path.name == "process_supervisor.py" or "installers" in path.parts:
            continue
        for name, line in _calls(path):
            assert name in {"safe_execute_subprocess", "process_supervisor.execute"}, f"unclassified {name} at {path}:{line}"


def test_scan_supervisor_calls_declare_governed_capability() -> None:
    path = APP / "engines" / "code_sast" / "git_history_scanner.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "process_supervisor.execute"]
    assert calls
    for node in calls:
        keys = {keyword.arg for keyword in node.keywords}
        assert {"execution_context", "execution_capability"}.issubset(keys)
