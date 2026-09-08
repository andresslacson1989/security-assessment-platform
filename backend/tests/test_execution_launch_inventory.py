"""Checked-in inventory of every scan-reachable process-launch boundary.

This test is intentionally AST-only: it does not import application modules or
open the protected production database.  Any new launch mechanism must be
classified here before it can be merged.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
LAUNCH_FUNCTIONS = {
    "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell", "safe_execute_subprocess",
    "self.execute_command", "self.safe_execute_subprocess",
    "process_supervisor.execute", "os.system", "os.popen",
}


class _LaunchVisitor(ast.NodeVisitor):
    def __init__(self):
        self._function_stack = []
        self.calls = []

    def _visit_function(self, node):
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Call(self, node):
        function = ast.unparse(node.func)
        if function in LAUNCH_FUNCTIONS:
            self.calls.append((
                function,
                node.lineno,
                self._function_stack[-1] if self._function_stack else "<module>",
                {keyword.arg for keyword in node.keywords},
            ))
        self.generic_visit(node)


def _calls_from_source(source: str, filename: str) -> list[tuple[str, int, str, set[str]]]:
    visitor = _LaunchVisitor()
    visitor.visit(ast.parse(source, filename=filename))
    return visitor.calls


def _calls(path: Path) -> list[tuple[str, int, str, set[str]]]:
    return _calls_from_source(path.read_text(encoding="utf-8"), str(path))


def _assert_adapter_launch_contract(path: str, launch: tuple[str, int, str, set[str]]) -> None:
    function, line, owner, keywords = launch
    if function != "self.execute_command":
        return
    if owner == "get_version":
        assert "non_scan_context" in keywords, f"version probe lacks explicit non-scan context at {path}:{line}"
        return
    assert {"execution_authority_provider", "operation_id"}.issubset(keywords), (
        f"scan launch lacks explicit authority and operation identity at {path}:{line}"
    )


def test_all_process_creation_is_inventory_classified() -> None:
    launches = {
        path.relative_to(ROOT).as_posix(): _calls(path)
        for path in APP.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    direct_popen = [path for path, calls in launches.items() if any(name == "subprocess.Popen" for name, _, _, _ in calls)]
    assert direct_popen == ["app/core/process_supervisor.py"]
    assert launches["app/core/binary_resolver.py"]
    assert launches["app/core/process_supervisor.py"]


def test_installer_launches_are_non_scan_capabilities() -> None:
    for path in (APP / "installers").glob("*.py"):
        calls = _calls(path)
        assert all(name == "process_supervisor.execute" for name, _, _, _ in calls), path
        for name, line, _, keywords in calls:
            assert "non_scan_context" in keywords, f"missing non-scan capability at {path}:{line}"


def test_scan_process_launch_api_is_centralized() -> None:
    for path in APP.rglob("*.py"):
        if path.name == "process_supervisor.py" or "installers" in path.parts:
            continue
        for name, line, _, _ in _calls(path):
            assert name in {
                "safe_execute_subprocess", "self.safe_execute_subprocess",
                "process_supervisor.execute", "self.execute_command",
            }, f"unclassified {name} at {path}:{line}"


def test_scan_adapter_launches_declare_explicit_authority_or_observation_context() -> None:
    for path in sorted((APP / "adapters").glob("*.py")):
        for launch in _calls(path):
            _assert_adapter_launch_contract(path.as_posix(), launch)


def test_external_launch_helpers_declare_explicit_non_scan_context() -> None:
    for path in sorted(APP.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for function, line, _, keywords in _calls(path):
            if function == "process_supervisor.execute":
                assert "non_scan_context" in keywords, f"external helper lacks context at {path}:{line}"


def test_launch_inventory_rejects_ungoverned_scan_fixture() -> None:
    launches = _calls_from_source(
        "async def run():\n    await self.execute_command(['tool'])\n",
        "ungoverned_scan_fixture.py",
    )

    assert len(launches) == 1
    with pytest.raises(AssertionError, match="explicit authority"):
        _assert_adapter_launch_contract("ungoverned_scan_fixture.py", launches[0])
