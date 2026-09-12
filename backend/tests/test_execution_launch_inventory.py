"""Checked-in inventory of every scan-reachable process-launch boundary.

This test is intentionally AST-only: it does not import application modules or
open the protected production database.  Any new launch mechanism must be
classified here before it can be merged.
"""

import ast
import asyncio
import signal
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


def test_windows_governed_launch_uses_native_job_list_and_has_no_pid_fallback() -> None:
    source = (APP / "core" / "windows_job.py").read_text(encoding="utf-8")
    assert "CreateProcessW" in source
    assert "PROC_THREAD_ATTRIBUTE_JOB_LIST" in source
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in source
    assert "TerminateJobObject" in source
    assert "taskkill" not in source.lower()


def test_every_windows_supervisor_launch_uses_a_typed_job_attestation() -> None:
    source = (APP / "core" / "process_supervisor.py").read_text(encoding="utf-8")
    assert 'if os.name == "nt":' in source
    assert 'if os.name == "nt" and execution_capability is not None:' not in source
    for required in (
        "WindowsJobProcess",
        "WindowsNonScanJobAttestation",
        "parse_windows_attestation_json",
        "windows_non_scan_job_name",
    ):
        assert required in source


def test_production_recovery_never_reopens_windows_jobs_by_name() -> None:
    for path in APP.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if any(
                keyword.arg == "reopen"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                raise AssertionError(f"production code reopens a Windows job at {path}:{node.lineno}")


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


def test_production_worker_uses_the_public_post_consume_handoff() -> None:
    """The Redis consumer must not bypass the orchestrator authority boundary."""
    worker_path = ROOT.parent / "run_worker.py"
    tree = ast.parse(worker_path.read_text(encoding="utf-8"), filename=str(worker_path))
    public_handoffs = []
    forbidden = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            if callee == "orchestrator.execute_dispatched_scan":
                public_handoffs.append(node)
            if callee == "local_executor.execute_bounded":
                forbidden.append(f"direct executor call at line {node.lineno}")
        elif isinstance(node, ast.Attribute) and node.attr in {"_execute_scan", "_active_jobs"}:
            forbidden.append(f"private execution state {node.attr} at line {node.lineno}")

    assert len(public_handoffs) == 1
    handoff = public_handoffs[0]
    assert {keyword.arg for keyword in handoff.keywords} >= {
        "cloud_credentials", "executor", "queue_binding",
    }
    executor_keyword = next(keyword for keyword in handoff.keywords if keyword.arg == "executor")
    assert isinstance(executor_keyword.value, ast.Name)
    assert executor_keyword.value.id == "local_executor"
    assert forbidden == []


def test_enterprise_compose_requires_shared_worker_identity_and_generation() -> None:
    """The API and worker must receive the same durable deployment binding."""
    compose = (ROOT.parent / "docker-compose.yml").read_text(encoding="utf-8")
    api_section = compose.split("  cyberassess-enterprise:", 1)[1].split("  cyberassess-worker:", 1)[0]
    worker_section = compose.split("  cyberassess-worker:", 1)[1].split("  postgres:", 1)[0]
    for variable in ("CYBERASSESS_WORKER_IDENTITY", "CYBERASSESS_WORKER_GENERATION"):
        expected = f'{variable}: "${{{variable}:?{variable} must be shared by the enterprise API and worker}}"'
        assert expected in api_section
        assert expected in worker_section


@pytest.mark.asyncio
async def test_worker_shutdown_handlers_request_loop_stop_and_clean_up(monkeypatch) -> None:
    """SIGTERM/SIGINT must request an orderly queue shutdown on POSIX loops."""
    import run_worker

    loop = asyncio.get_running_loop()
    callbacks = {}
    removed = []

    monkeypatch.setattr(
        loop,
        "add_signal_handler",
        lambda shutdown_signal, callback, *args: callbacks.__setitem__(
            shutdown_signal, (callback, args)
        ),
    )
    monkeypatch.setattr(
        loop,
        "remove_signal_handler",
        lambda shutdown_signal: removed.append(shutdown_signal) or True,
    )

    stop_event = asyncio.Event()
    signal_loop, installed = run_worker._install_shutdown_handlers(stop_event)

    assert signal_loop is loop
    assert installed == (signal.SIGINT, signal.SIGTERM)
    callbacks[signal.SIGTERM][0](*callbacks[signal.SIGTERM][1])
    assert stop_event.is_set()

    run_worker._remove_shutdown_handlers(signal_loop, installed)
    assert removed == [signal.SIGINT, signal.SIGTERM]


@pytest.mark.asyncio
async def test_worker_signals_during_active_handler_finish_work_then_exit(monkeypatch) -> None:
    """Signals request loop shutdown without interrupting an active handoff."""
    import importlib
    import run_worker

    import app.core.orchestrator as orchestrator_module
    import app.core.queue as queue_module

    callbacks = {}
    removed = []
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(
        loop,
        "add_signal_handler",
        lambda shutdown_signal, callback, *args: callbacks.__setitem__(
            shutdown_signal, (callback, args)
        ),
    )
    monkeypatch.setattr(
        loop,
        "remove_signal_handler",
        lambda shutdown_signal: removed.append(shutdown_signal) or True,
    )

    active_started = asyncio.Event()
    allow_active_completion = asyncio.Event()

    class FakeOrchestrator:
        instances = []

        def __init__(self):
            self.__class__.instances.append(self)

        def register_engine(self, _engine):
            pass

        async def execute_dispatched_scan(self, *args, **kwargs):
            assert args[:3] == (
                "scan-active-shutdown",
                "org-active-shutdown",
                "request-active-shutdown",
            )
            assert kwargs["queue_binding"] is not None
            active_started.set()
            await allow_active_completion.wait()

    from app.core.queue import QueueDispatchBinding

    queue_binding = QueueDispatchBinding.create(
        scan_id="scan-active-shutdown",
        organization_id="org-active-shutdown",
        authorization_request_id="request-active-shutdown",
        manifest_hash="b" * 64,
        execution_ids=("execution-active-shutdown",),
        operation_ids=("network:nmap",),
    )

    class FakeQueue:
        instance = None

        def __init__(self, url):
            self.url = url
            self.calls = 0
            self.closed = False
            self.__class__.instance = self

        async def consume_once(self, handler, **_kwargs):
            self.calls += 1
            assert self.calls == 1
            active_task = asyncio.create_task(
                handler(
                    "scan-active-shutdown",
                    "org-active-shutdown",
                    "request-active-shutdown",
                    None,
                    queue_binding,
                )
            )
            await active_started.wait()
            assert not active_task.done()
            callbacks[signal.SIGINT][0](*callbacks[signal.SIGINT][1])
            callbacks[signal.SIGTERM][0](*callbacks[signal.SIGTERM][1])
            assert not active_task.done()
            allow_active_completion.set()
            await active_task
            return True

        async def close(self):
            self.closed = True

    monkeypatch.setattr(orchestrator_module, "ScanOrchestrator", FakeOrchestrator)
    monkeypatch.setattr(queue_module, "EXECUTION_QUEUE_URL", "redis://active-shutdown-test")
    monkeypatch.setattr(queue_module, "RedisDurableQueue", FakeQueue)
    monkeypatch.setattr(queue_module, "ScanQueueManager", lambda: object())
    for module_name, class_name in (
        ("app.engines.network.engine", "NetworkAssessmentEngine"),
        ("app.engines.web_dast.engine", "WebDastAssessmentEngine"),
        ("app.engines.code_sast.engine", "CodeSastAssessmentEngine"),
        ("app.engines.infra_iac.engine", "InfraIacAssessmentEngine"),
        ("app.engines.cicd_audit.engine", "CicdAuditAssessmentEngine"),
    ):
        module = importlib.import_module(module_name)
        monkeypatch.setattr(module, class_name, lambda: object())

    await run_worker.run_worker()

    assert FakeQueue.instance is not None
    assert FakeQueue.instance.calls == 1
    assert FakeQueue.instance.closed is True
    assert removed == [signal.SIGINT, signal.SIGTERM]


@pytest.mark.asyncio
async def test_production_worker_runtime_handler_calls_public_handoff(monkeypatch) -> None:
    """Exercise the actual nested Redis handler without launching a scan."""
    import importlib
    import run_worker

    import app.core.orchestrator as orchestrator_module
    import app.core.queue as queue_module

    class StopWorker(Exception):
        pass

    class FakeOrchestrator:
        instances = []

        def __init__(self):
            self.engines = []
            self.handoffs = []
            self.__class__.instances.append(self)

        def register_engine(self, engine):
            self.engines.append(engine)

        async def execute_dispatched_scan(self, *args, **kwargs):
            self.handoffs.append((args, kwargs))

    class FakeExecutor:
        durable_enabled = False

    from app.core.queue import QueueDispatchBinding

    queue_binding = QueueDispatchBinding.create(
        scan_id="scan-runtime",
        organization_id="org-runtime",
        authorization_request_id="request-runtime",
        manifest_hash="a" * 64,
        execution_ids=("execution-runtime",),
        operation_ids=("network:nmap",),
    )

    class FakeQueue:
        instance = None

        def __init__(self, url):
            self.url = url
            self.closed = False
            self.__class__.instance = self

        async def consume_once(self, handler, **_kwargs):
            await handler("scan-runtime", "org-runtime", "request-runtime", None, queue_binding)
            raise StopWorker

        async def close(self):
            self.closed = True

    monkeypatch.setattr(orchestrator_module, "ScanOrchestrator", FakeOrchestrator)
    monkeypatch.setattr(queue_module, "EXECUTION_QUEUE_URL", "redis://runtime-test")
    monkeypatch.setattr(queue_module, "RedisDurableQueue", FakeQueue)
    monkeypatch.setattr(queue_module, "ScanQueueManager", FakeExecutor)
    for module_name, class_name in (
        ("app.engines.network.engine", "NetworkAssessmentEngine"),
        ("app.engines.web_dast.engine", "WebDastAssessmentEngine"),
        ("app.engines.code_sast.engine", "CodeSastAssessmentEngine"),
        ("app.engines.infra_iac.engine", "InfraIacAssessmentEngine"),
        ("app.engines.cicd_audit.engine", "CicdAuditAssessmentEngine"),
    ):
        module = importlib.import_module(module_name)
        monkeypatch.setattr(module, class_name, lambda: object())

    with pytest.raises(StopWorker):
        await run_worker.run_worker()

    assert len(FakeOrchestrator.instances) == 1
    orchestrator = FakeOrchestrator.instances[0]
    assert len(orchestrator.engines) == 5
    assert len(orchestrator.handoffs) == 1
    args, kwargs = orchestrator.handoffs[0]
    assert args == ("scan-runtime", "org-runtime", "request-runtime")
    assert kwargs["cloud_credentials"] is None
    assert isinstance(kwargs["executor"], FakeExecutor)
    assert kwargs["queue_binding"] == queue_binding
    assert FakeQueue.instance is not None and FakeQueue.instance.closed is True
