#!/usr/bin/env python3
"""Run a complete pytest selection with deterministic, evidence-checked shards.

This helper is intentionally standard-library-only.  It is used by the
authoritative GitHub workflow to keep the existing focused and full job
identities while preventing a bounded job from reporting success after only a
partial test run.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


MANIFEST_SCHEMA = "cyberassess.ci.complete_pytest_manifest.v1"
OBSERVER_SCHEMA = "cyberassess.ci.pytest_shard_observation.v1"
AGGREGATE_SCHEMA = "cyberassess.ci.complete_pytest_junit.v1"
EVENTS_SCHEMA = "cyberassess.ci.pytest_shard_events.v1"
EXECUTION_STATE_SCHEMA = "cyberassess.ci.pytest_shard_execution_state.v1"
MAX_FAILURE_TEXT = 16_000
_SECRET_ENV_KEY = re.compile(r"(?:TOKEN|PASSWORD|SECRET|CREDENTIAL|PRIVATE|API[_-]?KEY|AUTH)", re.IGNORECASE)
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AUTHENTICATED_URL_PATTERN = re.compile(r"\b([a-z][a-z0-9+.-]*://)([^\s/@:]+):([^\s/@]+)@", re.IGNORECASE)


class _ShardProcessTimeout(RuntimeError):
    """Internal signal for the helper's own absolute shard deadline."""


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _redact_text(value: object) -> str:
    """Remove known secret values before diagnostic text becomes durable evidence."""
    text = "" if value is None else str(value)
    secret_values = sorted(
        {
            secret
            for key, secret in os.environ.items()
            if _SECRET_ENV_KEY.search(key) and len(secret) >= 4
        },
        key=len,
        reverse=True,
    )
    for secret in secret_values:
        text = text.replace(secret, "[REDACTED]")
    text = _JWT_PATTERN.sub("[REDACTED-JWT]", text)
    text = _AUTHENTICATED_URL_PATTERN.sub(r"\1[REDACTED]@", text)
    if len(text) > MAX_FAILURE_TEXT:
        text = text[:MAX_FAILURE_TEXT] + "...[TRUNCATED]"
    return text


def _failure_record(report: object) -> dict[str, str]:
    longrepr = getattr(report, "longreprtext", None)
    if longrepr is None:
        longrepr = getattr(report, "longrepr", "")
    return {
        "outcome": _redact_text(getattr(report, "outcome", "failed")),
        "phase": _redact_text(getattr(report, "when", "")),
        "trace": _redact_text(longrepr),
    }


class _ShardEventWriter:
    """Single-process, append-only, immediately flushed shard event writer."""

    def __init__(self, path: Path, *, suite: str, manifest_sha256: str, shard_index: int, shard_count: int) -> None:
        self.path = path
        self.suite = suite
        self.manifest_sha256 = manifest_sha256
        self.shard_index = shard_index
        self.shard_count = shard_count
        self._sequence = self._read_last_sequence()
        self._handle = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8", buffering=1)

    def _read_last_sequence(self) -> int:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0
        last_sequence = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record.get("schema") != EVENTS_SCHEMA:
                raise RuntimeError(f"pytest event schema mismatch: {self.path}")
            if record.get("manifest_sha256") != self.manifest_sha256:
                raise RuntimeError(f"pytest event manifest mismatch: {self.path}")
            if record.get("shard_index") != self.shard_index or record.get("shard_count") != self.shard_count:
                raise RuntimeError(f"pytest event shard identity mismatch: {self.path}")
            sequence = record.get("sequence")
            if not isinstance(sequence, int) or sequence != last_sequence + 1:
                raise RuntimeError(f"pytest event sequence is not strictly increasing: {self.path}")
            last_sequence = sequence
        return last_sequence

    def write(
        self,
        *,
        event_type: str,
        node_id: str,
        pytest_phase: str | None = None,
        outcome: str | None = None,
        duration_seconds: float | None = None,
        failure: dict[str, str] | None = None,
    ) -> None:
        if self._handle is None:
            raise RuntimeError(f"pytest event writer is closed: {self.path}")
        self._sequence += 1
        record: dict[str, object] = {
            "schema": EVENTS_SCHEMA,
            "suite": self.suite,
            "manifest_sha256": self.manifest_sha256,
            "shard_index": self.shard_index,
            "shard_count": self.shard_count,
            "sequence": self._sequence,
            "timestamp": _utc_timestamp(),
            "monotonic_ns": time.monotonic_ns(),
            "process_id": os.getpid(),
            "event_type": event_type,
            "node_id": node_id,
            "pytest_phase": pytest_phase,
            "outcome": outcome,
            "duration_seconds": duration_seconds,
        }
        if failure is not None:
            record["failure"] = {key: _redact_text(value) for key, value in failure.items()}
        self._handle.write(_canonical_json(record).decode("utf-8") + "\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def close(self) -> None:
        if self._handle is None:
            return
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        self._handle = None


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _parse_node_ids(output: str) -> list[str]:
    node_ids: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "::" not in line:
            continue
        if not line.startswith(("tests/", "backend/tests/")):
            continue
        node_ids.append(line)
    if not node_ids:
        raise RuntimeError("pytest collection produced no test node IDs")
    duplicates = sorted({node_id for node_id in node_ids if node_ids.count(node_id) > 1})
    if duplicates:
        raise RuntimeError("pytest collection produced duplicate node IDs: " + ", ".join(duplicates[:5]))
    return node_ids


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_canonical_json(value) + b"\n")
    os.replace(temporary, path)


def _write_execution_state(
    metadata: dict[str, object],
    *,
    terminal_state: str,
    exit_code: int | None,
    timed_out: bool = False,
    terminated: bool = False,
    error: str | None = None,
) -> None:
    started_monotonic = float(metadata["started_monotonic"])
    record: dict[str, object] = {
        "schema": EXECUTION_STATE_SCHEMA,
        "suite": metadata["suite"],
        "manifest_sha256": metadata["manifest_sha256"],
        "shard_index": metadata["index"],
        "shard_count": metadata["shard_count"],
        "node_count": metadata["node_count"],
        "child_pid": metadata.get("child_pid"),
        "started_at": metadata["started_at"],
        "ended_at": _utc_timestamp(),
        "elapsed_seconds": round(max(0.0, time.monotonic() - started_monotonic), 6),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "terminated": terminated,
        "terminal_state": terminal_state,
        "paths": {
            "log": metadata["log"],
            "events": metadata["events"],
            "junit": metadata["junit"],
            "observer": metadata["observer"],
            "execution_state": metadata["execution_state"],
        },
    }
    if error:
        record["error"] = _redact_text(error)
    _write_json(Path(str(metadata["execution_state"])), record)


def _finalize_execution_states(
    metadata: list[dict[str, object]],
    *,
    terminal_state: str | None = None,
    timed_out: bool = False,
    terminated: bool = False,
    error: str | None = None,
) -> None:
    for item in metadata:
        process = item.get("process")
        exit_code = process.poll() if isinstance(process, subprocess.Popen) else None
        state = terminal_state
        if state is None:
            if item.get("start_error"):
                state = "start_failed"
            elif timed_out and item.get("was_running_at_failure"):
                state = "timed_out"
            elif terminated and item.get("was_running_at_failure"):
                state = "terminated"
            elif exit_code == 0:
                state = "completed"
            elif exit_code is not None:
                state = "failed"
            else:
                state = "terminated" if terminated else "failed"
        item["terminal_state"] = state
        item_timed_out = timed_out and bool(item.get("was_running_at_failure"))
        item_terminated = terminated and bool(item.get("was_running_at_failure"))
        item_error = str(item.get("start_error") or error or "") or None
        if state == "completed":
            item_error = None
        _write_execution_state(
            item,
            terminal_state=state,
            exit_code=exit_code,
            timed_out=item_timed_out,
            terminated=item_terminated,
            error=item_error,
        )


def _redis_shard_url(base_url: str, shard_index: int) -> str:
    parts = urlsplit(base_url)
    raw_database = parts.path.rstrip("/").rsplit("/", 1)[-1]
    database = int(raw_database) if raw_database.isdigit() else 15
    return urlunsplit((parts.scheme, parts.netloc, f"/{database + shard_index}", parts.query, parts.fragment))


def _run_collection(args: argparse.Namespace, root: Path, collection_dir: Path) -> list[str]:
    collection_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["CI_ROOT"] = str(collection_dir)
    environment["CI_REPORT_DIR"] = str(collection_dir / "reports")
    environment["CI_PYTEST_BASETEMP"] = str(collection_dir / "pytest")
    environment["CYBERASSESS_DB_PATH"] = str(collection_dir / "collection.db")
    environment["TEMP"] = str(collection_dir / "tmp")
    environment["TMP"] = str(collection_dir / "tmp")
    environment["TMPDIR"] = str(collection_dir / "tmp")
    environment["PYTHONPYCACHEPREFIX"] = str(collection_dir / "pycache")
    for path in (
        environment["CI_REPORT_DIR"],
        environment["CI_PYTEST_BASETEMP"],
        environment["TEMP"],
        environment["PYTHONPYCACHEPREFIX"],
    ):
        Path(path).mkdir(parents=True, exist_ok=True)

    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--collect-only", "-q"]
    if args.suite_paths:
        command.extend(args.suite_paths)
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=args.collection_timeout_seconds,
    )
    (collection_dir / "pytest-collect.stdout").write_text(result.stdout, encoding="utf-8")
    (collection_dir / "pytest-collect.stderr").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"pytest collection failed with exit code {result.returncode}")
    return _parse_node_ids(result.stdout)


def _shard_environment(
    base_environment: dict[str, str],
    *,
    suite: str,
    shard_root: Path,
    shard_index: int,
    shard_count: int,
    manifest_path: Path,
    observer_path: Path,
    events_path: Path,
    redis_url: str | None,
) -> dict[str, str]:
    report_dir = shard_root / "reports"
    pytest_base_temp = shard_root / "pytest"
    temporary_dir = shard_root / "tmp"
    pycache_dir = shard_root / "pycache"
    for path in (report_dir, pytest_base_temp, temporary_dir, pycache_dir):
        path.mkdir(parents=True, exist_ok=True)
    environment = dict(base_environment)
    environment.update(
        {
            "CI_ROOT": str(shard_root),
            "CI_REPORT_DIR": str(report_dir),
            "CI_PYTEST_BASETEMP": str(pytest_base_temp),
            "CYBERASSESS_DB_PATH": str(shard_root / "cyberassess.db"),
            "TEMP": str(temporary_dir),
            "TMP": str(temporary_dir),
            "TMPDIR": str(temporary_dir),
            "PYTHONPYCACHEPREFIX": str(pycache_dir),
            "PYTEST_BASETEMP": str(pytest_base_temp),
            "CI_SHARD_INDEX": str(shard_index),
            "CI_SHARD_COUNT": str(shard_count),
            "CI_SUITE": suite,
            "CI_SHARD_MANIFEST": str(manifest_path),
            "CI_SHARD_OBSERVER_REPORT": str(observer_path),
            "CI_SHARD_EVENTS": str(events_path),
            "PYTHONUNBUFFERED": "1",
        }
    )
    if redis_url:
        environment["CYBERASSESS_LIVE_REDIS_TEST_URL"] = _redis_shard_url(redis_url, shard_index)
    script_directory = str(Path(__file__).resolve().parent)
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = script_directory + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
    return environment


def _terminate_processes(processes: list[subprocess.Popen[object]]) -> None:
    for process in processes:
        if process.poll() is not None:
            continue
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
    deadline = time.monotonic() + 5
    for process in processes:
        if process.poll() is not None:
            continue
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            process.kill()


def _read_observer(path: Path, expected_manifest_digest: str, shard_index: int, shard_count: int) -> dict[str, object]:
    if not path.is_file():
        raise RuntimeError(f"missing pytest observer evidence: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"invalid pytest observer evidence: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != OBSERVER_SCHEMA:
        raise RuntimeError(f"pytest observer schema mismatch: {path}")
    if value.get("manifest_sha256") != expected_manifest_digest:
        raise RuntimeError(f"pytest observer manifest mismatch: {path}")
    if value.get("shard_index") != shard_index or value.get("shard_count") != shard_count:
        raise RuntimeError(f"pytest observer shard identity mismatch: {path}")
    counts = value.get("setup_report_counts")
    if not isinstance(counts, dict) or any(
        not isinstance(key, str) or not isinstance(item, int)
        for key, item in counts.items()
    ):
        raise RuntimeError(f"pytest observer report counts are malformed: {path}")
    return value


def _read_events(
    path: Path,
    *,
    expected_manifest_digest: str,
    shard_index: int,
    shard_count: int,
    expected_node_ids: list[str],
) -> list[dict[str, object]]:
    if not path.is_file():
        raise RuntimeError(f"missing pytest event evidence: {path}")
    try:
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"invalid pytest event evidence: {path}") from exc
    if not records:
        raise RuntimeError(f"pytest event evidence is empty: {path}")
    expected_nodes = set(expected_node_ids)
    seen_sequences: list[int] = []
    node_events: dict[str, set[str]] = {node_id: set() for node_id in expected_node_ids}
    for expected_sequence, value in enumerate(records, start=1):
        if not isinstance(value, dict) or value.get("schema") != EVENTS_SCHEMA:
            raise RuntimeError(f"pytest event schema mismatch: {path}")
        if value.get("manifest_sha256") != expected_manifest_digest:
            raise RuntimeError(f"pytest event manifest mismatch: {path}")
        if value.get("shard_index") != shard_index or value.get("shard_count") != shard_count:
            raise RuntimeError(f"pytest event shard identity mismatch: {path}")
        sequence = value.get("sequence")
        if not isinstance(sequence, int) or sequence != expected_sequence:
            raise RuntimeError(f"pytest event sequence mismatch: {path}")
        seen_sequences.append(sequence)
        node_id = value.get("node_id")
        event_type = value.get("event_type")
        if not isinstance(node_id, str) or not isinstance(event_type, str):
            raise RuntimeError(f"pytest event identity is malformed: {path}")
        if node_id in expected_nodes:
            node_events[node_id].add(event_type if event_type != "phase_result" else str(value.get("pytest_phase")))
    required_events = {"node_start", "setup", "call", "teardown"}
    missing = {
        node_id: sorted(required_events - event_types)
        for node_id, event_types in node_events.items()
        if required_events - event_types
    }
    if missing:
        raise RuntimeError(f"pytest event coverage is incomplete for {path}: {missing}")
    if seen_sequences != list(range(1, len(records) + 1)):
        raise RuntimeError(f"pytest event sequence is not monotonic: {path}")
    return records


def _parse_junit(path: Path, expected_node_count: int) -> tuple[ET.Element, list[ET.Element]]:
    if not path.is_file():
        raise RuntimeError(f"missing shard JUnit evidence: {path}")
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise RuntimeError(f"invalid shard JUnit evidence: {path}") from exc
    testcases = list(root.iter("testcase"))
    if len(testcases) != expected_node_count:
        raise RuntimeError(
            f"shard JUnit testcase count mismatch for {path}: expected {expected_node_count}, got {len(testcases)}"
        )
    return root, testcases


def _write_aggregate(
    *,
    path: Path,
    suite_name: str,
    manifest_digest: str,
    shard_reports: list[tuple[int, ET.Element, list[ET.Element]]],
) -> None:
    testcases: list[ET.Element] = []
    elapsed = 0.0
    errors = failures = skipped = 0
    for _, root, cases in shard_reports:
        testcases.extend(copy.deepcopy(case) for case in cases)
        for suite in root.iter("testsuite"):
            elapsed += float(suite.attrib.get("time", "0"))
        errors += sum(1 for case in cases if case.find("error") is not None)
        failures += sum(1 for case in cases if case.find("failure") is not None)
        skipped += sum(1 for case in cases if case.find("skipped") is not None)
    aggregate = ET.Element(
        "testsuites",
        {
            "name": suite_name,
            "schema": AGGREGATE_SCHEMA,
            "manifest_sha256": manifest_digest,
        },
    )
    suite = ET.SubElement(
        aggregate,
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(testcases)),
            "errors": str(errors),
            "failures": str(failures),
            "skipped": str(skipped),
            "time": f"{elapsed:.6f}",
        },
    )
    suite.extend(testcases)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    ET.ElementTree(aggregate).write(temporary, encoding="utf-8", xml_declaration=True)
    os.replace(temporary, path)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=("focused", "full"))
    parser.add_argument("--suite-path", action="append", dest="suite_paths", default=[])
    parser.add_argument("--shards", type=int, default=2)
    parser.add_argument("--job-root", required=True, type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--base-temp", required=True, type=Path)
    parser.add_argument("--junitxml", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--redis-url", default=os.environ.get("CYBERASSESS_LIVE_REDIS_TEST_URL"))
    parser.add_argument("--collection-timeout-seconds", type=int, default=300)
    parser.add_argument("--process-timeout-seconds", type=int, default=1500)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if args.shards < 2:
        raise SystemExit("--shards must be at least 2 for complete bounded execution")
    if args.process_timeout_seconds <= 0 or args.collection_timeout_seconds <= 0:
        raise SystemExit("timeouts must be positive")
    root = Path(__file__).resolve().parents[2]
    args.job_root = args.job_root.resolve()
    args.report_dir = args.report_dir.resolve()
    args.base_temp = args.base_temp.resolve()
    args.junitxml = args.junitxml.resolve()
    args.log = args.log.resolve()
    args.report_dir.mkdir(parents=True, exist_ok=True)
    args.job_root.mkdir(parents=True, exist_ok=True)
    args.base_temp.mkdir(parents=True, exist_ok=True)

    collection_dir = args.job_root / "collection"
    node_ids = _run_collection(args, root, collection_dir)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "suite": args.suite,
        "shard_count": args.shards,
        "node_ids": node_ids,
    }
    manifest_digest = _sha256(manifest)
    manifest_record = dict(manifest)
    manifest_record["sha256"] = manifest_digest
    manifest_path = args.report_dir / f"{args.suite}-manifest.json"
    _write_json(manifest_path, manifest_record)

    shard_inputs = [
        [node_id for position, node_id in enumerate(node_ids) if position % args.shards == shard]
        for shard in range(args.shards)
    ]
    if any(not shard_nodes for shard_nodes in shard_inputs):
        raise RuntimeError("deterministic shard partition produced an empty shard")

    base_environment = os.environ.copy()
    processes: list[subprocess.Popen[object]] = []
    handles: list[object] = []
    shard_metadata: list[dict[str, object]] = []
    for shard_index, shard_nodes in enumerate(shard_inputs):
        shard_root = args.job_root / "shards" / f"{shard_index:02d}"
        shard_report_dir = shard_root / "reports"
        observer_path = shard_report_dir / "pytest-observer.json"
        events_path = shard_report_dir / "pytest-events.jsonl"
        execution_state_path = shard_report_dir / "pytest-execution-state.json"
        shard_junit = shard_report_dir / f"{args.suite}-shard-{shard_index:02d}.xml"
        shard_log = shard_report_dir / f"{args.suite}-shard-{shard_index:02d}.log"
        metadata: dict[str, object] = {
                "suite": args.suite,
                "manifest_sha256": manifest_digest,
                "index": shard_index,
                "shard_count": args.shards,
                "node_count": len(shard_nodes),
                "junit": str(shard_junit),
                "log": str(shard_log),
                "events": str(events_path),
                "observer": str(observer_path),
                "execution_state": str(execution_state_path),
                "started_at": _utc_timestamp(),
                "started_monotonic": time.monotonic(),
                "child_pid": None,
                "process": None,
        }
        shard_metadata.append(metadata)
        _write_execution_state(metadata, terminal_state="running", exit_code=None)

    try:
        for shard_index, shard_nodes in enumerate(shard_inputs):
            metadata = shard_metadata[shard_index]
            shard_root = args.job_root / "shards" / f"{shard_index:02d}"
            observer_path = Path(str(metadata["observer"]))
            events_path = Path(str(metadata["events"]))
            shard_junit = Path(str(metadata["junit"]))
            shard_log = Path(str(metadata["log"]))
            environment = _shard_environment(
                base_environment,
                suite=args.suite,
                shard_root=shard_root,
                shard_index=shard_index,
                shard_count=args.shards,
                manifest_path=manifest_path,
                observer_path=observer_path,
                events_path=events_path,
                redis_url=args.redis_url,
            )
            command = [
                sys.executable,
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-p",
                "run_complete_pytest",
                "-q",
                f"--basetemp={environment['PYTEST_BASETEMP']}",
                f"--junitxml={shard_junit}",
                *shard_nodes,
            ]
            handle = shard_log.open("w", encoding="utf-8")
            handles.append(handle)
            process = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
            processes.append(process)
            metadata["process"] = process
            metadata["child_pid"] = process.pid
            _write_execution_state(metadata, terminal_state="running", exit_code=None)

        deadline = time.monotonic() + args.process_timeout_seconds
        exit_codes: list[int] = []
        for process in processes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ShardProcessTimeout("pytest shard process timeout exceeded")
            exit_codes.append(process.wait(timeout=remaining))
        if any(code != 0 for code in exit_codes):
            _finalize_execution_states(shard_metadata, error="one or more complete pytest shards failed")
            raise RuntimeError("one or more complete pytest shards failed: " + repr(exit_codes))
    except (OSError, subprocess.TimeoutExpired, _ShardProcessTimeout) as exc:
        for metadata in shard_metadata:
            process = metadata.get("process")
            metadata["was_running_at_failure"] = isinstance(process, subprocess.Popen) and process.poll() is None
            if isinstance(exc, OSError) and process is None:
                metadata["start_error"] = str(exc)
        _terminate_processes(processes)
        _finalize_execution_states(
            shard_metadata,
            timed_out=isinstance(exc, (subprocess.TimeoutExpired, _ShardProcessTimeout)),
            terminated=True,
            error=str(exc),
        )
        raise RuntimeError("complete pytest shard execution timed out or could not start") from exc
    except BaseException:
        if not all("terminal_state" in metadata for metadata in shard_metadata):
            for metadata in shard_metadata:
                process = metadata.get("process")
                metadata["was_running_at_failure"] = isinstance(process, subprocess.Popen) and process.poll() is None
            _terminate_processes(processes)
            _finalize_execution_states(shard_metadata, terminated=True, error="parent execution interrupted")
        raise
    finally:
        for handle in handles:
            handle.close()

    shard_reports: list[tuple[int, ET.Element, list[ET.Element]]] = []
    for shard_index, shard_nodes in enumerate(shard_inputs):
        metadata = shard_metadata[shard_index]
        _write_execution_state(metadata, terminal_state="completed", exit_code=0)
        observer = _read_observer(Path(str(metadata["observer"])), manifest_digest, shard_index, args.shards)
        counts = observer["setup_report_counts"]
        expected_counts = {node_id: 1 for node_id in shard_nodes}
        if counts != expected_counts:
            raise RuntimeError(f"pytest shard {shard_index} did not execute every node exactly once")
        _read_events(
            Path(str(metadata["events"])),
            expected_manifest_digest=manifest_digest,
            shard_index=shard_index,
            shard_count=args.shards,
            expected_node_ids=shard_nodes,
        )
        junit_root, testcases = _parse_junit(Path(str(metadata["junit"])), len(shard_nodes))
        shard_reports.append((shard_index, junit_root, testcases))

    _write_aggregate(
        path=args.junitxml,
        suite_name=args.suite,
        manifest_digest=manifest_digest,
        shard_reports=shard_reports,
    )
    lines = [
        f"schema={MANIFEST_SCHEMA}",
        f"suite={args.suite}",
        f"manifest={manifest_path}",
        f"manifest_sha256={manifest_digest}",
        f"node_count={len(node_ids)}",
        f"shard_count={args.shards}",
    ]
    for metadata in shard_metadata:
        lines.append(
            json.dumps(
                {key: value for key, value in metadata.items() if key != "process"},
                sort_keys=True,
            )
        )
        lines.append(f"--- shard {metadata['index']} log ---")
        lines.append(Path(str(metadata["log"])).read_text(encoding="utf-8"))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.log.write_text("\n".join(lines), encoding="utf-8")
    _write_json(
        args.report_dir / f"{args.suite}-shards.json",
        {
            "manifest": manifest_record,
            "shards": [
                {key: value for key, value in metadata.items() if key != "process"}
                for metadata in shard_metadata
            ],
        },
    )
    return 0


_event_writer: _ShardEventWriter | None = None
_setup_report_counts: dict[str, int] = {}


def _emit_event(**kwargs: object) -> None:
    if _event_writer is None:
        return
    try:
        _event_writer.write(**kwargs)
    except Exception as exc:  # pragma: no cover - parent validation fails closed
        sys.stderr.write(f"failed to write pytest event evidence: {_redact_text(exc)}\n")


def pytest_sessionstart(session):
    """Initialize the shard event stream before the first test starts."""
    global _event_writer
    path_value = os.environ.get("CI_SHARD_EVENTS")
    manifest_value = os.environ.get("CI_SHARD_MANIFEST")
    if not path_value or not manifest_value:
        return
    try:
        manifest = json.loads(Path(manifest_value).read_text(encoding="utf-8"))
        _event_writer = _ShardEventWriter(
            Path(path_value),
            suite=os.environ.get("CI_SUITE", "unknown"),
            manifest_sha256=str(manifest["sha256"]),
            shard_index=int(os.environ["CI_SHARD_INDEX"]),
            shard_count=int(os.environ["CI_SHARD_COUNT"]),
        )
        _emit_event(event_type="session_start", node_id="")
    except Exception as exc:  # pragma: no cover - parent validation fails closed
        sys.stderr.write(f"failed to initialize pytest event evidence: {_redact_text(exc)}\n")


def pytest_runtest_logstart(nodeid, location):
    """Record a durable start marker for each collected node."""
    _emit_event(event_type="node_start", node_id=nodeid)


def pytest_runtest_logreport(report):
    """Record setup counts and a durable event for every pytest phase."""
    if report.when == "setup":
        _setup_report_counts[report.nodeid] = _setup_report_counts.get(report.nodeid, 0) + 1
    failure = _failure_record(report) if report.outcome == "failed" else None
    _emit_event(
        event_type="phase_result",
        node_id=report.nodeid,
        pytest_phase=report.when,
        outcome=report.outcome,
        duration_seconds=float(getattr(report, "duration", 0.0)),
        failure=failure,
    )


def pytest_sessionfinish(session, exitstatus):
    """Persist observer evidence even when pytest exits with failures."""
    path_value = os.environ.get("CI_SHARD_OBSERVER_REPORT")
    manifest_value = os.environ.get("CI_SHARD_MANIFEST")
    if not path_value or not manifest_value:
        return
    try:
        manifest = json.loads(Path(manifest_value).read_text(encoding="utf-8"))
        manifest_digest = manifest.get("sha256")
        _emit_event(event_type="session_finish", node_id="", outcome=str(exitstatus))
        record = {
            "schema": OBSERVER_SCHEMA,
            "manifest_sha256": manifest_digest,
            "shard_index": int(os.environ["CI_SHARD_INDEX"]),
            "shard_count": int(os.environ["CI_SHARD_COUNT"]),
            "pytest_exit_status": int(exitstatus),
            "setup_report_counts": dict(sorted(_setup_report_counts.items())),
        }
        _write_json(Path(path_value), record)
    except Exception as exc:  # pragma: no cover - the parent treats missing evidence as failure
        sys.stderr.write(f"failed to write pytest shard observer evidence: {exc}\n")


def pytest_unconfigure(config):
    """Flush and close the shard event stream after pytest hooks finish."""
    global _event_writer
    if _event_writer is not None:
        try:
            _event_writer.close()
        except Exception as exc:  # pragma: no cover - parent validation fails closed
            sys.stderr.write(f"failed to close pytest event evidence: {_redact_text(exc)}\n")
        finally:
            _event_writer = None


if __name__ == "__main__":
    raise SystemExit(main())
