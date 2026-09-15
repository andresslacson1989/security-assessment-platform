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
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


MANIFEST_SCHEMA = "cyberassess.ci.complete_pytest_manifest.v1"
OBSERVER_SCHEMA = "cyberassess.ci.pytest_shard_observation.v1"
AGGREGATE_SCHEMA = "cyberassess.ci.complete_pytest_junit.v1"


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
    shard_root: Path,
    shard_index: int,
    shard_count: int,
    manifest_path: Path,
    observer_path: Path,
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
            "CI_SHARD_MANIFEST": str(manifest_path),
            "CI_SHARD_OBSERVER_REPORT": str(observer_path),
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
    try:
        for shard_index, shard_nodes in enumerate(shard_inputs):
            shard_root = args.job_root / "shards" / f"{shard_index:02d}"
            shard_report_dir = shard_root / "reports"
            observer_path = shard_report_dir / "pytest-observer.json"
            shard_junit = shard_report_dir / f"{args.suite}-shard-{shard_index:02d}.xml"
            shard_log = shard_report_dir / f"{args.suite}-shard-{shard_index:02d}.log"
            environment = _shard_environment(
                base_environment,
                shard_root=shard_root,
                shard_index=shard_index,
                shard_count=args.shards,
                manifest_path=manifest_path,
                observer_path=observer_path,
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
            process = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
            handles.append(handle)
            processes.append(process)
            shard_metadata.append(
                {
                    "index": shard_index,
                    "node_count": len(shard_nodes),
                    "junit": str(shard_junit),
                    "log": str(shard_log),
                    "observer": str(observer_path),
                    "process_id": process.pid,
                }
            )

        deadline = time.monotonic() + args.process_timeout_seconds
        exit_codes: list[int] = []
        for process in processes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("pytest shard process timeout exceeded")
            exit_codes.append(process.wait(timeout=remaining))
        if any(code != 0 for code in exit_codes):
            raise RuntimeError("one or more complete pytest shards failed: " + repr(exit_codes))
    except (OSError, subprocess.TimeoutExpired) as exc:
        _terminate_processes(processes)
        raise RuntimeError("complete pytest shard execution timed out or could not start") from exc
    except BaseException:
        _terminate_processes(processes)
        raise
    finally:
        for handle in handles:
            handle.close()

    shard_reports: list[tuple[int, ET.Element, list[ET.Element]]] = []
    for shard_index, shard_nodes in enumerate(shard_inputs):
        metadata = shard_metadata[shard_index]
        observer = _read_observer(Path(str(metadata["observer"])), manifest_digest, shard_index, args.shards)
        counts = observer["setup_report_counts"]
        expected_counts = {node_id: 1 for node_id in shard_nodes}
        if counts != expected_counts:
            raise RuntimeError(f"pytest shard {shard_index} did not execute every node exactly once")
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
        lines.append(json.dumps(metadata, sort_keys=True))
        lines.append(f"--- shard {metadata['index']} log ---")
        lines.append(Path(str(metadata["log"])).read_text(encoding="utf-8"))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.log.write_text("\n".join(lines), encoding="utf-8")
    _write_json(args.report_dir / f"{args.suite}-shards.json", {"manifest": manifest_record, "shards": shard_metadata})
    return 0


def pytest_runtest_logreport(report):
    """Record exactly one setup report for every selected node in a shard."""
    if report.when != "setup":
        return
    path_value = os.environ.get("CI_SHARD_OBSERVER_REPORT")
    manifest_value = os.environ.get("CI_SHARD_MANIFEST")
    if not path_value or not manifest_value:
        return
    counts = getattr(pytest_runtest_logreport, "_counts", None)
    if counts is None:
        counts = {}
        pytest_runtest_logreport._counts = counts
    counts[report.nodeid] = counts.get(report.nodeid, 0) + 1


def pytest_sessionfinish(session, exitstatus):
    """Persist observer evidence even when pytest exits with failures."""
    path_value = os.environ.get("CI_SHARD_OBSERVER_REPORT")
    manifest_value = os.environ.get("CI_SHARD_MANIFEST")
    if not path_value or not manifest_value:
        return
    try:
        manifest = json.loads(Path(manifest_value).read_text(encoding="utf-8"))
        manifest_digest = manifest.get("sha256")
        counts = getattr(pytest_runtest_logreport, "_counts", {})
        record = {
            "schema": OBSERVER_SCHEMA,
            "manifest_sha256": manifest_digest,
            "shard_index": int(os.environ["CI_SHARD_INDEX"]),
            "shard_count": int(os.environ["CI_SHARD_COUNT"]),
            "pytest_exit_status": int(exitstatus),
            "setup_report_counts": dict(sorted(counts.items())),
        }
        _write_json(Path(path_value), record)
    except Exception as exc:  # pragma: no cover - the parent treats missing evidence as failure
        sys.stderr.write(f"failed to write pytest shard observer evidence: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
