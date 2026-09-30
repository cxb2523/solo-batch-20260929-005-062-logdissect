"""Unit tests for logdissect.service."""

import csv
import json
import os
import threading
import time
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

import pytest

from logdissect.service import (
    EXPORT_FIELDS,
    JobConflictError,
    JobManager,
    JobValidationError,
    ExportHandler,
    parse_time_bound,
    run_export,
    sidecar_path_for,
    stream_entries,
)


SAMPLE_LINES = [
    "Feb 27 21:30:46 shade hostd[1]: first entry",
    "garbage line that matches nothing",
    "Feb 27 21:31:00 shade worker[2]: second entry",
]


@pytest.fixture
def workspace(tmp_path):
    src = tmp_path / "input.log"
    src.write_text("\n".join(SAMPLE_LINES) + "\n", encoding="utf-8")
    os.utime(str(src), (1740700800, 1740700800))  # 2025-02-28 UTC
    return tmp_path


def make_job(workspace, fmt="jsonl", keep_unknown=False, start=None, end=None,
             overwrite=False, name="out.jsonl"):
    return {
        "id": "job-1",
        "inputs": [str(workspace / "input.log")],
        "output_path": str(workspace / name),
        "format": fmt,
        "parser": "syslog",
        "tzone": "+0000",
        "start": start,
        "end": end,
        "keep_unknown": keep_unknown,
        "overwrite": overwrite,
        "stats": None,
    }


def test_stream_parses_and_marks_unknown(workspace):
    results = list(stream_entries(str(workspace / "input.log"),
                                  "syslog", tzone="+0000"))
    assert len(results) == 3
    assert [parsed for _, parsed in results] == [True, False, True]
    first = results[0][0]
    assert first["numeric_date_stamp_utc"].startswith("20250227213046")
    assert first["log_source"] == "shade"
    assert results[1][0]["parser"] == "unknown"


def test_export_streams_jsonl_and_aggregates(workspace):
    out = workspace / "out.jsonl"
    stats = run_export(make_job(workspace))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["message"] == "first entry"
    assert list(record)[:len(EXPORT_FIELDS)] == list(EXPORT_FIELDS)
    assert stats["hits"] == 2
    assert stats["parsed"] == 2
    assert stats["dropped_unknown"] == 1
    assert stats["format_distribution"] == {"syslog": 2}
    assert stats["first_timestamp_utc"] == "20250227213046"
    assert stats["last_timestamp_utc"] == "20250227213100"


def test_keep_unknown_passes_garbage_but_not_span(workspace):
    out = workspace / "kept.jsonl"
    job = make_job(workspace, name="kept.jsonl", keep_unknown=True)
    stats = run_export(job)
    records = [json.loads(line)
               for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 3
    assert records[1]["parser"] == "unknown"
    assert records[1]["timestamp_utc"] == ""
    assert stats["hits"] == 3
    assert stats["dropped_unknown"] == 0
    assert stats["format_distribution"] == {"syslog": 2, "unknown": 1}
    assert stats["first_timestamp_utc"] == "20250227213046"
    assert stats["last_timestamp_utc"] == "20250227213100"


def test_closed_interval_time_filter(workspace):
    out = workspace / "ranged.jsonl"
    job = make_job(workspace, name="ranged.jsonl",
                   start="20250227213046", end="20250227213046")
    stats = run_export(job)
    records = [json.loads(line)
               for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["message"] == "first entry"
    assert stats["dropped_outside_range"] == 1


def test_csv_and_jsonl_share_schema(workspace):
    csv_job = make_job(workspace, fmt="csv", name="a.csv")
    run_export(csv_job)
    with open(str(workspace / "a.csv"), newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    json_job = make_job(workspace, fmt="jsonl", name="b.jsonl")
    run_export(json_job)
    record = json.loads(
        (workspace / "b.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert header == list(EXPORT_FIELDS)
    assert list(record)[:len(EXPORT_FIELDS)] == header


def test_parse_time_bound_pads_closed_interval():
    assert parse_time_bound("20250227213046", "start") == "20250227213046"
    assert parse_time_bound("2025022721", "end") == "20250227219999"
    assert parse_time_bound("2025022721", "start") == "20250227210000"
    with pytest.raises(ValueError):
        parse_time_bound("not-a-date", "start")


def test_existing_path_conflict_and_overwrite(workspace):
    manager = JobManager(state_dir=str(workspace / "state"))
    out = str(workspace / "conflict.jsonl")
    spec = {"inputs": [str(workspace / "input.log")], "output_path": out,
            "parser": "syslog", "tzone": "+0000"}
    job = manager.submit(spec)
    manager.executor.shutdown(wait=True)
    assert job["status"] == "succeeded"

    manager2 = JobManager(state_dir=str(workspace / "state"))
    with pytest.raises(JobConflictError):
        manager2.submit(spec)
    job2 = manager2.submit(dict(spec, overwrite=True))
    manager2.executor.shutdown(wait=True)
    assert job2["status"] == "succeeded"
    manager2.shutdown()


def test_invalid_spec(workspace):
    manager = JobManager(state_dir=str(workspace / "state2"))
    with pytest.raises(JobValidationError):
        manager.submit({"inputs": [], "output_path": "x.jsonl"})
    with pytest.raises(JobValidationError):
        manager.submit({
            "inputs": [str(workspace / "input.log")],
            "output_path": str(workspace / "x"),
            "format": "xml",
        })
    with pytest.raises(JobValidationError):
        manager.submit({
            "inputs": [str(workspace / "missing.log")],
            "output_path": str(workspace / "x"),
        })
    manager.shutdown()


def test_same_path_serialized_with_lock(workspace, monkeypatch):
    big = workspace / "big.log"
    lines = []
    for minute in range(120):
        lines.append("Feb 27 {:02d}:{:02d}:00 shade h[{}]: m{}".format(
            21 + minute // 60, minute % 60, minute, minute))
    big.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.utime(str(big), (1740700800, 1740700800))

    manager = JobManager(state_dir=str(workspace / "state3"), max_workers=4)
    original_persist = manager._persist
    hold = threading.Event()

    def slow_persist(job):
        if job["status"] == "running" and not hold.is_set():
            hold.set()
            time.sleep(0.6)
        return original_persist(job)

    monkeypatch.setattr(manager, "_persist", slow_persist)
    out = str(workspace / "same.jsonl")
    base = {"inputs": [str(big)], "output_path": out, "parser": "syslog",
            "tzone": "+0000"}
    manager.submit(base)
    hold.wait(2)
    with pytest.raises(JobConflictError):
        manager.submit(base)
    manager.executor.shutdown(wait=True)
    manager.shutdown()


def test_sidecar_recovery_after_restart(workspace):
    state = str(workspace / "state4")
    out = str(workspace / "rec.jsonl")
    sidecar = sidecar_path_for(out)
    manager = JobManager(state_dir=state)
    job = manager.submit({
        "inputs": [str(workspace / "input.log")],
        "output_path": out,
        "parser": "syslog",
        "tzone": "+0000",
    })
    manager.executor.shutdown(wait=True)
    assert job["status"] == "succeeded"
    assert os.path.exists(sidecar)

    restarted = JobManager(state_dir=state)
    loaded = restarted.get_job(job["id"])
    assert loaded["status"] == "succeeded"
    assert loaded["stats"]["hits"] == 2
    restarted.shutdown()


def test_interrupted_running_job_recovered(workspace):
    state = str(workspace / "state5")
    manager = JobManager(state_dir=state)
    out = str(workspace / "gone.jsonl")
    tmp = str(workspace / "partial-download.tmp")
    with open(tmp, "w") as fh:
        fh.write("partial")
    job = {
        "id": "crashed-job",
        "status": "running",
        "inputs": [str(workspace / "input.log")],
        "output_path": out,
        "sidecar_path": sidecar_path_for(out),
        "format": "jsonl",
        "parser": "syslog",
        "tzone": "+0000",
        "start": None,
        "end": None,
        "keep_unknown": False,
        "overwrite": False,
        "submitted_at": None,
        "started_at": None,
        "finished_at": None,
        "error": None,
        "stats": None,
        "tmp_path": tmp,
    }
    manager.jobs[job["id"]] = job
    manager._persist(job)
    manager.shutdown()

    restarted = JobManager(state_dir=state)
    recovered = restarted.get_job(job["id"])
    assert recovered["status"] == "interrupted"
    assert not os.path.exists(tmp)
    restarted.shutdown()


@pytest.fixture
def http_server(workspace):
    manager = JobManager(
        state_dir=str(workspace / "state-http"), max_workers=2
    )
    handler = ExportHandler
    handler.manager = manager
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield "http://{}:{}".format(host, port), manager
    server.shutdown()
    server.server_close()
    manager.shutdown()


def _request(base, method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_http_endpoints_and_409(http_server, workspace):
    base, manager = http_server
    out = str(workspace / "http.jsonl")
    spec = {"inputs": [str(workspace / "input.log")], "output_path": out,
            "parser": "syslog", "tzone": "+0000"}
    code, body = _request(base, "POST", "/export", spec)
    assert code == 202
    job_id = json.loads(body)["id"]

    deadline = time.time() + 10
    while time.time() < deadline:
        code, body = _request(base, "GET", "/jobs/" + job_id)
        if json.loads(body)["status"] == "succeeded":
            break
        time.sleep(0.1)
    assert code == 200
    assert json.loads(body)["stats"]["hits"] == 2

    code, body = _request(base, "POST", "/export", spec)
    assert code == 409
    assert "already exists" in json.loads(body)["error"]

    code, body = _request(base, "GET", "/jobs/" + job_id + "/report")
    assert code == 200
    assert "Hits written" in body
    assert ">2<" in body
    assert "2025-02-27 21:30:46" in body
    assert "2025-02-27 21:31:00" in body
    assert "syslog" in body

    code, _ = _request(base, "GET", "/jobs/nope")
    assert code == 404
