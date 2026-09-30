"""HTTP surface for the export service."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from logdissect.service import create_server


@pytest.fixture
def http_server(workdir):
    server = create_server(
        host="127.0.0.1",
        port=0,
        jobs_dir=str(workdir / "http-jobs"),
        max_workers=2,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = "http://%s:%d" % (host, port)
    yield base, server.service
    server.shutdown()
    server.service.shutdown()
    thread.join(timeout=2)


def _request(base, method, path, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def test_full_http_lifecycle_and_409(http_server, syslog_file, workdir):
    base, service = http_server
    out = str(workdir / "http.csv")
    body = {"sources": [syslog_file], "output_path": out}

    status, text = _request(base, "POST", "/export", body)
    assert status == 202
    job_id = json.loads(text)["id"]

    import time

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status, text = _request(base, "GET", "/jobs/" + job_id)
        assert status == 200
        if json.loads(text)["state"] == "completed":
            break
        time.sleep(0.02)
    assert json.loads(text)["state"] == "completed"

    # Resubmitting to the same existing path without overwrite -> 409.
    status, text = _request(base, "POST", "/export", body)
    assert status == 409
    assert "already exists" in json.loads(text)["message"]

    # Explicit overwrite is accepted.
    body_overwrite = dict(body, overwrite=True)
    status, text = _request(base, "POST", "/export", body_overwrite)
    assert status == 202
    second_id = json.loads(text)["id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status, text = _request(base, "GET", "/jobs/" + second_id)
        if json.loads(text)["state"] in ("completed", "failed"):
            break
        time.sleep(0.02)
    assert json.loads(text)["state"] == "completed"

    status, report = _request(base, "GET", "/jobs/" + second_id + "/report")
    assert status == 200
    assert "<h1>Export report</h1>" in report
    assert "syslog" in report
    assert "<h2>Format distribution</h2>" in report


def test_unknown_job_404(http_server):
    base, _ = http_server
    status, _ = _request(base, "GET", "/jobs/nope")
    assert status == 404
    status, _ = _request(base, "GET", "/jobs/nope/report")
    assert status == 404


def test_bad_payload_400(http_server, workdir):
    base, _ = http_server
    status, text = _request(
        base,
        "POST",
        "/export",
        {"sources": [], "output_path": str(workdir / "x.csv")},
    )
    assert status == 400
