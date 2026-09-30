"""Fixtures shared by the export service tests."""

import json
import os

import pytest

from logdissect.service import ExportService


SYSLOG_LINES = [
    "Feb 27 21:30:46 shade dbus[593]: started hostname service",
    "Feb 27 21:30:52 shade systemd[1]: started terminal server",
    "this line does not look like any supported log",
    "Feb 27 21:34:57 shade tracker[22716]: permission denied",
    "Feb 27 21:35:01 shade CRON[5030]: periodic job ran",
]


@pytest.fixture
def workdir(tmp_path):
    return tmp_path


@pytest.fixture
def syslog_file(workdir):
    path = workdir / "messages.log"
    path.write_text("\n".join(SYSLOG_LINES) + "\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def service(workdir):
    svc = ExportService(str(workdir / "jobs"), max_workers=2)
    yield svc
    svc.shutdown()


def wait_for_job(service, job_id, timeout=5.0):
    """Poll the job store until the job reaches a terminal state."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = service.store.get(job_id)
        if job["state"] in ("completed", "failed"):
            return job
        time.sleep(0.02)
    raise AssertionError("job %s did not finish" % job_id)


def run_sync(service, payload):
    """Submit a job and block until it finishes."""
    job = service.submit(payload)
    return wait_for_job(service, job["id"])


def read_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows
