"""Path conflict, overwrite, and same-path serialization."""

import os
import threading
import time

import pytest

from logdissect.service import PathConflict
from conftest import wait_for_job


def test_existing_path_returns_409_without_overwrite(
    service, syslog_file, workdir
):
    out = workdir / "taken.csv"
    out.write_text("preexisting\n", encoding="utf-8")
    with pytest.raises(PathConflict) as exc:
        service.submit(
            {"sources": [syslog_file], "output_path": str(out)}
        )
    assert exc.value.status == 409


def test_overwrite_must_be_explicit(service, syslog_file, workdir):
    out = workdir / "taken.csv"
    out.write_text("preexisting\n", encoding="utf-8")
    job = service.submit(
        {
            "sources": [syslog_file],
            "output_path": str(out),
            "overwrite": True,
        }
    )
    job = wait_for_job(service, job["id"])
    assert job["state"] == "completed"
    assert job["stats"]["hits"] == 4
    assert "preexisting" not in out.read_text(encoding="utf-8")


def test_second_submit_to_same_inflight_path_is_409(
    service, syslog_file, workdir
):
    out = str(workdir / "shared.csv")
    first = service.submit(
        {"sources": [syslog_file], "output_path": out}
    )
    try:
        # The path lock is held for the whole run; even with
        # overwrite=true the concurrent submission is rejected.
        with pytest.raises(PathConflict) as exc:
            service.submit(
                {
                    "sources": [syslog_file],
                    "output_path": out,
                    "overwrite": True,
                }
            )
        assert exc.value.status == 409
    finally:
        finished = wait_for_job(service, first["id"])
        assert finished["state"] == "completed"


def test_same_path_jobs_serialize_after_release(
    service, syslog_file, workdir
):
    out = str(workdir / "serial.csv")
    first = wait_for_job(
        service,
        service.submit(
            {"sources": [syslog_file], "output_path": out}
        )["id"],
    )
    assert first["state"] == "completed"
    # Lock released: an explicit overwrite is accepted again.
    second = service.submit(
        {
            "sources": [syslog_file],
            "output_path": out,
            "overwrite": True,
        }
    )
    second = wait_for_job(service, second["id"])
    assert second["state"] == "completed"


def test_distinct_paths_run_concurrently(service, syslog_file, workdir):
    entered = threading.Event()
    release = threading.Event()

    from logdissect.service import ExportRunner

    real_run = ExportRunner.run

    def gated_run(self):
        entered.set()
        release.wait(5)
        return real_run(self)

    ExportRunner.run = gated_run
    try:
        first = service.submit(
            {
                "sources": [syslog_file],
                "output_path": str(workdir / "one.csv"),
            }
        )
        assert entered.wait(2)
        # A different path submits immediately and is not blocked.
        second = service.submit(
            {
                "sources": [syslog_file],
                "output_path": str(workdir / "two.csv"),
            }
        )
        release.set()
        assert wait_for_job(service, first["id"])["state"] == "completed"
        assert wait_for_job(service, second["id"])["state"] == "completed"
    finally:
        ExportRunner.run = real_run
        release.set()


def test_no_temp_file_left_after_success(
    service, syslog_file, workdir
):
    out = str(workdir / "clean.csv")
    job = service.submit(
        {"sources": [syslog_file], "output_path": out}
    )
    wait_for_job(service, job["id"])
    leftovers = [
        n
        for n in os.listdir(workdir)
        if n.startswith(".clean.") and n.endswith(".tmp")
    ]
    assert leftovers == []
