"""Sidecar persistence and state-machine recovery across restarts."""

import json
import os
import threading

from logdissect.service import (
    FAILED,
    COMPLETED,
    RUNNING,
    JobStore,
    SIDECAR_EXT,
)
from conftest import wait_for_job


def test_sidecar_written_on_completion(service, syslog_file, workdir):
    job = service.submit(
        {
            "sources": [syslog_file],
            "output_path": str(workdir / "out.csv"),
        }
    )
    finished = wait_for_job(service, job["id"])
    sidecar = os.path.join(
        str(workdir / "jobs"), finished["id"] + SIDECAR_EXT
    )
    assert os.path.exists(sidecar)
    with open(sidecar, encoding="utf-8") as handle:
        persisted = json.load(handle)
    assert persisted["state"] == COMPLETED
    assert persisted["stats"]["hits"] == 4
    assert persisted["spec"]["output_path"] == str(workdir / "out.csv")


def test_running_job_marked_failed_after_restart(workdir, syslog_file):
    jobs_dir = str(workdir / "jobs2")
    store = JobStore(jobs_dir)
    job = store.create(
        "deadbeef",
        {
            "sources": [syslog_file],
            "output_path": str(workdir / "x.csv"),
            "format": "csv",
            "parser": None,
            "keep_unknown": False,
            "overwrite": False,
            "start": None,
            "end": None,
        },
    )
    store.update("deadbeef", state=RUNNING, stats={"hits": 3})

    # Simulate a fresh process rebuilding state from sidecars.
    revived = JobStore(jobs_dir)
    recovered = revived.get("deadbeef")
    assert recovered["state"] == FAILED
    assert recovered["error"] == "interrupted by process restart"
    assert recovered["stats"]["hits"] == 3


def test_completed_job_survives_restart(workdir, syslog_file):
    jobs_dir = str(workdir / "jobs3")
    store = JobStore(jobs_dir)
    store.create(
        "cafe01",
        {
            "sources": [syslog_file],
            "output_path": str(workdir / "y.csv"),
            "format": "csv",
            "parser": None,
            "keep_unknown": False,
            "overwrite": False,
            "start": None,
            "end": None,
        },
    )
    store.update(
        "cafe01",
        state=COMPLETED,
        stats={"hits": 4, "formats": {"syslog": 4}},
    )
    revived = JobStore(jobs_dir)
    recovered = revived.get("cafe01")
    assert recovered["state"] == COMPLETED
    assert recovered["stats"]["formats"] == {"syslog": 4}
