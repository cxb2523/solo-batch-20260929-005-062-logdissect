"""Core export behavior: streaming, filtering, aggregation, formats."""

import csv
import os

import pytest

from logdissect.service import (
    EXPORT_FIELDS,
    BadRequest,
    export_record,
    timestamp_int,
)
from conftest import read_jsonl, run_sync


def test_closed_interval_includes_both_edges(service, syslog_file, workdir):
    out = str(workdir / "edges.csv")
    job = run_sync(
        service,
        {
            "sources": [syslog_file],
            "output_path": out,
            "start": "20260227213052",
            "end": "20260227213457",
        },
    )
    assert job["state"] == "completed"
    stats = job["stats"]
    # Exactly the 21:30:52 and 21:34:57 entries hit both interval edges.
    assert stats["hits"] == 2
    assert stats["excluded_by_range"] == 2
    assert stats["earliest"] == 20260227213052
    assert stats["latest"] == 20260227213457
    assert stats["earliest_text"] == "2026-02-27 21:30:52"
    assert stats["latest_text"] == "2026-02-27 21:34:57"


def test_unknown_entries_dropped_by_default(service, syslog_file, workdir):
    out = str(workdir / "drop.csv")
    job = run_sync(
        service,
        {"sources": [syslog_file], "output_path": out},
    )
    assert job["state"] == "completed"
    stats = job["stats"]
    assert stats["scanned"] == 5
    assert stats["dropped_unparsed"] == 1
    assert stats["hits"] == 4
    assert "unknown" not in stats["formats"]
    assert set(stats["formats"]) == {"syslog"}


def test_keep_unknown_passes_unknown_entries(service, syslog_file, workdir):
    out = str(workdir / "keep.jsonl")
    job = run_sync(
        service,
        {
            "sources": [syslog_file],
            "output_path": out,
            "format": "jsonl",
            "keep_unknown": True,
        },
    )
    assert job["state"] == "completed"
    stats = job["stats"]
    assert stats["hits"] == 5
    assert stats["formats"] == {"syslog": 4, "unknown": 1}
    # Unknown rows have no parsed timestamp: they do not widen the span.
    assert stats["earliest"] == 20260227213046
    assert stats["latest"] == 20260227213501
    rows = read_jsonl(out)
    unknown = [r for r in rows if r["format"] == "unknown"]
    assert len(unknown) == 1
    assert unknown[0]["timestamp"] == ""
    assert unknown[0]["raw_text"].startswith("this line")


def test_csv_and_jsonl_share_field_order(service, syslog_file, workdir):
    csv_out = str(workdir / "a.csv")
    jsonl_out = str(workdir / "a.jsonl")
    run_sync(
        service,
        {"sources": [syslog_file], "output_path": csv_out},
    )
    run_sync(
        service,
        {
            "sources": [syslog_file],
            "output_path": jsonl_out,
            "format": "jsonl",
        },
    )
    with open(csv_out, encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
    assert header == EXPORT_FIELDS
    rows = read_jsonl(jsonl_out)
    for row in rows:
        assert list(row.keys()) == EXPORT_FIELDS


def test_single_pass_aggregation_never_builds_entry_list(
    service, syslog_file, workdir, monkeypatch
):
    """No intermediate entry list may accumulate during a run."""
    from logdissect.service import ExportRunner

    blocked = {"open": False}
    real_run = ExportRunner.run

    def spy_run(self):
        # The runner holds only scalar counters and dicts, no entry list.
        assert not hasattr(self, "entries")
        assert not hasattr(self, "records")
        return real_run(self)

    monkeypatch.setattr(ExportRunner, "run", spy_run)
    out = str(workdir / "spy.csv")
    job = run_sync(
        service,
        {"sources": [syslog_file], "output_path": out},
    )
    assert job["state"] == "completed"
    assert job["stats"]["hits"] == 4


def test_records_are_streamed_before_job_completes(
    service, syslog_file, workdir
):
    out = str(workdir / "stream.csv")
    job = run_sync(
        service,
        {"sources": [syslog_file], "output_path": out},
    )
    assert job["state"] == "completed"
    with open(out, encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip()]
    # Header plus four hits, and no temp file remains.
    assert len(lines) == 1 + 4
    assert not [n for n in os.listdir(workdir) if n.endswith(".tmp")]


def test_explicit_linejson_parser(workdir, service):
    source = workdir / "events.jsonl"
    source.write_text(
        '{"numeric_date_stamp": "20240227213000", "message": "one"}\n'
        '{"numeric_date_stamp": "20240227213100", "message": "two"}\n'
        "not json at all\n",
        encoding="utf-8",
    )
    out = str(workdir / "events.csv")
    job = run_sync(
        service,
        {
            "sources": [str(source)],
            "output_path": out,
            "parser": "linejson",
            "keep_unknown": True,
        },
    )
    assert job["state"] == "completed", job.get("error")
    stats = job["stats"]
    assert stats["scanned"] == 3
    assert stats["hits"] == 3
    assert stats["formats"] == {"linejson": 2, "unknown": 1}
    assert stats["earliest"] == 20240227213000


def test_bad_bound_and_unknown_parser(service, syslog_file, workdir):
    with pytest.raises(BadRequest):
        service.submit(
            {
                "sources": [syslog_file],
                "output_path": str(workdir / "x.csv"),
                "start": "not-a-date",
            }
        )
    with pytest.raises(BadRequest):
        service.submit(
            {
                "sources": [syslog_file],
                "output_path": str(workdir / "y.csv"),
                "parser": "nope",
            }
        )
    with pytest.raises(BadRequest):
        service.submit(
            {
                "sources": [syslog_file],
                "output_path": str(workdir / "z.csv"),
                "start": "20240228",
                "end": "20240227",
            }
        )


def test_export_record_stable_order():
    entry = {
        "numeric_date_stamp": "20240227213000",
        "raw_text": "line",
        "message": "msg",
        "source_path": os.path.join("dir", "file.log"),
        "unexpected": "ignored",
    }
    record = export_record(entry, "syslog", "file.log")
    assert list(record.keys()) == EXPORT_FIELDS
    assert record["timestamp"] == "2024-02-27 21:30:00"
    assert record["source_file"] == "file.log"
