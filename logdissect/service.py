"""Local resident log export service.

A thread-pool backed HTTP service that parses log files and exports them
to CSV or JSONL. Design rules enforced here:

* Time filtering compares successfully parsed UTC timestamps as a closed
  interval. Lines that fail to parse are dropped unless ``keep_unknown``
  is set; the report time span is computed only from parsed lines.
* Each input line is parsed, filtered, aggregated and streamed to disk in
  a single forward pass -- entries are never collected into a list.
* An existing output path yields HTTP 409 unless ``overwrite`` is set.
  Writes go to a temporary file followed by an atomic rename, and jobs
  targeting the same path are serialized with a per-path lock.
* Job state is persisted to a sidecar next to the output and recovered on
  process restart.
* The CSV column order and JSONL field names are generated from the same
  stable, reproducible schema.
"""

import csv
import html
import json
import os
import re
import sys
import threading
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import logdissect.parsers
import logdissect.utils
from logdissect.parsers.type import ParseModule

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8791
DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".logdissect", "service")

TERMINAL_STATES = frozenset({"succeeded", "failed", "interrupted"})

# Single source of truth for output field order. CSV columns and JSONL
# keys are both derived from this tuple, so output is reproducible.
EXPORT_FIELDS = (
    "timestamp_utc",
    "timestamp",
    "year",
    "month",
    "day",
    "tstamp",
    "tzone",
    "parser",
    "log_source",
    "source_process",
    "source_pid",
    "protocol",
    "source_host",
    "source_port",
    "dest_host",
    "dest_port",
    "severity",
    "action",
    "message",
    "raw_text",
    "source_path",
)

_MONTH_NUM = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_MONTH_PREFIX = re.compile(r"^([A-Z][a-z]{2})\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
_TIME_PREFIX = re.compile(r"^(\d{2}):(\d{2}):(\d{2})")


def _atomic_write(path, write_callback, mode="w", encoding="utf-8"):
    """Write to a temp file in the same directory, then atomically rename."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    tmp_path = "{}.{}.tmp".format(path, uuid.uuid4().hex)
    try:
        with open(tmp_path, mode, encoding=encoding, newline="") as tmp:
            write_callback(tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def atomic_write_json(path, payload):
    """Atomically write a JSON document."""
    _atomic_write(
        path,
        lambda fh: fh.write(json.dumps(payload, indent=2, sort_keys=True)),
    )


def parse_time_bound(value, bound_type):
    """Normalize a request time bound to a 14 digit YYYYMMDDHHMMSS string.

    ``bound_type`` is ``"start"`` (padded with zeros) or ``"end"``
    (padded with nines) so the comparison is a closed interval.
    """
    if value is None:
        return None
    digits = re.sub(r"[^0-9]", "", str(value))
    if not digits or len(digits) > 14:
        raise ValueError(
            "time bound must be YYYYMMDDHHMMSS (shorter values are allowed)"
        )
    pad = "0" if bound_type == "start" else "9"
    return (digits + pad * 14)[:14]


def _prescan_year_crossings(sourcepath):
    """Count forward month increases for standard datestamp logs.

    A forward increase (e.g. Jan -> Feb) marks a December -> January
    boundary seen while walking the file in file order. Each crossing
    pushes the earliest line one year further back from the file mtime
    year, matching logdissect's reverse-parse year assignment.
    """
    crossings = 0
    prev = None
    with open(sourcepath, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _MONTH_PREFIX.match(line)
            if not match:
                continue
            month = _MONTH_NUM[match.group(1)]
            if prev == 12 and month == 1:
                crossings += 1
            prev = month
    return crossings


def _prescan_day_crossings(sourcepath):
    """Count forward HHMMSS increases for time-only (nodate) logs."""
    crossings = 0
    prev = None
    with open(sourcepath, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _TIME_PREFIX.match(line)
            if not match:
                continue
            current = int(match.group(1) + match.group(2) + match.group(3))
            if prev is not None and current > prev:
                crossings += 1
            prev = current
    return crossings


def stream_entries(sourcepath, parser_name, tzone=None):
    """Yield ``(entry, parsed)`` tuples for one input file, line by line.

    ``entry`` is a dict on success; ``parsed`` is then True. Unparseable
    lines yield ``({"raw_text": line, "parser": "unknown"}, False)``.
    Nothing is buffered beyond a single line.
    """
    parser = _load_parser(parser_name)
    parser.date_regex = re.compile(r"{}".format(parser.format_regex))
    if parser.backup_format_regex:
        parser.backup_date_regex = re.compile(
            r"{}".format(parser.backup_format_regex)
        )
    if tzone:
        parser.tzone = tzone
    elif not parser.tzone:
        parser.backuptzone = logdissect.utils.get_local_tzone()

    source_abspath = os.path.abspath(sourcepath)
    mtime = os.path.getmtime(source_abspath)
    mtime_dt = datetime.fromtimestamp(mtime)

    if parser.datestamp_type == "standard":
        crossings = _prescan_year_crossings(sourcepath)
        entry_year = mtime_dt.year - crossings
        prev_month = None
    elif parser.datestamp_type == "nodate":
        day_crossings = _prescan_day_crossings(sourcepath)
        datedata = {
            "timestamp": datetime(mtime_dt.year, mtime_dt.month, mtime_dt.day)
            - _timedelta_days(day_crossings),
        }
    else:
        entry_year = None
        prev_month = None
        datedata = None

    with open(sourcepath, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            entry = parser.parse_line(line)
            if entry is None:
                yield {
                    "raw_text": line,
                    "parser": "unknown",
                    "source_path": source_abspath,
                }, False
                continue

            if "date_stamp" in entry:
                if parser.datestamp_type == "standard":
                    month_num = int(entry["month"])
                    if prev_month == 12 and month_num == 1:
                        entry_year += 1
                    prev_month = month_num
                    entry["numeric_date_stamp"] = (
                        str(entry_year)
                        + entry["month"]
                        + entry["day"]
                        + entry["tstamp"]
                    )
                    entry["year"] = str(entry_year)
                elif parser.datestamp_type == "nodate":
                    current_hms = int(
                        entry["tstamp"].split(".")[0]
                    )
                    if (
                        "entry_time" in datedata
                        and current_hms < datedata["entry_time"]
                    ):
                        datedata["timestamp"] = datedata["timestamp"] + _timedelta_days(1)
                    datedata["entry_time"] = current_hms
                    stamp = datedata["timestamp"]
                    entry["year"] = str(stamp.year)
                    entry["month"] = str(stamp.month).rjust(2, "0")
                    entry["day"] = str(stamp.day).rjust(2, "0")
                    entry["numeric_date_stamp"] = (
                        entry["year"] + entry["month"]
                        + entry["day"] + entry["tstamp"]
                    )

                entry["tzone"] = parser.tzone or parser.backuptzone
                entry = logdissect.utils.get_utc_date(entry)

            entry["raw_text"] = line
            entry["source_path"] = source_abspath
            yield entry, True


def _timedelta_days(count):
    from datetime import timedelta
    return timedelta(days=count)


def _load_parser(parser_name):
    module = __import__(
        "logdissect.parsers." + parser_name,
        globals(), locals(), [logdissect],
    )
    return module.ParseModule()


def _entry_utc_stamp(entry):
    """Return the entry's second-precision UTC stamp, or None."""
    stamp = entry.get("numeric_date_stamp_utc")
    if not stamp or stamp == "0":
        return None
    return stamp.split(".")[0][:14]


def _in_time_range(entry, start, end):
    """Closed-interval comparison on the parsed UTC timestamp."""
    stamp = _entry_utc_stamp(entry)
    if stamp is None:
        return False
    if start is not None and stamp < start:
        return False
    if end is not None and stamp > end:
        return False
    return True


def _canonical_record(entry):
    """Build an output record whose keys follow EXPORT_FIELDS first.

    Extra parser-specific keys are appended in sorted order, which keeps
    the output stable and reproducible while never losing data.
    """
    record = {}
    enriched = dict(entry)
    utc_stamp = entry.get("numeric_date_stamp_utc")
    if utc_stamp and utc_stamp != "0":
        base = utc_stamp.split(".")[0]
        enriched["timestamp_utc"] = "{}-{}-{}T{}:{}:{}Z".format(
            base[0:4], base[4:6], base[6:8],
            base[8:10], base[10:12], base[12:14],
        )
    if entry.get("date_stamp") and not entry.get("timestamp"):
        enriched["timestamp"] = entry["date_stamp"]
    for key in EXPORT_FIELDS:
        value = enriched.get(key)
        record[key] = "" if value is None else value
    for key in sorted(entry):
        if key not in record:
            value = entry[key]
            record[key] = "" if value is None else value
    return record


def _write_csv_row(writer, record):
    writer.writerow([record.get(key, "") for key in record])


def run_export(job, progress_callback=None):
    """Execute one export job: single-pass parse, filter, aggregate, write.

    Returns the final stats dict. The output is written to a temp file
    and atomically renamed only after the full pass succeeds.
    """
    output_path = os.path.abspath(job["output_path"])
    fmt = job["format"]
    start = job.get("start")
    end = job.get("end")
    keep_unknown = bool(job.get("keep_unknown"))
    parser_name = job["parser"]
    tzone = job.get("tzone")

    hits = 0
    dropped_unknown = 0
    dropped_outside_range = 0
    parsed_count = 0
    format_counts = Counter()
    min_stamp = None
    max_stamp = None

    tmp_path = job.get("tmp_path") or "{}.{}.tmp".format(output_path, uuid.uuid4().hex)
    job["tmp_path"] = tmp_path
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    def update_stats():
        job["stats"] = {
            "hits": hits,
            "parsed": parsed_count,
            "dropped_unknown": dropped_unknown,
            "dropped_outside_range": dropped_outside_range,
            "format_distribution": dict(sorted(format_counts.items())),
            "first_timestamp_utc": min_stamp,
            "last_timestamp_utc": max_stamp,
        }

    lines_seen = 0
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="") as out:
            if fmt == "csv":
                writer = csv.DictWriter(out, fieldnames=list(EXPORT_FIELDS), extrasaction="ignore")
                writer.writeheader()
            for source in job["inputs"]:
                for entry, parsed in stream_entries(source, parser_name, tzone):
                    if not parsed:
                        if keep_unknown:
                            record = _canonical_record(entry)
                        else:
                            dropped_unknown += 1
                            continue
                    else:
                        if not _in_time_range(entry, start, end):
                            dropped_outside_range += 1
                            continue
                        record = _canonical_record(entry)
                        parsed_count += 1
                        stamp = _entry_utc_stamp(entry)
                        if stamp is not None:
                            min_stamp = stamp if min_stamp is None else min(min_stamp, stamp)
                            max_stamp = stamp if max_stamp is None else max(max_stamp, stamp)

                    if fmt == "csv":
                        writer.writerow(record)
                    else:
                        out.write(json.dumps(record, ensure_ascii=False) + "\n")

                    hits += 1
                    format_counts[record["parser"] or "unknown"] += 1
                    lines_seen += 1
                    if progress_callback and lines_seen % 1000 == 0:
                        update_stats()
                        progress_callback(job)
            out.flush()
            os.fsync(out.fileno())

        update_stats()
        os.replace(tmp_path, output_path)
        return job["stats"]
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass



SIDECAR_SUFFIX = ".logdissect-job.json"


def sidecar_path_for(output_path):
    return os.path.abspath(output_path) + SIDECAR_SUFFIX


class JobConflictError(Exception):
    """Raised when an output path is already claimed (HTTP 409)."""


class JobValidationError(Exception):
    """Raised for malformed export requests (HTTP 400)."""


class JobManager:
    """Owns job records, sidecars, per-path locks and worker threads."""

    def __init__(self, state_dir=DEFAULT_STATE_DIR, max_workers=4):
        self.state_dir = os.path.abspath(state_dir)
        os.makedirs(self.state_dir, exist_ok=True)
        self.index_path = os.path.join(self.state_dir, "jobs.json")
        self.jobs = {}
        self._path_active = {}
        self._path_locks = {}
        self._path_guard = threading.Lock()
        self._jobs_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="logdissect-export"
        )
        self._recover()

    def _load_index(self):
        try:
            with open(self.index_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write_index_locked(self):
        payload = {
            job_id: job["sidecar_path"] for job_id, job in self.jobs.items()
        }
        atomic_write_json(self.index_path, payload)

    def _recover(self):
        """Reload job state from sidecars after a process restart."""
        index = self._load_index()
        for job_id, sidecar in index.items():
            try:
                with open(sidecar, "r", encoding="utf-8") as handle:
                    job = json.load(handle)
            except (OSError, ValueError):
                continue
            status = job.get("status")
            if status not in TERMINAL_STATES:
                output_exists = os.path.exists(job.get("output_path", ""))
                tmp_path = job.get("tmp_path")
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                if status == "running" and output_exists:
                    job["status"] = "succeeded"
                    job.setdefault("stats", {})
                else:
                    job["status"] = "interrupted"
                    job["error"] = "interrupted by process restart"
                self._persist(job)
            self.jobs[job_id] = job

    def _persist(self, job):
        atomic_write_json(job["sidecar_path"], job)
        self._write_index_locked()

    def get_job(self, job_id):
        with self._jobs_lock:
            return self.jobs.get(job_id)

    def list_jobs(self):
        with self._jobs_lock:
            return list(self.jobs.keys())

    def _path_lock(self, path):
        with self._path_guard:
            lock = self._path_locks.get(path)
            if lock is None:
                lock = threading.Lock()
                self._path_locks[path] = lock
            return lock

    def submit(self, spec):
        """Validate a request and queue an export job."""
        try:
            inputs = spec["inputs"]
            output_path = os.path.abspath(spec["output_path"])
        except (KeyError, TypeError):
            raise JobValidationError("inputs and output_path are required")

        if not isinstance(inputs, list) or not inputs:
            raise JobValidationError("inputs must be a non-empty list")
        missing = [path for path in inputs if not os.path.isfile(path)]
        if missing:
            raise JobValidationError("input not found: " + ", ".join(missing))

        fmt = spec.get("format", "jsonl")
        if fmt not in ("csv", "jsonl"):
            raise JobValidationError("format must be 'csv' or 'jsonl'")
        parser_name = spec.get("parser", "syslog")
        if parser_name not in logdissect.parsers.__all__:
            raise JobValidationError("unknown parser: " + parser_name)

        try:
            start = parse_time_bound(spec.get("start"), "start")
            end = parse_time_bound(spec.get("end"), "end")
        except ValueError as exc:
            raise JobValidationError(str(exc))
        if start and end and start > end:
            raise JobValidationError("start is later than end")

        overwrite = bool(spec.get("overwrite", False))
        keep_unknown = bool(spec.get("keep_unknown", False))

        with self._path_guard:
            if self._path_active.get(output_path):
                raise JobConflictError(
                    "a queued or running job already targets this path"
                )
            if os.path.exists(output_path) and not overwrite:
                raise JobConflictError(
                    "output path already exists; resubmit with overwrite=true"
                )
            self._path_active[output_path] = True

        job_id = uuid.uuid4().hex[:12]
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        job = {
            "id": job_id,
            "status": "queued",
            "inputs": [os.path.abspath(p) for p in inputs],
            "output_path": output_path,
            "sidecar_path": sidecar_path_for(output_path),
            "format": fmt,
            "parser": parser_name,
            "tzone": spec.get("tzone"),
            "start": start,
            "end": end,
            "keep_unknown": keep_unknown,
            "overwrite": overwrite,
            "submitted_at": now,
            "started_at": None,
            "finished_at": None,
            "error": None,
            "stats": None,
            "tmp_path": None,
        }
        with self._jobs_lock:
            self.jobs[job_id] = job
            self._write_index_locked()
        self._persist(job)
        self.executor.submit(self._run_job, job_id, output_path)
        return job

    def _run_job(self, job_id, output_path):
        path_lock = self._path_lock(output_path)
        with path_lock:
            job = self.get_job(job_id)
            if job is None:
                self._release_path(output_path)
                return
            if os.path.exists(output_path) and not job.get("overwrite"):
                job["status"] = "failed"
                job["error"] = "output path already exists"
                job["finished_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                self._persist(job)
                self._release_path(output_path)
                return
            job["status"] = "running"
            job["started_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            tmp_path = job.get("tmp_path") or "{}.{}.tmp".format(output_path, uuid.uuid4().hex)
            job["tmp_path"] = tmp_path
            self._persist(job)
            try:
                if job.get("overwrite") and os.path.exists(output_path):
                    os.remove(output_path)
                stats = run_export(job, progress_callback=self._persist)
                job["stats"] = stats
                job["status"] = "succeeded"
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = str(exc) or exc.__class__.__name__
            finally:
                job["tmp_path"] = None
                job["finished_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                self._persist(job)
                self._release_path(output_path)

    def _release_path(self, output_path):
        with self._path_guard:
            self._path_active.pop(output_path, None)

    def shutdown(self):
        self.executor.shutdown(wait=False, cancel_futures=True)



def _format_stamp(stamp):
    """Render a YYYYMMDDHHMMSS stamp as YYYY-MM-DD HH:MM:SS (UTC)."""
    if not stamp:
        return "-"
    return "{}-{}-{} {}:{}:{}".format(
        stamp[0:4], stamp[4:6], stamp[6:8],
        stamp[8:10], stamp[10:12], stamp[12:14],
    )


def render_report(job):
    """Render the summary HTML page for one job."""
    stats = job.get("stats") or {}
    distribution = stats.get("format_distribution", {})
    rows = "".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(name)), html.escape(str(count))
        )
        for name, count in sorted(distribution.items())
    )
    first = _format_stamp(stats.get("first_timestamp_utc"))
    last = _format_stamp(stats.get("last_timestamp_utc"))

    def cell(key):
        return html.escape(str(stats.get(key, 0)))

    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Export job {id}</title></head>
<body>
<h1>Export job {id}</h1>
<p><strong>Status:</strong> {status}</p>
<p><strong>Parser:</strong> {parser} &nbsp; <strong>Format:</strong> {fmt}</p>
<p><strong>Output:</strong> {output}</p>
<h2>Summary</h2>
<table border="1" cellpadding="4">
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Hits written</td><td>{hits}</td></tr>
<tr><td>Parsed entries</td><td>{parsed}</td></tr>
<tr><td>Dropped (unparseable)</td><td>{dropped_unknown}</td></tr>
<tr><td>Dropped (outside time range)</td><td>{dropped_range}</td></tr>
<tr><td>Time span start (UTC)</td><td>{first}</td></tr>
<tr><td>Time span end (UTC)</td><td>{last}</td></tr>
</table>
<h2>Format distribution</h2>
<table border="1" cellpadding="4">
<tr><th>Format</th><th>Count</th></tr>
{rows}
</table>
{error}
</body>
</html>
""".format(
        id=html.escape(job["id"]),
        status=html.escape(job["status"]),
        parser=html.escape(job["parser"]),
        fmt=html.escape(job["format"]),
        output=html.escape(job["output_path"]),
        hits=cell("hits"),
        parsed=cell("parsed"),
        dropped_unknown=cell("dropped_unknown"),
        dropped_range=cell("dropped_outside_range"),
        first=html.escape(first),
        last=html.escape(last),
        rows=rows or "<tr><td>-</td><td>0</td></tr>",
        error="<p><strong>Error:</strong> {}</p>".format(
            html.escape(job["error"])
        ) if job.get("error") else "",
    )


_JOB_ROUTE = re.compile(r"^/jobs/([A-Za-z0-9_-]+)$")
_REPORT_ROUTE = re.compile(r"^/jobs/([A-Za-z0-9_-]+)/report$")


class ExportHandler(BaseHTTPRequestHandler):
    manager = None

    def log_message(self, fmt, *args):
        sys.stderr.write("[service] " + fmt % args + "\n")

    def _send_json(self, code, payload, extra_headers=None):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/export":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            spec = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send_json(400, {"error": "request body must be JSON"})
            return
        try:
            job = self.manager.submit(spec)
        except JobValidationError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except JobConflictError as exc:
            self._send_json(409, {"error": str(exc)})
            return
        self._send_json(
            202,
            job,
            {"Location": "/jobs/{}".format(job["id"])},
        )

    def do_GET(self):
        match = _REPORT_ROUTE.match(self.path)
        if match:
            job = self.manager.get_job(match.group(1))
            if job is None:
                self._send_json(404, {"error": "unknown job id"})
                return
            self._send_html(200, render_report(job))
            return

        match = _JOB_ROUTE.match(self.path)
        if match:
            job = self.manager.get_job(match.group(1))
            if job is None:
                self._send_json(404, {"error": "unknown job id"})
                return
            self._send_json(200, job)
            return

        if self.path in ("/", "/health"):
            self._send_json(200, {"status": "ok", "jobs": len(self.manager.jobs)})
            return

        self._send_json(404, {"error": "not found"})


def serve(host=DEFAULT_HOST, port=DEFAULT_PORT, state_dir=DEFAULT_STATE_DIR,
          max_workers=4):
    manager = JobManager(state_dir=state_dir, max_workers=max_workers)
    handler = ExportHandler
    handler.manager = manager
    httpd = ThreadingHTTPServer((host, port), handler)
    sys.stderr.write(
        "[service] logdissect export service on http://{}:{}\n".format(
            host, port
        )
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        manager.shutdown()


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="logdissect export service")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.state_dir, args.workers)


if __name__ == "__main__":
    main()

