"""Local resident log export service.

A thread-pool HTTP service that exports parsed log entries to CSV or
JSONL files.  Design constraints (all three decisions interlock):

* Time filtering is a closed interval compared on parsed timestamps.
* Entries that fail to parse are dropped by default; ``keep_unknown``
  keeps them, and they never contribute to the report time span, which
  is computed solely from successfully parsed entries.
* Records are streamed to disk one at a time; the hit count and format
  distribution are accumulated in a single online pass (no entry list
  is ever built).

Output is written through a temporary file plus an atomic rename.  An
existing destination yields HTTP 409 unless ``overwrite`` is declared,
and concurrent jobs targeting the same path are serialized with a
per-path lock.  Job state is persisted to a sidecar JSON file so the
state machine can be recovered after a process restart.
"""

import csv
import io
import json
import os
import re
import threading
import time
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# The bundled parser modules predate raw-string regex literals;
# silence their (pre-existing) invalid escape SyntaxWarnings.
warnings.filterwarnings("ignore", category=SyntaxWarning)

import logdissect.parsers
import logdissect.utils


# CSV columns and JSONL field names are generated from the same source
# so the order is stable and reproducible across formats.
EXPORT_FIELDS = [
    "timestamp",
    "format",
    "source_file",
    "raw_text",
    "message",
]
EXPORT_FORMATS = ("csv", "jsonl")

# Job states:
QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
TERMINAL_STATES = (COMPLETED, FAILED)

SIDECAR_EXT = ".job.json"
TEMP_SUFFIX = ".tmp"


class JobError(Exception):
    """Base class for job submission errors."""

    status = 400


class BadRequest(JobError):
    """The request payload is invalid."""

    status = 400


class PathConflict(JobError):
    """The output path already exists or a job owns it."""

    status = 409


class NotFound(JobError):
    """The referenced job does not exist."""

    status = 404


def parse_bound(value):
    """Parse a time-filter bound into ``YYYYMMDDHHMMSS`` digits."""
    if isinstance(value, bool) or value is None:
        raise BadRequest("time bound must be a string")
    text = str(value).strip()
    if not text:
        raise BadRequest("time bound must not be empty")
    digits = re.sub(r"[^0-9]", "", text)
    if len(digits) < 8 or len(digits) > 14 or not digits.isdigit():
        raise BadRequest(
            "invalid time bound %r (use YYYYMMDDHHMMSS)" % value
        )
    if not (1 <= int(digits[4:6]) <= 12 and 1 <= int(digits[6:8]) <= 31):
        raise BadRequest(
            "invalid time bound %r (need at least YYYYMMDD)" % value
        )
    return digits


def normalize_start(value):
    """Pad a start bound with zeros: the left edge of the interval."""
    return int(parse_bound(value).ljust(14, "0"))


def normalize_end(value):
    """Pad an end bound with nines: the right edge of the interval."""
    return int(parse_bound(value).ljust(14, "9"))


def timestamp_int(entry):
    """Return a comparable 14-digit timestamp int for a parsed entry.

    ``numeric_date_stamp`` is the local compact timestamp used by every
    regex-based parser; linejson entries may carry their own stamped
    fields.  Returns ``None`` when no usable timestamp exists.
    """
    # Closed-interval filtering compares the parsed local timestamp,
    # matching logdissect.filters.range (numeric_date_stamp).  The UTC
    # variant is only a fallback for data that carries nothing else.
    stamp = entry.get("numeric_date_stamp")
    if stamp is None:
        stamp = entry.get("numeric_date_stamp_utc")
    if stamp is None:
        return None
    digits = str(stamp).split(".", 1)[0]
    if not digits.isdigit():
        return None
    return int(digits.ljust(14, "0")[:14])


def display_timestamp(value):
    """Render a 14-digit timestamp as ``YYYY-MM-DD HH:MM:SS``."""
    text = str(value).zfill(14)
    return "%s-%s-%s %s:%s:%s" % (
        text[0:4],
        text[4:6],
        text[6:8],
        text[8:10],
        text[10:12],
        text[12:14],
    )


def _stamp_standard(entry, year, tzone):
    """Attach a compact timestamp to a forward-parsed standard entry."""
    entry["year"] = str(entry.get("year") or year)
    entry["numeric_date_stamp"] = (
        entry["year"] + entry["month"] + entry["day"] + entry["tstamp"]
    )
    entry["tzone"] = entry.get("tzone") or tzone
    return logdissect.utils.get_utc_date(entry)


def _stamp_nodate(entry, state, tzone):
    """Attach timestamps to a nodate (time-only) entry, forward order."""
    current = int(entry["tstamp"].split(".", 1)[0])
    if state["last_time"] is not None and current < state["last_time"]:
        state["timestamp"] -= timedelta(days=1)
    state["last_time"] = current
    stamp = state["timestamp"]
    entry["year"] = str(stamp.year)
    entry["month"] = "%02d" % stamp.month
    entry["day"] = "%02d" % stamp.day
    entry["numeric_date_stamp"] = (
        entry["year"] + entry["month"] + entry["day"] + entry["tstamp"]
    )
    entry.setdefault("tzone", tzone)
    return logdissect.utils.get_utc_date(entry)

class ParserCatalog:
    """Lazily instantiated, reusable logdissect parser collection."""

    # sojson consumes a whole JSON document and cannot stream per line.
    UNSUPPORTED = ("sojson", "blank")

    def __init__(self):
        self._modules = None
        self._compiled = None
        self._tzone = logdissect.utils.get_local_tzone()

    def _load(self):
        modules = {}
        for name in sorted(logdissect.parsers.__all__):
            if name in self.UNSUPPORTED:
                continue
            module = __import__(
                "logdissect.parsers." + name,
                globals(),
                locals(),
                [logdissect],
            ).ParseModule()
            modules[name] = module
        compiled = []
        for name in sorted(modules):
            module = modules[name]
            if getattr(module, "format_regex", None):
                module.date_regex = re.compile(
                    r"{}".format(module.format_regex)
                )
                backup = None
                if module.backup_format_regex:
                    module.backup_date_regex = re.compile(
                        r"{}".format(module.backup_format_regex)
                    )
                    backup = module.backup_date_regex
                compiled.append(
                    (name, module, module.date_regex, backup)
                )
        return modules, compiled

    @property
    def modules(self):
        if self._modules is None:
            self._modules, self._compiled = self._load()
        return self._modules

    def get(self, name):
        if name in self.UNSUPPORTED or name not in self.modules:
            raise BadRequest("unknown parser %r" % name)
        return self.modules[name]

    def detect(self, line):
        """Auto-detect the first regex parser matching ``line``."""
        if self._compiled is None:
            self._modules, self._compiled = self._load()
        for name, module, regex, backup_regex in self._compiled:
            if regex.search(line) or (
                backup_regex is not None and backup_regex.search(line)
            ):
                return name, module
        return None

    def parse_line(self, module, line, source_state):
        """Parse one line, completing timestamp fields for streaming."""
        datestamp_type = getattr(module, "datestamp_type", None)
        if datestamp_type is None and module.name == "linejson":
            try:
                entry = module.parse_line(line)
            except (ValueError, TypeError):
                return None
            return entry if isinstance(entry, dict) else None
        if datestamp_type is None:
            return module.parse_line(line)

        entry = module.parse_line(line)
        if entry is None or "date_stamp" not in entry:
            return entry
        tzone = module.tzone or self._tzone
        if datestamp_type == "standard":
            entry = _stamp_standard(entry, source_state["year"], tzone)
        elif datestamp_type == "nodate":
            entry = _stamp_nodate(entry, source_state["nodate"], tzone)
        elif datestamp_type in ("iso", "webaccess", "unix"):
            entry["tzone"] = entry.get("tzone") or tzone
            if datestamp_type == "unix":
                entry = logdissect.utils.get_utc_date(entry)
        return entry

    def source_state(self, source_path):
        """Initial per-source parser state for forward streaming."""
        timestamp = datetime.fromtimestamp(os.path.getmtime(source_path))
        return {
            "year": timestamp.year,
            "nodate": {"timestamp": timestamp, "last_time": None},
        }

def export_record(entry, format_name, source_file):
    """Build the stable, same-source record for CSV and JSONL output."""
    record = {}
    value = timestamp_int(entry)
    for field in EXPORT_FIELDS:
        if field == "timestamp":
            record[field] = display_timestamp(value) if value else ""
        elif field == "format":
            record[field] = format_name
        elif field == "source_file":
            record[field] = entry.get("source_path", source_file).split(
                os.sep
            )[-1]
        elif field == "raw_text":
            record[field] = entry.get("raw_text", "")
        elif field == "message":
            record[field] = str(entry.get("message", ""))
        else:
            record[field] = str(entry.get(field, ""))
    return record


class ExportRunner:
    """Single-pass streaming export with online aggregation.

    Parsed records are written to ``temp_path`` as they are accepted.
    Counters, the format distribution and the time-span extremes are
    updated during the same pass; no parsed list is retained.
    """

    def __init__(self, catalog, spec, temp_path, progress=None):
        self.catalog = catalog
        self.spec = spec
        self.temp_path = temp_path
        self.progress = progress or (lambda stats: None)

        self.hits = 0
        self.dropped_unparsed = 0
        self.excluded_by_range = 0
        self.scanned = 0
        self.formats = {}
        self.earliest = None
        self.latest = None

        self._explicit = None
        if spec.get("parser"):
            self._explicit = catalog.get(spec["parser"])
        self._last_report = 0.0

    def _accept(self, entry, format_name, source_file):
        """Range-check a parsed entry and stream it to disk."""
        value = timestamp_int(entry)
        start = self.spec.get("start")
        end = self.spec.get("end")
        # Timestamp-less entries (kept unknown rows) bypass the
        # timestamp-based closed interval: it can only compare entries
        # that actually parsed a timestamp.
        if value is not None and (
            (start is not None and value < start)
            or (end is not None and value > end)
        ):
            self.excluded_by_range += 1
            return
        record = export_record(entry, format_name, source_file)
        self._writer.writerow(record)
        self.hits += 1
        self.formats[format_name] = self.formats.get(format_name, 0) + 1
        # The span is driven only by successfully parsed entries.
        if value is not None:
            if self.earliest is None or value < self.earliest:
                self.earliest = value
            if self.latest is None or value > self.latest:
                self.latest = value

    def _report(self, force=False):
        now = time.monotonic()
        if force or now - self._last_report >= 0.5:
            self._last_report = now
            self.progress(self.stats())

    def stats(self):
        return {
            "hits": self.hits,
            "scanned": self.scanned,
            "dropped_unparsed": self.dropped_unparsed,
            "excluded_by_range": self.excluded_by_range,
            "formats": dict(sorted(self.formats.items())),
            "earliest": self.earliest,
            "latest": self.latest,
        }

    def run(self):
        output_format = self.spec["format"]
        with open(self.temp_path, "w", newline="", encoding="utf-8") as out:
            if output_format == "csv":
                self._writer = _CsvRecordWriter(out)
            else:
                self._writer = _JsonlRecordWriter(out)
            self._writer.write_header()
            for source_file in self.spec["sources"]:
                source_state = self.catalog.source_state(source_file)
                with open(source_file, "r", encoding="utf-8") as logfile:
                    for raw in logfile:
                        line = raw.rstrip("\n").rstrip("\r")
                        self.scanned += 1
                        entry = None
                        format_name = "unknown"
                        if self._explicit is not None:
                            module = self._explicit
                            format_name = module.name
                            try:
                                entry = self.catalog.parse_line(
                                    module, line, source_state
                                )
                            except (ValueError, TypeError):
                                entry = None
                        else:
                            detected = self.catalog.detect(line)
                            if detected is not None:
                                format_name, module = detected
                                try:
                                    entry = self.catalog.parse_line(
                                        module, line, source_state
                                    )
                                except (ValueError, TypeError):
                                    entry = None
                        if entry is None:
                            self.dropped_unparsed += 1
                            if self.spec.get("keep_unknown"):
                                self._accept(
                                    {"raw_text": line},
                                    "unknown",
                                    source_file,
                                )
                        else:
                            entry.setdefault("raw_text", line)
                            entry.setdefault("source_path", source_file)
                            self._accept(entry, format_name, source_file)
                        if self.scanned % 100 == 0:
                            self._report()
            out.flush()
            os.fsync(out.fileno())
        self._report(force=True)
        return self.stats()


class _CsvRecordWriter:
    """Stream records as CSV using the shared column order."""

    def __init__(self, out):
        self._buffer = io.StringIO()
        self._csv = csv.DictWriter(
            self._buffer, fieldnames=EXPORT_FIELDS, extrasaction="ignore"
        )
        self._out = out

    def write_header(self):
        self._csv.writeheader()
        self._out.write(self._buffer.getvalue())
        self._buffer.seek(0)
        self._buffer.truncate(0)

    def writerow(self, record):
        self._csv.writerow(record)
        self._out.write(self._buffer.getvalue())
        self._buffer.seek(0)
        self._buffer.truncate(0)


class _JsonlRecordWriter:
    """Stream records as JSONL using the shared field order."""

    def __init__(self, out):
        self._out = out

    def write_header(self):
        return None

    def writerow(self, record):
        ordered = {field: record.get(field, "") for field in EXPORT_FIELDS}
        self._out.write(json.dumps(ordered, ensure_ascii=False) + "\n")

def _atomic_write_text(path, text):
    """Write ``text`` to ``path`` via a temp file plus atomic rename."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp_path = os.path.join(
        directory, ".%s.%s%s" % (os.path.basename(path), os.getpid(), TEMP_SUFFIX)
    )
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


class JobStore:
    """Persistent job state backed by sidecar JSON metadata."""

    def __init__(self, jobs_dir):
        self.jobs_dir = os.path.abspath(jobs_dir)
        os.makedirs(self.jobs_dir, exist_ok=True)
        self._jobs = {}
        self._locks = {}
        self._store_lock = threading.Lock()
        self._recover()

    def sidecar_path(self, job_id):
        return os.path.join(self.jobs_dir, job_id + SIDECAR_EXT)

    def path_lock(self, output_path):
        """Return the serialization lock for one output path."""
        key = os.path.abspath(output_path)
        with self._store_lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock

    def _recover(self):
        """Rebuild the state machine from sidecar metadata on startup.

        Jobs that were queued or running when the previous process died
        are marked failed with an ``interrupted`` error; their temp
        files are cleaned up.  Completed jobs stay queryable.
        """
        for name in sorted(os.listdir(self.jobs_dir)):
            if not name.endswith(SIDECAR_EXT):
                continue
            path = os.path.join(self.jobs_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    job = json.load(handle)
            except (ValueError, OSError):
                continue
            state = job.get("state")
            if state in (QUEUED, RUNNING):
                job["state"] = FAILED
                job["error"] = "interrupted by process restart"
                job["finished_at"] = time.time()
                self._persist(job)
            self._jobs[job["id"]] = job

    def create(self, job_id, spec):
        job = {
            "id": job_id,
            "state": QUEUED,
            "spec": spec,
            "created_at": time.time(),
            "updated_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "output_path": spec["output_path"],
            "stats": {},
            "error": None,
        }
        self._jobs[job_id] = job
        self._persist(job)
        return job

    def get(self, job_id):
        job = self._jobs.get(job_id)
        if job is None:
            raise NotFound("no such job %r" % job_id)
        return job

    def update(self, job_id, **changes):
        job = self.get(job_id)
        job.update(changes)
        job["updated_at"] = time.time()
        self._persist(job)
        return job

    def _persist(self, job):
        payload = json.dumps(job, indent=2, sort_keys=True)
        _atomic_write_text(self.sidecar_path(job["id"]), payload + "\n")

    def snapshot(self, job):
        """JSON-serializable view of one job."""
        view = dict(job)
        view.pop("spec", None)
        view["request"] = job.get("spec", {})
        return view

    def all_jobs(self):
        return [self.snapshot(job) for _, job in sorted(self._jobs.items())]

class ExportService:
    """Owns the thread pool, job store and parser catalog."""

    def __init__(self, jobs_dir, max_workers=4, catalog=None):
        self.store = JobStore(jobs_dir)
        self.catalog = catalog or ParserCatalog()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="logdissect-export",
        )

    def shutdown(self, wait=True):
        self._executor.shutdown(wait=wait)

    def submit(self, payload):
        """Validate and enqueue an export job; returns the job dict."""
        spec = self._validate(payload)
        job_id = uuid.uuid4().hex
        output_path = spec["output_path"]

        # Serialize jobs that touch the same output path and reject
        # duplicates while an earlier job is still in flight.
        lock = self.store.path_lock(output_path)
        if not lock.acquire(blocking=False):
            raise PathConflict(
                "an export job for %r is already in progress" % output_path
            )
        try:
            if os.path.exists(output_path) and not spec["overwrite"]:
                raise PathConflict(
                    "output path %r already exists; resubmit with"
                    " overwrite=true to replace it" % output_path
                )
            job = self.store.create(job_id, spec)
        except BaseException:
            lock.release()
            raise
        self._executor.submit(self._run, job_id, lock)
        return self.store.get(job_id)

    def _validate(self, payload):
        if not isinstance(payload, dict):
            raise BadRequest("request body must be a JSON object")
        sources = payload.get("sources")
        if not isinstance(sources, list) or not sources:
            raise BadRequest("'sources' must be a non-empty list of paths")
        resolved_sources = []
        for source in sources:
            if not isinstance(source, str) or not source:
                raise BadRequest("each source path must be a string")
            full = os.path.abspath(source)
            if not os.path.isfile(full):
                raise BadRequest("source not found: %s" % source)
            resolved_sources.append(full)

        output_path = payload.get("output_path")
        if not isinstance(output_path, str) or not output_path:
            raise BadRequest("'output_path' is required")
        output_path = os.path.abspath(output_path)

        output_format = payload.get("format", "csv")
        if output_format not in EXPORT_FORMATS:
            raise BadRequest(
                "'format' must be one of %s" % ", ".join(EXPORT_FORMATS)
            )

        parser = payload.get("parser")
        if parser is not None:
            if not isinstance(parser, str):
                raise BadRequest("'parser' must be a string")
            self.catalog.get(parser)

        spec = {
            "sources": resolved_sources,
            "output_path": output_path,
            "format": output_format,
            "parser": parser,
            "keep_unknown": bool(payload.get("keep_unknown", False)),
            "overwrite": bool(payload.get("overwrite", False)),
            "start": None,
            "end": None,
        }
        if payload.get("start") is not None:
            spec["start"] = normalize_start(payload["start"])
        if payload.get("end") is not None:
            spec["end"] = normalize_end(payload["end"])
        if (
            spec["start"] is not None
            and spec["end"] is not None
            and spec["start"] > spec["end"]
        ):
            raise BadRequest("'start' must not be later than 'end'")
        return spec

    def _run(self, job_id, path_lock):
        """Worker: stream the export, atomic-rename, update sidecar."""
        temp_path = None
        try:
            job = self.store.update(job_id, state=RUNNING, started_at=time.time())
            spec = job["spec"]
            output_path = spec["output_path"]
            directory = os.path.dirname(output_path) or "."
            os.makedirs(directory, exist_ok=True)
            temp_path = os.path.join(
                directory,
                ".%s.%s%s" % (
                    os.path.basename(output_path), job_id, TEMP_SUFFIX
                ),
            )
            runner = ExportRunner(
                self.catalog,
                spec,
                temp_path,
                progress=lambda stats: self.store.update(
                    job_id, stats=stats
                ),
            )
            stats = runner.run()

            # Re-check under the same path lock before the rename: a
            # sibling task or an outside writer may have created the
            # destination; overwrite must be declared explicitly.
            if os.path.exists(output_path) and not spec["overwrite"]:
                raise PathConflict(
                    "output path %r appeared during export; resubmit"
                    " with overwrite=true" % output_path
                )
            os.replace(temp_path, output_path)
            stats["earliest_text"] = (
                display_timestamp(stats["earliest"])
                if stats["earliest"] is not None
                else None
            )
            stats["latest_text"] = (
                display_timestamp(stats["latest"])
                if stats["latest"] is not None
                else None
            )
            self.store.update(
                job_id,
                state=COMPLETED,
                stats=stats,
                finished_at=time.time(),
                error=None,
            )
        except BaseException as exc:
            stats = {}
            try:
                stats = self.store.get(job_id).get("stats", {})
            except NotFound:
                pass
            try:
                self.store.update(
                    job_id,
                    state=FAILED,
                    error="%s: %s" % (type(exc).__name__, exc),
                    stats=stats,
                    finished_at=time.time(),
                )
            except NotFound:
                pass
        finally:
            # Remove the staging temp file on failure; after a
            # successful os.replace it no longer exists.
            if temp_path:
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except OSError:
                    pass
            path_lock.release()

_HTML_HEAD = (
    "<!doctype html><html><head><meta charset=\"utf-8\">"
    "<title>logdissect export report</title>"
    "<style>body{font-family:monospace;margin:2rem}"
    "table{border-collapse:collapse;margin:1rem 0}"
    "td,th{border:1px solid #999;padding:4px 10px;text-align:left}"
    ".state-completed{color:#060}.state-failed{color:#900}"
    ".state-running{color:#06c}</style></head><body>"
)


def _esc(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_report(job):
    """Render the summary HTML page for one job."""
    stats = job.get("stats", {})
    state = job.get("state")
    parts = [_HTML_HEAD]
    parts.append("<h1>Export report</h1>")
    parts.append(
        "<p>Job <code>%s</code> &mdash; "
        '<span class="state-%s">%s</span></p>'
        % (_esc(job["id"]), _esc(state), _esc(state))
    )
    if state == FAILED:
        parts.append("<p><strong>Error:</strong> %s</p>" % _esc(job.get("error")))
    spec = job.get("spec", {})
    parts.append("<h2>Request</h2><table>")
    parts.append(
        "<tr><th>sources</th><td>%s</td></tr>"
        % _esc(", ".join(spec.get("sources", [])))
    )
    parts.append(
        "<tr><th>output</th><td>%s</td></tr>"
        % _esc(spec.get("output_path", ""))
    )
    parts.append(
        "<tr><th>format</th><td>%s</td></tr>" % _esc(spec.get("format", ""))
    )
    if spec.get("parser"):
        parts.append(
            "<tr><th>parser</th><td>%s</td></tr>" % _esc(spec["parser"])
        )
    if spec.get("start") is not None:
        parts.append(
            "<tr><th>range</th><td>%s &ndash; %s (closed)</td></tr>"
            % (
                _esc(display_timestamp(spec["start"])),
                _esc(display_timestamp(spec["end"]))
                if spec.get("end") is not None
                else "end",
            )
        )
    parts.append(
        "<tr><th>keep_unknown</th><td>%s</td></tr>"
        % _esc(spec.get("keep_unknown"))
    )
    parts.append("</table>")

    parts.append("<h2>Summary</h2><table>")
    parts.append(
        "<tr><th>hits</th><td>%d</td></tr>" % stats.get("hits", 0)
    )
    parts.append(
        "<tr><th>scanned</th><td>%d</td></tr>" % stats.get("scanned", 0)
    )
    parts.append(
        "<tr><th>dropped unparsed</th><td>%d</td></tr>"
        % stats.get("dropped_unparsed", 0)
    )
    parts.append(
        "<tr><th>excluded by range</th><td>%d</td></tr>"
        % stats.get("excluded_by_range", 0)
    )
    earliest = stats.get("earliest_text")
    latest = stats.get("latest_text")
    if earliest and latest:
        parts.append(
            "<tr><th>time span</th><td>%s &ndash; %s</td></tr>"
            % (_esc(earliest), _esc(latest))
        )
    else:
        parts.append(
            "<tr><th>time span</th><td>no parsed timestamps</td></tr>"
        )
    parts.append("</table>")

    parts.append("<h2>Format distribution</h2>")
    formats = stats.get("formats", {})
    if formats:
        parts.append("<table><tr><th>format</th><th>count</th></tr>")
        for name in sorted(formats):
            parts.append(
                "<tr><td>%s</td><td>%d</td></tr>"
                % (_esc(name), formats[name])
            )
        parts.append("</table>")
    else:
        parts.append("<p>(none)</p>")
    parts.append("</body></html>")
    return "".join(parts)


class ServiceHandler(BaseHTTPRequestHandler):
    """Threaded HTTP routes for the export service."""

    server_version = "logdissect-service/1.0"

    def log_message(self, fmt, *args):
        return

    def _send_json(self, status, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status, body):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error_json(self, exc):
        self._send_json(
            getattr(exc, "status", 500),
            {"error": type(exc).__name__, "message": str(exc)},
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        service = self.server.service
        try:
            if len(parts) == 2 and parts[0] == "jobs":
                job = service.store.get(parts[1])
                self._send_json(200, service.store.snapshot(job))
            elif len(parts) == 3 and parts[0] == "jobs" and parts[2] == "report":
                job = service.store.get(parts[1])
                self._send_html(200, render_report(job))
            else:
                self._send_json(404, {"error": "NotFound", "message": parsed.path})
        except JobError as exc:
            self._send_error_json(exc)

    def do_POST(self):
        parsed = urlparse(self.path)
        if [p for p in parsed.path.split("/") if p] != ["export"]:
            self._send_json(404, {"error": "NotFound", "message": parsed.path})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                raise BadRequest("request body must be valid UTF-8 JSON")
            job = self.server.service.submit(payload)
            self._send_json(202, self.server.service.store.snapshot(job))
        except JobError as exc:
            self._send_error_json(exc)


def create_server(host="127.0.0.1", port=8123, jobs_dir=None, max_workers=4):
    """Build a threaded HTTP server with an attached export service."""
    if jobs_dir is None:
        jobs_dir = os.path.join(os.getcwd(), ".logdissect-jobs")
    service = ExportService(jobs_dir, max_workers=max_workers)
    httpd = ThreadingHTTPServer((host, port), ServiceHandler)
    httpd.service = service
    return httpd


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="logdissect export service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8123)
    parser.add_argument(
        "--jobs-dir",
        default=os.path.join(os.getcwd(), ".logdissect-jobs"),
        help="directory for sidecar job metadata",
    )
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)

    httpd = create_server(
        host=args.host,
        port=args.port,
        jobs_dir=args.jobs_dir,
        max_workers=args.workers,
    )
    print(
        "logdissect export service listening on http://%s:%d"
        % (args.host, args.port)
    )
    print("POST /export, GET /jobs/{id}, GET /jobs/{id}/report")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.service.shutdown()


if __name__ == "__main__":
    main()