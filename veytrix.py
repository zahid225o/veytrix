#!/usr/bin/env python3
"""
veytrix.py — Veytrix 2.0
=========================
Endpoint Security Monitoring & Threat Detection.

Single-file implementation containing:
  - DetectionEvent contract + validation + sanitization
  - SQLite event store with migrations, indexed search, retention
  - Duplicate-alert grouping (preserves every underlying event)
  - Transparent 0–100 threat scoring with configurable weights
  - Behavioral correlation engine (rule-based, cross-event)
  - Professional PDF report generator (ReportLab)
  - Process monitoring (psutil) — optional
  - Network connection monitoring (psutil) — optional
  - File integrity monitoring (SHA-256 baselines)
  - Safe manual quarantine with restore
  - CLI (init-db, ingest, search, report, correlate, retention, monitor, demo)
  - Tkinter GUI dashboard — optional
  - Embedded unittest suite

Usage
-----
    python veytrix.py --version
    python veytrix.py --test
    python veytrix.py demo --outdir ./veytrix_demo
    python veytrix.py init-db --db events.db --base-dir ~/.veytrix
    python veytrix.py ingest  --db events.db --json events.json --base-dir ~/.veytrix
    python veytrix.py search  --db events.db --min-severity high --limit 20
    python veytrix.py report  --db events.db --out report.pdf --base-dir ~/.veytrix
    python veytrix.py correlate --db events.db --window 300
    python veytrix.py retention --db events.db --max-age-days 30 --vacuum
    python veytrix.py monitor-procs
    python veytrix.py monitor-net
    python veytrix.py ui

No GUI/process-monitoring/detection-rules coupling in the core; no AI APIs;
no cloud calls; fully local.
"""
from __future__ import annotations

__version__ = "2.0.0"
APP_NAME = "Veytrix"

# ─── Standard library ────────────────────────────────────────────────────────
import argparse
import datetime as dt
import hashlib
import json
import logging
import os
import queue
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence
from xml.sax.saxutils import escape as xml_escape

# ─── Optional dependencies (graceful degradation) ────────────────────────────
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)
    HAS_REPORTLAB = True
except Exception:
    HAS_REPORTLAB = False

try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    psutil = None
    HAS_PSUTIL = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    HAS_TK = True
except Exception:
    tk = None
    ttk = messagebox = filedialog = None
    HAS_TK = False

log = logging.getLogger("veytrix")


# ═════════════════════════════════════════════════════════════════════════════
#  Constants, exceptions, helpers
# ═════════════════════════════════════════════════════════════════════════════

SEVERITY_LEVELS: tuple[str, ...] = ("low", "medium", "high", "critical")
_SEVERITY_RANK: dict[str, int] = {s: i + 1 for i, s in enumerate(SEVERITY_LEVELS)}
MAX_TEXT_LEN = 8_000
MAX_RAW_LEN = 64_000
MAX_ID_LEN = 128
DEFAULT_PAGE_SIZE = 100
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6666, 9999}


class ValidationError(ValueError):
    """Malformed event data."""


class SecurityError(RuntimeError):
    """Unsafe path or operation."""


def sanitize_text(value: Any, max_len: int = MAX_TEXT_LEN) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            value = repr(value)
    value = _CONTROL_RE.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    if max_len and len(value) > max_len:
        value = value[:max_len] + "…[truncated]"
    return value


def _now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_timestamp(value: Any) -> str:
    if value is None:
        raise ValidationError("timestamp is required")
    if isinstance(value, dt.datetime):
        d = value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValidationError("timestamp is empty")
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        try:
            d = dt.datetime.fromisoformat(iso)
        except ValueError as exc:
            raise ValidationError(f"invalid timestamp {value!r}: {exc}") from exc
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    raise ValidationError(f"unsupported timestamp type: {type(value).__name__}")


def _coerce_pid(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValidationError("pid must not be bool")
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid pid {value!r}") from exc
    if v < 0:
        raise ValidationError(f"pid must be non-negative, got {v}")
    return v


def _coerce_severity(value: Any) -> str:
    if value is None:
        raise ValidationError("severity is required")
    s = str(value).strip().lower()
    if s not in SEVERITY_LEVELS:
        raise ValidationError(f"severity must be one of {SEVERITY_LEVELS}, got {value!r}")
    return s


def _coerce_json_dict(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        data = value
    elif isinstance(value, str):
        try:
            data = json.loads(value)
        except Exception as exc:
            raise ValidationError(f"raw must be valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("raw JSON must be an object")
    else:
        try:
            data = dict(value)
        except Exception as exc:
            raise ValidationError(f"raw must be a mapping: {exc}") from exc
    try:
        encoded = json.dumps(data, default=str, ensure_ascii=False)
    except Exception:
        encoded = json.dumps({"_repr": repr(data)}, ensure_ascii=False)
    if len(encoded) > MAX_RAW_LEN:
        return {"_truncated": True, "_preview": encoded[:MAX_RAW_LEN]}
    return data


def _get_any(obj: Any, keys: Sequence[str], default: Any = None) -> Any:
    for key in keys:
        if isinstance(obj, dict):
            if key in obj and obj[key] is not None:
                return obj[key]
        elif hasattr(obj, key):
            v = getattr(obj, key)
            if v is not None:
                return v
    return default


def safe_path(base_dir: str, filename: str, *,
              allowed_extensions: Optional[Sequence[str]] = None,
              create_base: bool = False) -> str:
    if not isinstance(filename, str) or not filename:
        raise SecurityError("filename must be a non-empty string")
    if "\x00" in filename:
        raise SecurityError("filename contains NUL byte")
    base = os.path.realpath(os.path.abspath(base_dir))
    if not os.path.isdir(base):
        if create_base:
            os.makedirs(base, mode=0o700, exist_ok=True)
            base = os.path.realpath(base)
        else:
            raise SecurityError(f"base directory does not exist: {base_dir}")
    if os.path.isabs(filename) or (os.name == "nt" and os.path.splitdrive(filename)[0]):
        raise SecurityError(f"absolute path not allowed: {filename!r}")
    norm = os.path.normpath(filename)
    if norm == ".." or norm.startswith(".." + os.sep):
        raise SecurityError(f"path traversal not allowed: {filename!r}")
    target = os.path.realpath(os.path.join(base, norm))
    if not (target == base or target.startswith(base + os.sep)):
        raise SecurityError(f"resolved path escapes base: {target!r}")
    if allowed_extensions:
        ext = os.path.splitext(target)[1].lower()
        allowed = {e.lower() for e in allowed_extensions}
        if ext not in allowed:
            raise SecurityError(
                f"extension {ext!r} not allowed, permitted: {sorted(allowed)}")
    if os.path.islink(target):
        raise SecurityError(f"refusing to write to symlink: {target!r}")
    return target


# ═════════════════════════════════════════════════════════════════════════════
#  DetectionEvent — the shared contract
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class DetectionEvent:
    event_id: str
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    description: str = ""
    explanation: str = ""
    investigation_notes: str = ""
    host: str = ""
    user: str = ""
    process_name: str = ""
    process_path: str = ""
    process_pid: Optional[int] = None
    process_ppid: Optional[int] = None
    process_cmdline: str = ""
    process_hash: str = ""
    source: str = ""
    event_type: str = "detection"
    confidence: float = 0.5
    evidence: list = field(default_factory=list)
    currently_running: bool = False
    fingerprint: str = ""
    is_echoed: bool = False
    raw: dict = field(default_factory=dict)
    schema_version: int = 3

    COLUMNS: tuple[str, ...] = (
        "event_id", "timestamp", "rule_id", "rule_name", "severity",
        "description", "explanation", "investigation_notes", "host", "user",
        "process_name", "process_path", "process_pid", "process_ppid",
        "process_cmdline", "process_hash", "source",
        "event_type", "confidence", "evidence_json", "currently_running",
        "fingerprint", "is_echoed",
        "raw_json", "schema_version",
    )

    @classmethod
    def from_mapping(cls, obj: Any) -> "DetectionEvent":
        if obj is None or not (isinstance(obj, dict) or hasattr(obj, "__dict__")):
            raise ValidationError(
                f"DetectionEvent requires mapping/object, got {type(obj).__name__}")
        rule_id = _get_any(obj, ("rule_id", "ruleId", "id"))
        rule_name = _get_any(obj, ("rule_name", "ruleName",
                                    "detection_name", "name", "title"))
        if rule_id is None or not str(rule_id).strip():
            raise ValidationError("rule_id is required")
        if rule_name is None or not str(rule_name).strip():
            raise ValidationError("rule_name is required")
        timestamp = _normalize_timestamp(
            _get_any(obj, ("timestamp", "time", "ts", "occurred_at")))
        severity = _coerce_severity(_get_any(obj, ("severity", "risk_level", "risk")))
        raw_id = _get_any(obj, ("event_id", "eventId", "id"))
        event_id = (sanitize_text(str(raw_id), max_len=MAX_ID_LEN)
                    if raw_id is not None else str(uuid.uuid4()))
        proc = _get_any(obj, ("process",), None)
        if proc is not None and not isinstance(proc, dict) and hasattr(proc, "__dict__"):
            proc = vars(proc)
        if not isinstance(proc, dict):
            proc = {}

        def pf(*names, default=None):
            for n in names:
                if n in proc and proc[n] is not None:
                    return proc[n]
            return default

        pname = _get_any(obj, ("process_name", "processName"),
                         pf("name", "process_name", "image"))
        ppath = _get_any(obj, ("process_path", "processPath"),
                         pf("path", "image_path", "process_path"))
        ppid = _get_any(obj, ("process_pid", "processPid", "pid"),
                        pf("pid", "process_pid"))
        pppid = _get_any(obj, ("process_ppid", "processPpid", "ppid"),
                         pf("ppid", "parent_pid"))
        pcmd = _get_any(obj, ("process_cmdline", "processCmdline", "cmdline"),
                        pf("cmdline", "command_line", "command"))
        phash = _get_any(obj, ("process_hash", "processHash", "hash"),
                         pf("hash", "sha256", "md5"))
        raw = _coerce_json_dict(_get_any(obj, ("raw", "raw_data", "extra", "metadata")))
        event_type = str(_get_any(obj, ("event_type", "type"), "detection")).lower()
        confidence = float(_get_any(obj, ("confidence",), 0.5) or 0.5)
        confidence = max(0.0, min(1.0, confidence))
        evidence = _get_any(obj, ("evidence",), []) or []
        if not isinstance(evidence, list):
            evidence = []
        currently_running = bool(_get_any(obj, ("currently_running", "running"), False))
        is_echoed = bool(_get_any(obj, ("is_echoed", "echoed"), False))
        host = _get_any(obj, ("host", "hostname", "computer"), "")
        norm_cmd = " ".join((pcmd or "").split()).lower()
        fp_material = "|".join([str(rule_id), str(host), str(pname or ""), norm_cmd])
        fingerprint = hashlib.sha256(fp_material.encode("utf-8")).hexdigest()[:32]
        return cls(
            event_id=event_id, timestamp=timestamp,
            rule_id=sanitize_text(str(rule_id), max_len=MAX_ID_LEN),
            rule_name=sanitize_text(str(rule_name)),
            severity=severity,
            description=sanitize_text(
                _get_any(obj, ("description", "summary", "message"), "")),
            explanation=sanitize_text(
                _get_any(obj, ("explanation", "rationale", "reason"), "")),
            investigation_notes=sanitize_text(
                _get_any(obj, ("investigation_notes", "notes",
                                "investigationNotes"), "")),
            host=sanitize_text(host),
            user=sanitize_text(_get_any(obj, ("user", "username", "user_name"), "")),
            process_name=sanitize_text(pname or ""),
            process_path=sanitize_text(ppath or ""),
            process_pid=_coerce_pid(ppid),
            process_ppid=_coerce_pid(pppid),
            process_cmdline=sanitize_text(pcmd or ""),
            process_hash=sanitize_text(phash or "", max_len=256),
            source=sanitize_text(_get_any(obj, ("source", "sensor"), "")),
            event_type=event_type, confidence=confidence, evidence=evidence,
            currently_running=currently_running, fingerprint=fingerprint,
            is_echoed=is_echoed, raw=raw,
            schema_version=int(_get_any(obj, ("schema_version",), 3) or 3),
        )

    def to_row(self) -> tuple:
        return (
            self.event_id, self.timestamp, self.rule_id, self.rule_name,
            self.severity, self.description, self.explanation,
            self.investigation_notes, self.host, self.user,
            self.process_name, self.process_path, self.process_pid,
            self.process_ppid, self.process_cmdline, self.process_hash,
            self.source, self.event_type, self.confidence,
            json.dumps(self.evidence, default=str, ensure_ascii=False),
            int(self.currently_running), self.fingerprint, int(self.is_echoed),
            json.dumps(self.raw, default=str, ensure_ascii=False),
            self.schema_version,
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DetectionEvent":
        def _load(s, default):
            try:
                return json.loads(s) if s else default
            except Exception:
                return default
        return cls(
            event_id=row["event_id"], timestamp=row["timestamp"],
            rule_id=row["rule_id"], rule_name=row["rule_name"],
            severity=row["severity"],
            description=row["description"] or "",
            explanation=row["explanation"] or "",
            investigation_notes=row["investigation_notes"] or "",
            host=row["host"] or "", user=row["user"] or "",
            process_name=row["process_name"] or "",
            process_path=row["process_path"] or "",
            process_pid=row["process_pid"], process_ppid=row["process_ppid"],
            process_cmdline=row["process_cmdline"] or "",
            process_hash=row["process_hash"] or "",
            source=row["source"] or "",
            event_type=row["event_type"] or "detection",
            confidence=float(row["confidence"] or 0.5),
            evidence=_load(row["evidence_json"], []),
            currently_running=bool(row["currently_running"]),
            fingerprint=row["fingerprint"] or "",
            is_echoed=bool(row["is_echoed"]),
            raw=_load(row["raw_json"], {}),
            schema_version=row["schema_version"] or 3,
        )


# ═════════════════════════════════════════════════════════════════════════════
#  SQLite event store
# ═════════════════════════════════════════════════════════════════════════════

MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, [
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
            description TEXT NOT NULL DEFAULT '',
            explanation TEXT NOT NULL DEFAULT '',
            investigation_notes TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            user TEXT NOT NULL DEFAULT '',
            process_name TEXT NOT NULL DEFAULT '',
            process_path TEXT NOT NULL DEFAULT '',
            process_pid INTEGER, process_ppid INTEGER,
            process_cmdline TEXT NOT NULL DEFAULT '',
            process_hash TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            schema_version INTEGER NOT NULL DEFAULT 1,
            inserted_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
        "CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)",
        "CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(process_name)",
    ]),
    (2, [
        "CREATE INDEX IF NOT EXISTS idx_events_sev_ts ON events(severity, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_events_rule_ts ON events(rule_id, timestamp)",
    ]),
    (3, [
        "ALTER TABLE events ADD COLUMN event_type TEXT NOT NULL DEFAULT 'detection'",
        "ALTER TABLE events ADD COLUMN confidence REAL NOT NULL DEFAULT 0.5",
        "ALTER TABLE events ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE events ADD COLUMN currently_running INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE events ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE events ADD COLUMN is_echoed INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_events_running ON events(currently_running)",
    ]),
]


class EventDatabase:
    def __init__(self, db_path: str, *, base_dir: Optional[str] = None,
                 create_base: bool = True, timeout: float = 10.0):
        if base_dir is not None:
            self.db_path = safe_path(
                base_dir, db_path,
                allowed_extensions={".db", ".sqlite", ".sqlite3"},
                create_base=create_base)
        else:
            self.db_path = os.path.realpath(os.path.abspath(db_path))
            ext = os.path.splitext(self.db_path)[1].lower()
            if ext not in (".db", ".sqlite", ".sqlite3"):
                raise SecurityError(
                    f"database must have .db/.sqlite/.sqlite3 extension, got {ext!r}")
        self._conn: Optional[sqlite3.Connection] = None
        self._timeout = timeout

    def connect(self) -> "EventDatabase":
        if self._conn is not None:
            return self
        parent = os.path.dirname(self.db_path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, mode=0o700, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=self._timeout,
                                isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        self._conn = conn
        self._migrate()
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self): return self.connect()
    def __exit__(self, *exc): self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        return self._conn

    def _migrate(self) -> None:
        conn = self._conn
        assert conn is not None
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version ("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        current = int(conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0])
        for version, statements in MIGRATIONS:
            if version <= current:
                continue
            conn.execute("BEGIN IMMEDIATE")
            try:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, _now_utc_iso()))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        conn = self.conn
        cur = conn.cursor()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            cur.close()

    def insert_many(self, events: Iterable[DetectionEvent], *,
                    replace: bool = False) -> int:
        now = _now_utc_iso()
        rows = [e.to_row() + (now,) for e in events]
        if not rows:
            return 0
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        cols = ",".join(DetectionEvent.COLUMNS) + ",inserted_at"
        ph = ",".join("?" for _ in range(len(DetectionEvent.COLUMNS) + 1))
        sql = f"{verb} INTO events ({cols}) VALUES ({ph})"
        with self.transaction() as cur:
            before = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            cur.executemany(sql, rows)
            after = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return int(after - before)

    def insert(self, event: DetectionEvent, *, replace: bool = False) -> bool:
        return self.insert_many([event], replace=replace) == 1

    def search(self, *, severity=None, min_severity=None, rule_id=None, host=None,
               process_name=None, source=None, event_type=None,
               currently_running=None, since=None, until=None, text=None,
               limit: int = DEFAULT_PAGE_SIZE, offset: int = 0,
               order: str = "desc") -> list[DetectionEvent]:
        if limit is None or limit < 0:
            raise ValueError("limit must be non-negative")
        limit = min(int(limit), 10_000)
        if offset < 0:
            raise ValueError("offset must be non-negative")
        clauses: list[str] = []
        params: list[Any] = []
        if severity is not None:
            sevs = [severity] if isinstance(severity, str) else list(severity)
            sevs = [_coerce_severity(s) for s in sevs]
            clauses.append("severity IN ({})".format(",".join("?" * len(sevs))))
            params.extend(sevs)
        if min_severity is not None:
            rank = _SEVERITY_RANK[_coerce_severity(min_severity)]
            allowed = [s for s, r in _SEVERITY_RANK.items() if r >= rank]
            clauses.append("severity IN ({})".format(",".join("?" * len(allowed))))
            params.extend(allowed)
        if rule_id is not None:
            clauses.append("rule_id = ?"); params.append(str(rule_id))
        if host is not None:
            clauses.append("host = ?"); params.append(str(host))
        if process_name is not None:
            clauses.append("process_name = ?"); params.append(str(process_name))
        if source is not None:
            clauses.append("source = ?"); params.append(str(source))
        if event_type is not None:
            clauses.append("event_type = ?"); params.append(str(event_type))
        if currently_running is not None:
            clauses.append("currently_running = ?")
            params.append(int(bool(currently_running)))
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(_normalize_timestamp(since))
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(_normalize_timestamp(until))
        if text:
            like = f"%{sanitize_text(text, max_len=500)}%"
            clauses.append("(description LIKE ? OR explanation LIKE ? "
                           "OR rule_name LIKE ? OR investigation_notes LIKE ?)")
            params.extend([like] * 4)
        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        sql += f" ORDER BY timestamp {direction}, id {direction} LIMIT ? OFFSET ?"
        params.extend([limit, int(offset)])
        rows = self.conn.execute(sql, params).fetchall()
        return [DetectionEvent.from_row(r) for r in rows]

    def count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def apply_retention(self, *, max_age_days: Optional[int] = None,
                        max_events: Optional[int] = None,
                        vacuum: bool = False) -> dict:
        if max_age_days is not None and max_age_days < 0:
            raise ValueError("max_age_days must be >= 0")
        if max_events is not None and max_events < 0:
            raise ValueError("max_events must be >= 0")
        deleted = 0
        with self.transaction() as cur:
            if max_age_days is not None:
                cutoff = (dt.datetime.now(dt.timezone.utc)
                          - dt.timedelta(days=max_age_days)).strftime(
                              "%Y-%m-%dT%H:%M:%S.%fZ")
                cur.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                if cur.rowcount > 0:
                    deleted += cur.rowcount
            if max_events is not None:
                cur.execute(
                    "DELETE FROM events WHERE id NOT IN ("
                    "SELECT id FROM events ORDER BY timestamp DESC, id DESC LIMIT ?)",
                    (int(max_events),))
                if cur.rowcount > 0:
                    deleted += cur.rowcount
        if vacuum:
            self.conn.execute("VACUUM")
        return {"deleted": deleted, "remaining": self.count()}


# ═════════════════════════════════════════════════════════════════════════════
#  Dedupe
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class EventGroup:
    fingerprint: str
    representative: DetectionEvent
    members: list[DetectionEvent] = field(default_factory=list)

    @property
    def occurrence_count(self) -> int: return len(self.members)
    @property
    def first_seen(self) -> str: return min(m.timestamp for m in self.members)
    @property
    def last_seen(self) -> str: return max(m.timestamp for m in self.members)
    @property
    def any_running(self) -> bool:
        return any(m.currently_running for m in self.members)


def group_events(events: Iterable[DetectionEvent]) -> list[EventGroup]:
    groups: dict[str, list[DetectionEvent]] = {}
    for ev in events:
        key = ev.fingerprint or ev.event_id
        groups.setdefault(key, []).append(ev)
    out: list[EventGroup] = []
    for fp, members in groups.items():
        rep = sorted(
            members,
            key=lambda e: (_SEVERITY_RANK.get(e.severity, 0),
                           e.confidence, e.timestamp),
            reverse=True,
        )[0]
        out.append(EventGroup(fp, rep,
                              sorted(members, key=lambda e: e.timestamp)))
    out.sort(key=lambda g: g.representative.timestamp, reverse=True)
    return out


def summarize(groups: Sequence[EventGroup]) -> dict:
    events = [m for g in groups for m in g.members]
    return {
        "unique_events": len(events),
        "unique_processes": len({(e.host, e.process_path or e.process_name)
                                  for e in events}),
        "unique_groups": len(groups),
        "currently_running": sum(1 for e in events if e.currently_running),
        "historical": sum(1 for e in events if not e.currently_running),
    }


# ═════════════════════════════════════════════════════════════════════════════
#  Scoring
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_WEIGHTS = {
    "base": {"low": 10, "medium": 30, "high": 60, "critical": 85},
    "encoded_cmd": 15, "hidden_window": 10, "lsass_access": 25,
    "office_spawn": 12, "browser_spawn": 8, "unsigned_binary": 5,
    "suspicious_port": 8, "echoed_penalty": -30, "echoed_cap": 15,
    "running_bonus": 5,
}
_ECHO_PATTERNS = [
    re.compile(r"\becho(\.exe)?\s+", re.I),
    re.compile(r"write-(host|output)\b", re.I),
    re.compile(r"^\s*(\"|').*(\"|')\s*$"),
]
_ENCODED = re.compile(r"(-enc(odedcommand)?\s+|-e\s+)[A-Za-z0-9+/=]{20,}", re.I)
_HIDDEN = re.compile(r"(-w(indowstyle)?\s+hidden|-nop\b)", re.I)
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
_BROWSER = {"chrome.exe", "msedge.exe", "firefox.exe"}


@dataclass
class ScoreResult:
    score: int
    severity: str
    confidence: float
    evidence: list[dict] = field(default_factory=list)
    is_echoed: bool = False


def load_weights(path: Optional[str | Path] = None) -> dict:
    if path and Path(path).exists():
        user = json.loads(Path(path).read_text())
        merged = {**DEFAULT_WEIGHTS, **user}
        merged["base"] = {**DEFAULT_WEIGHTS["base"], **user.get("base", {})}
        return merged
    return DEFAULT_WEIGHTS


def _detect_echo(ev: DetectionEvent) -> bool:
    if ev.is_echoed:
        return True
    cmd = ev.process_cmdline or ""
    return any(p.search(cmd) for p in _ECHO_PATTERNS)


def score_event(ev: DetectionEvent, weights: Optional[dict] = None) -> ScoreResult:
    w = weights or DEFAULT_WEIGHTS
    evidence: list[dict] = []
    score = float(w["base"].get(ev.severity, 30))
    evidence.append({"indicator": "base_severity", "weight": score,
                     "detail": ev.severity})
    cmd = ev.process_cmdline or ""
    ppath = (ev.process_path or "").lower()
    if _ENCODED.search(cmd):
        score += w["encoded_cmd"]
        evidence.append({"indicator": "encoded_command",
                         "weight": w["encoded_cmd"],
                         "detail": "Base64/encoded payload"})
    if _HIDDEN.search(cmd):
        score += w["hidden_window"]
        evidence.append({"indicator": "hidden_window",
                         "weight": w["hidden_window"],
                         "detail": "Hidden execution window"})
    if "lsass" in cmd.lower() or "lsass" in ppath:
        score += w["lsass_access"]
        evidence.append({"indicator": "lsass_access",
                         "weight": w["lsass_access"],
                         "detail": "LSASS referenced"})
    if any(o in ppath for o in _OFFICE):
        score += w["office_spawn"]
        evidence.append({"indicator": "office_spawn",
                         "weight": w["office_spawn"],
                         "detail": "Parent is Office process"})
    if any(b in ppath for b in _BROWSER):
        score += w["browser_spawn"]
        evidence.append({"indicator": "browser_spawn",
                         "weight": w["browser_spawn"],
                         "detail": "Parent is browser"})
    if not ev.process_hash:
        score += w["unsigned_binary"]
        evidence.append({"indicator": "missing_hash",
                         "weight": w["unsigned_binary"],
                         "detail": "No hash recorded"})
    ports = {int(m.group()) for m in re.finditer(r":(\d+)", cmd)
             if int(m.group()) in SUSPICIOUS_PORTS}
    if ports:
        score += w["suspicious_port"]
        evidence.append({"indicator": "suspicious_port",
                         "weight": w["suspicious_port"],
                         "detail": str(sorted(ports))})
    if ev.currently_running:
        score += w["running_bonus"]
        evidence.append({"indicator": "currently_running",
                         "weight": w["running_bonus"],
                         "detail": "Process still active"})
    echoed = _detect_echo(ev)
    if echoed:
        score += w["echoed_penalty"]
        score = min(score, w["echoed_cap"])
        evidence.append({"indicator": "echoed_text",
                         "weight": w["echoed_penalty"],
                         "detail": "Matched echo/quoted-text pattern"})
    score = max(0, min(100, int(round(score))))
    if score >= 80:
        sev = "critical"
    elif score >= 60:
        sev = "high"
    elif score >= 30:
        sev = "medium"
    else:
        sev = "low"
    spec = sum(1 for e in evidence if e["indicator"] != "base_severity")
    conf = min(1.0, 0.4 + 0.12 * spec)
    if echoed:
        conf = min(conf, 0.25)
    return ScoreResult(score, sev, round(conf, 2), evidence, echoed)


def rescore(events: Iterable[DetectionEvent],
            weights: Optional[dict] = None) -> None:
    for ev in events:
        r = score_event(ev, weights)
        ev.severity, ev.confidence, ev.evidence, ev.is_echoed = (
            r.severity, r.confidence, r.evidence, r.is_echoed)


# ═════════════════════════════════════════════════════════════════════════════
#  Behavior correlation
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class BehaviorAlert:
    rule_id: str
    name: str
    confidence: float
    score: int
    window_seconds: int
    evidence: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    host: str = ""
    process: str = ""

    def to_event(self) -> DetectionEvent:
        return DetectionEvent.from_mapping({
            "rule_id": f"BEH:{self.rule_id}",
            "rule_name": self.name,
            "severity": "high" if self.score >= 60 else "medium",
            "timestamp": _now_utc_iso(),
            "description": f"Behavioral correlation: {self.name}",
            "explanation": "; ".join(self.evidence),
            "host": self.host,
            "process_name": self.process,
            "source": "behavior-engine",
            "event_type": "behavior",
            "confidence": self.confidence,
            "evidence": [{"indicator": "behavior", "weight": self.score,
                          "detail": e} for e in self.evidence],
        })


def _parse_ts(ts: str) -> dt.datetime:
    s = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    d = dt.datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def _rule_encoded_ps_with_network(events, window):
    ps = [e for e in events if "powershell" in (e.process_name or "").lower()
          and any(x.get("indicator") == "encoded_command"
                  for x in (e.evidence or []))]
    net = [e for e in events if e.event_type == "network"]
    if ps and net:
        return BehaviorAlert("R-BEH-01",
                             "Encoded PowerShell followed by network egress",
                             confidence=0.85, score=80, window_seconds=window,
                             evidence=[f"{len(ps)} encoded PowerShell events",
                                       f"{len(net)} network events in window"],
                             event_ids=[e.event_id for e in ps + net],
                             host=ps[0].host, process=ps[0].process_name)
    return None


def _rule_office_spawns_shell(events, window):
    for e in events:
        if any(o in (e.process_path or "").lower() for o in
               ("winword.exe", "excel.exe", "powerpnt.exe")):
            if (e.process_name or "").lower() in (
                    "cmd.exe", "powershell.exe", "wscript.exe"):
                return BehaviorAlert("R-BEH-02", "Office application spawned shell",
                                     confidence=0.9, score=85,
                                     window_seconds=window,
                                     evidence=[f"{e.process_path} → {e.process_name}"],
                                     event_ids=[e.event_id], host=e.host,
                                     process=e.process_name)
    return None


def _rule_cred_then_lateral(events, window):
    cred = [e for e in events if "lsass" in (e.process_cmdline or "").lower()]
    net = [e for e in events if e.event_type == "network"
           and any(x.get("indicator") == "suspicious_port"
                   for x in (e.evidence or []))]
    if cred and net:
        return BehaviorAlert("R-BEH-03",
                             "Credential access followed by suspicious network",
                             confidence=0.88, score=90, window_seconds=window,
                             evidence=[f"{len(cred)} LSASS events",
                                       f"{len(net)} suspicious-port connections"],
                             event_ids=[e.event_id for e in cred + net],
                             host=cred[0].host,
                             process=cred[0].process_name)
    return None


DEFAULT_RULES: list[Callable] = [
    _rule_encoded_ps_with_network,
    _rule_office_spawns_shell,
    _rule_cred_then_lateral,
]


def correlate(events: Iterable[DetectionEvent], *, window_seconds: int = 300,
              rules: Sequence[Callable] = DEFAULT_RULES) -> list[BehaviorAlert]:
    events = list(events)
    by_host: dict[str, list[DetectionEvent]] = {}
    for e in events:
        by_host.setdefault(e.host or "_", []).append(e)
    alerts: list[BehaviorAlert] = []
    for host, evs in by_host.items():
        evs.sort(key=lambda e: e.timestamp)
        for i, _ in enumerate(evs):
            cutoff = _parse_ts(evs[i].timestamp) + dt.timedelta(seconds=window_seconds)
            window = [e for e in evs[i:] if _parse_ts(e.timestamp) <= cutoff]
            for rule in rules:
                a = rule(window, window_seconds)
                if a and not any(x.rule_id == a.rule_id and x.host == a.host
                                  for x in alerts):
                    alerts.append(a)
    return alerts


# ═════════════════════════════════════════════════════════════════════════════
#  PDF report generator
# ═════════════════════════════════════════════════════════════════════════════

_SEV_COLOR_HEX = {"low": "#5CB85C", "medium": "#F0AD4E",
                  "high": "#E67E22", "critical": "#E74C3C"}


class ReportGenerator:
    def __init__(self, *, base_dir: Optional[str] = None):
        if not HAS_REPORTLAB:
            raise RuntimeError(
                "reportlab is required for PDF reports. "
                "Install with:  pip install reportlab")
        self.base_dir = base_dir
        base = getSampleStyleSheet()
        self.s = {
            "title": ParagraphStyle("t", parent=base["Title"],
                                    fontName="Helvetica-Bold", fontSize=20,
                                    leading=24, alignment=TA_LEFT,
                                    textColor=colors.HexColor("#0B1F3A")),
            "h2": ParagraphStyle("h2", parent=base["Heading2"],
                                 fontName="Helvetica-Bold", fontSize=14,
                                 leading=18, spaceBefore=8, spaceAfter=6,
                                 textColor=colors.HexColor("#0B1F3A")),
            "h3": ParagraphStyle("h3", parent=base["Heading3"],
                                 fontName="Helvetica-Bold", fontSize=11,
                                 leading=14, spaceBefore=6, spaceAfter=3,
                                 textColor=colors.HexColor("#1F3A5F")),
            "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5,
                                   leading=13, splitLongWords=1, wordWrap="LTR"),
            "mono": ParagraphStyle("m", parent=base["Normal"],
                                   fontName="Courier", fontSize=8,
                                   leading=10, wordWrap="CJK"),
            "label": ParagraphStyle("l", parent=base["Normal"],
                                    fontName="Helvetica-Bold", fontSize=9,
                                    leading=12,
                                    textColor=colors.HexColor("#44546A")),
            "meta": ParagraphStyle("me", parent=base["Normal"],
                                   fontName="Helvetica", fontSize=9,
                                   leading=12, textColor=colors.grey),
        }

    @staticmethod
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(18 * mm, 10 * mm, f"{APP_NAME} 2.0 — Confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    @staticmethod
    def _tbl_style(header=True):
        cmds = [
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F5F7FA")]),
        ]
        if header:
            cmds += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1F3A")),
                     ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                     ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
        return TableStyle(cmds)

    def _pie_severity(self, counts: dict) -> Drawing:
        d = Drawing(180 * mm, 55 * mm)
        pie = Pie()
        pie.x, pie.y, pie.width, pie.height = 40, 10, 130, 130
        pie.data = [counts[s] or 0.0001 for s in SEVERITY_LEVELS]
        pie.labels = [f"{s} ({counts[s]})" for s in SEVERITY_LEVELS]
        pie.slices.strokeWidth = 0.5
        hex_map = {"low": colors.green, "medium": colors.gold,
                   "high": colors.orange, "critical": colors.firebrick}
        for i, s in enumerate(SEVERITY_LEVELS):
            pie.slices[i].fillColor = hex_map[s]
        d.add(pie)
        return d

    def _bar_rules(self, by_rule: dict) -> Drawing:
        top = sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        d = Drawing(180 * mm, 70 * mm)
        bar = VerticalBarChart()
        bar.x, bar.y, bar.width, bar.height = 40, 20, 130 * mm, 40 * mm
        bar.data = [[c for _, c in top]]
        bar.categoryAxis.categoryNames = [r[:16] for r, _ in top]
        bar.categoryAxis.labels.angle = 30
        bar.categoryAxis.labels.fontSize = 7
        bar.valueAxis.valueMin = 0
        bar.bars[0].fillColor = colors.HexColor("#1F3A5F")
        d.add(bar)
        return d

    def _block(self, label: str, text: str, mono=False) -> KeepTogether:
        style = self.s["mono"] if mono else self.s["body"]
        safe = xml_escape(sanitize_text(text or "", 20_000)).replace("\n", "<br/>")
        return KeepTogether([Paragraph(label, self.s["label"]),
                             Paragraph(safe or "—", style),
                             Spacer(1, 1.5 * mm)])

    def generate(self, events: Sequence[DetectionEvent], output_path: str, *,
                 title: str = "Veytrix Detection Report",
                 subtitle: Optional[str] = None,
                 include_raw: bool = False,
                 score_events: bool = True) -> str:
        if self.base_dir:
            target = safe_path(self.base_dir, output_path,
                               allowed_extensions={".pdf"}, create_base=True)
        else:
            target = os.path.realpath(os.path.abspath(output_path))
            if not target.lower().endswith(".pdf"):
                raise SecurityError("output path must end in .pdf")
        events = list(events)
        if score_events:
            for e in events:
                if not e.evidence:
                    r = score_event(e)
                    e.severity, e.confidence, e.evidence, e.is_echoed = (
                        r.severity, r.confidence, r.evidence, r.is_echoed)
        groups = group_events(events)
        stats = summarize(groups)
        doc = SimpleDocTemplate(target, pagesize=A4,
                                leftMargin=18 * mm, rightMargin=18 * mm,
                                topMargin=18 * mm, bottomMargin=18 * mm,
                                title=sanitize_text(title, 200),
                                author=APP_NAME)
        story: list = []
        story += self._cover(title, subtitle, stats, events)
        story += self._exec_summary(events, stats)
        story += self._index(groups)
        for i, g in enumerate(groups, 1):
            story += self._detail_group(i, g, include_raw)
        doc.build(story, onFirstPage=self._footer, onLaterPages=self._footer)
        return target

    def _cover(self, title, subtitle, stats, events) -> list:
        out = [Spacer(1, 6 * mm),
               Paragraph(xml_escape(sanitize_text(title, 200)), self.s["title"])]
        if subtitle:
            out.append(Paragraph(xml_escape(sanitize_text(subtitle, 200)),
                                  self.s["meta"]))
        out.append(Paragraph(f"Generated: {xml_escape(_now_utc_iso())}",
                              self.s["meta"]))
        if events:
            ts = sorted(e.timestamp for e in events)
            out.append(Paragraph(
                f"Time range: {xml_escape(ts[0])} → {xml_escape(ts[-1])}",
                self.s["meta"]))
        out.append(Paragraph(
            f"Unique events: {stats['unique_events']} · "
            f"Grouped alerts: {stats['unique_groups']} · "
            f"Processes: {stats['unique_processes']} · "
            f"Currently running: {stats['currently_running']} · "
            f"Historical: {stats['historical']}", self.s["meta"]))
        out.append(Spacer(1, 6 * mm))
        return out

    def _exec_summary(self, events, stats) -> list:
        out = [Paragraph("Executive Summary", self.s["h2"])]
        counts = {s: 0 for s in SEVERITY_LEVELS}
        by_rule: dict[str, int] = {}
        for e in events:
            counts[e.severity] = counts.get(e.severity, 0) + 1
            by_rule[e.rule_id] = by_rule.get(e.rule_id, 0) + 1
        rows = [["Metric", "Value"],
                ["Unique events", str(stats["unique_events"])],
                ["Grouped alerts", str(stats["unique_groups"])],
                ["Unique processes", str(stats["unique_processes"])],
                ["Currently running", str(stats["currently_running"])],
                ["Historical", str(stats["historical"])]]
        for s in reversed(SEVERITY_LEVELS):
            rows.append([f"{s.capitalize()} severity", str(counts[s])])
        t = Table(rows, colWidths=[70 * mm, 30 * mm])
        t.setStyle(self._tbl_style())
        out.append(t)
        out.append(Spacer(1, 4 * mm))
        if sum(counts.values()):
            out.append(Paragraph("Severity Distribution", self.s["h3"]))
            out.append(self._pie_severity(counts))
        if by_rule:
            out.append(Paragraph("Events by Rule", self.s["h3"]))
            out.append(self._bar_rules(by_rule))
        out.append(Spacer(1, 3 * mm))
        return out

    def _index(self, groups: Sequence[EventGroup]) -> list:
        out = [Paragraph("Alert Index (grouped)", self.s["h2"])]
        rows = [["#", "Last seen (UTC)", "Sev", "Count", "Live",
                 "Rule", "Host", "Process"]]
        for i, g in enumerate(groups, 1):
            e = g.representative
            rows.append([str(i), g.last_seen[:19].replace("T", " "),
                         e.severity.upper(), str(g.occurrence_count),
                         "●" if g.any_running else "–",
                         xml_escape(e.rule_id[:24]),
                         xml_escape((e.host or "-")[:18]),
                         xml_escape((e.process_name or "-")[:18])])
        t = Table(rows, colWidths=[8 * mm, 28 * mm, 12 * mm, 12 * mm, 10 * mm,
                                    30 * mm, 28 * mm, 30 * mm], repeatRows=1)
        t.setStyle(self._tbl_style())
        out.append(t)
        out.append(Spacer(1, 4 * mm))
        return out

    def _detail_group(self, idx: int, g: EventGroup,
                      include_raw: bool) -> list:
        e = g.representative
        out = [Paragraph(
            xml_escape(f"#{idx} · {e.rule_name}  [{e.severity.upper()}]  "
                       f"score={score_event(e).score}/100  "
                       f"conf={e.confidence:.2f}"), self.s["h2"])]
        out.append(Paragraph(
            f"Occurrences: {g.occurrence_count} · "
            f"First seen: {xml_escape(g.first_seen)} · "
            f"Last seen: {xml_escape(g.last_seen)} · "
            f"{'Currently running' if g.any_running else 'Historical only'}",
            self.s["meta"]))
        rows = [["Field", "Value"],
                ["Host", e.host or "—"], ["User", e.user or "—"],
                ["Source", e.source or "—"], ["Process", e.process_name or "—"],
                ["Path", e.process_path or "—"],
                ["PID", "" if e.process_pid is None else str(e.process_pid)],
                ["PPID", "" if e.process_ppid is None else str(e.process_ppid)],
                ["Command", e.process_cmdline or "—"],
                ["Hash", e.process_hash or "—"]]
        t = Table(rows, colWidths=[35 * mm, 125 * mm])
        t.setStyle(self._tbl_style())
        out.append(t)
        out.append(Spacer(1, 2 * mm))
        if e.evidence:
            erows = [["Indicator", "Weight", "Detail"]]
            for ev in e.evidence:
                erows.append([xml_escape(str(ev.get("indicator", ""))),
                              str(ev.get("weight", "")),
                              xml_escape(str(ev.get("detail", "")))])
            te = Table(erows, colWidths=[45 * mm, 20 * mm, 95 * mm])
            te.setStyle(self._tbl_style())
            out.append(Paragraph("Scoring Evidence", self.s["h3"]))
            out.append(te)
            out.append(Spacer(1, 2 * mm))
        out.append(self._block("Description", e.description))
        out.append(self._block("Explanation", e.explanation))
        out.append(self._block("Investigation Notes", e.investigation_notes))
        if include_raw and e.raw:
            out.append(self._block(
                "Raw Data",
                json.dumps(e.raw, indent=2, default=str), mono=True))
        if g.occurrence_count > 1:
            mrows = [["Timestamp", "PID", "Command"]] + [
                [m.timestamp[:19].replace("T", " "),
                 "" if m.process_pid is None else str(m.process_pid),
                 xml_escape((m.process_cmdline or "")[:80])]
                for m in g.members]
            tm = Table(mrows, colWidths=[40 * mm, 15 * mm, 105 * mm])
            tm.setStyle(self._tbl_style())
            out.append(Paragraph(
                f"Historical Occurrences ({g.occurrence_count})", self.s["h3"]))
            out.append(tm)
        out.append(Spacer(1, 5 * mm))
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  Process monitoring
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ProcessSnapshot:
    pid: int
    name: str
    ppid: Optional[int]
    cpu_percent: float
    memory_percent: float
    create_time: str
    cmdline: str
    exe: str
    username: str

    def as_dict(self) -> dict:
        return {
            "pid": self.pid, "name": self.name, "ppid": self.ppid,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "create_time": self.create_time, "cmdline": self.cmdline,
            "exe": self.exe, "username": self.username,
        }


def _iso_from_epoch(ts: float) -> str:
    try:
        return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:
        return ""


def snapshot_processes() -> list[ProcessSnapshot]:
    if not HAS_PSUTIL:
        log.warning("psutil not installed; process monitoring disabled")
        return []
    out: list[ProcessSnapshot] = []
    try:
        it = psutil.process_iter(
            ["pid", "name", "ppid", "cpu_percent", "memory_percent",
             "create_time", "cmdline", "exe", "username"])
    except Exception as exc:
        log.error("process_iter failed: %s", exc)
        return out
    for proc in it:
        try:
            info = proc.info
            out.append(ProcessSnapshot(
                pid=int(info["pid"]),
                name=info.get("name") or "",
                ppid=info.get("ppid"),
                cpu_percent=float(info.get("cpu_percent") or 0.0),
                memory_percent=float(info.get("memory_percent") or 0.0),
                create_time=_iso_from_epoch(info.get("create_time") or 0),
                cmdline=" ".join(info.get("cmdline") or []),
                exe=info.get("exe") or "",
                username=info.get("username") or "",
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            continue
        except Exception as exc:
            log.debug("skip pid: %s", exc)
            continue
    return out


def find_suspicious_processes(
        snapshots: list[ProcessSnapshot],
        patterns: Optional[list[str]] = None) -> list[ProcessSnapshot]:
    patterns = patterns or ["powershell", "cmd.exe", "wscript", "cscript",
                            "mshta", "rundll32", "regsvr32"]
    return [s for s in snapshots
            if any(p in (s.name or "").lower() for p in patterns)]


# ═════════════════════════════════════════════════════════════════════════════
#  Network monitoring
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ConnectionSnapshot:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    kind: str
    pid: Optional[int]
    process_name: str


def snapshot_connections() -> list[ConnectionSnapshot]:
    if not HAS_PSUTIL:
        log.warning("psutil not installed; network monitoring disabled")
        return []
    out: list[ConnectionSnapshot] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        log.warning("net_connections permission denied: %s", exc)
        return out
    except Exception as exc:
        log.error("net_connections failed: %s", exc)
        return out
    name_cache: dict[int, str] = {}
    for c in conns:
        try:
            if not c.raddr and c.status != "LISTEN":
                continue
            laddr = c.laddr
            raddr = c.raddr
            local_ip = getattr(laddr, "ip", "") if laddr else ""
            local_port = getattr(laddr, "port", 0) if laddr else 0
            remote_ip = getattr(raddr, "ip", "") if raddr else ""
            remote_port = getattr(raddr, "port", 0) if raddr else 0
            pname = ""
            if c.pid:
                if c.pid not in name_cache:
                    try:
                        name_cache[c.pid] = psutil.Process(c.pid).name()
                    except Exception:
                        name_cache[c.pid] = ""
                pname = name_cache[c.pid]
            out.append(ConnectionSnapshot(
                local_ip=local_ip, local_port=int(local_port),
                remote_ip=remote_ip, remote_port=int(remote_port),
                status=c.status or "",
                kind=c.type.name if c.type else "",
                pid=c.pid, process_name=pname,
            ))
        except Exception as exc:
            log.debug("skip conn: %s", exc)
            continue
    return out


def find_suspicious_connections(
        conns: list[ConnectionSnapshot]) -> list[ConnectionSnapshot]:
    return [c for c in conns
            if c.remote_port in SUSPICIOUS_PORTS
            or c.local_port in SUSPICIOUS_PORTS]


# ═════════════════════════════════════════════════════════════════════════════
#  File integrity monitoring
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class FileState:
    path: str
    sha256: str
    size: int
    mtime: str


@dataclass
class FileChange:
    path: str
    change: str
    old_sha256: str = ""
    new_sha256: str = ""
    when: str = ""


def hash_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def snapshot_files(paths: Iterable[str]) -> dict[str, FileState]:
    out: dict[str, FileState] = {}
    for p in paths:
        p = os.path.realpath(p)
        if not os.path.isfile(p):
            continue
        try:
            st = os.stat(p)
            out[p] = FileState(
                path=p, sha256=hash_file(p), size=st.st_size,
                mtime=dt.datetime.fromtimestamp(st.st_mtime, tz=dt.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        except (OSError, PermissionError) as exc:
            log.warning("skip %s: %s", p, exc)
    return out


def scan_directory(directory: str, *, max_files: int = 5000,
                   max_size_bytes: int = 50_000_000) -> dict[str, FileState]:
    out: dict[str, FileState] = {}
    if not os.path.isdir(directory):
        return out
    count = 0
    for root, _, files in os.walk(directory):
        for name in files:
            if count >= max_files:
                return out
            full = os.path.realpath(os.path.join(root, name))
            try:
                st = os.stat(full)
                if st.st_size > max_size_bytes:
                    continue
                out[full] = FileState(
                    path=full, sha256=hash_file(full), size=st.st_size,
                    mtime=dt.datetime.fromtimestamp(st.st_mtime,
                                                    tz=dt.timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
                count += 1
            except (OSError, PermissionError):
                continue
    return out


def diff_snapshots(before: dict[str, FileState],
                   after: dict[str, FileState]) -> list[FileChange]:
    changes: list[FileChange] = []
    now = _now_utc_iso()
    for path, b in before.items():
        if path not in after:
            changes.append(FileChange(path, "deleted", b.sha256, "", now))
        elif after[path].sha256 != b.sha256:
            changes.append(FileChange(path, "modified", b.sha256,
                                      after[path].sha256, now))
    for path, a in after.items():
        if path not in before:
            changes.append(FileChange(path, "created", "", a.sha256, now))
    return changes


class Baseline:
    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict[str, FileState]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {p: FileState(**v) for p, v in data.items()}

    def save(self, state: dict[str, FileState]) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({p: {"path": s.path, "sha256": s.sha256,
                           "size": s.size, "mtime": s.mtime}
                       for p, s in state.items()}, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  Quarantine
# ═════════════════════════════════════════════════════════════════════════════

SYSTEM_PATHS = {
    "windows": [r"c:\windows", r"c:\program files", r"c:\program files (x86)"],
    "linux": ["/bin", "/sbin", "/lib", "/lib64", "/usr/bin", "/usr/sbin",
              "/usr/lib", "/etc", "/boot", "/proc", "/sys", "/dev"],
}


def is_protected_path(path: str) -> bool:
    p = os.path.realpath(path).lower()
    if os.name == "nt":
        for pre in SYSTEM_PATHS["windows"]:
            if p.startswith(pre.lower()):
                return True
    else:
        for pre in SYSTEM_PATHS["linux"]:
            if p == pre or p.startswith(pre + os.sep):
                return True
    return False


class QuarantineManager:
    def __init__(self, quarantine_dir: str):
        self.root = os.path.realpath(quarantine_dir)
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        self.manifest_path = os.path.join(self.root, "manifest.json")

    def _load(self) -> list[dict]:
        if not os.path.exists(self.manifest_path):
            return []
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save(self, entries: list[dict]) -> None:
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2)

    def quarantine(self, file_path: str, *, reason: str = "",
                   confirm: bool = False) -> Optional[str]:
        if not confirm:
            raise PermissionError("quarantine requires confirm=True")
        src = os.path.realpath(file_path)
        if not os.path.isfile(src):
            raise FileNotFoundError(src)
        if is_protected_path(src):
            raise PermissionError(
                f"refusing to quarantine protected system file: {src}")
        qid = uuid.uuid4().hex[:12]
        dest_name = f"{qid}_{os.path.basename(src)}.quarantined"
        dest = os.path.join(self.root, dest_name)
        shutil.move(src, dest)
        entries = self._load()
        entries.append({
            "id": qid, "original_path": src, "quarantine_path": dest,
            "reason": reason, "when": _now_utc_iso(),
        })
        self._save(entries)
        return qid

    def restore(self, qid: str, *, confirm: bool = False,
                target: Optional[str] = None) -> str:
        if not confirm:
            raise PermissionError("restore requires confirm=True")
        entries = self._load()
        entry = next((e for e in entries if e["id"] == qid), None)
        if not entry:
            raise KeyError(f"no quarantine entry {qid}")
        src = entry["quarantine_path"]
        dest = target or entry["original_path"]
        if not os.path.exists(src):
            raise FileNotFoundError(src)
        if os.path.exists(dest):
            raise FileExistsError(dest)
        d = os.path.dirname(dest)
        if d:
            os.makedirs(d, exist_ok=True)
        shutil.move(src, dest)
        entries = [e for e in entries if e["id"] != qid]
        self._save(entries)
        return dest

    def list_entries(self) -> list[dict]:
        return self._load()


# ═════════════════════════════════════════════════════════════════════════════
#  Sample data
# ═════════════════════════════════════════════════════════════════════════════

def make_sample_events() -> list[DetectionEvent]:
    now = dt.datetime.now(dt.timezone.utc)

    def t(m): return (now - dt.timedelta(minutes=m)).isoformat()
    raw = [
        {"event_id": "evt-1001", "timestamp": t(120), "rule_id": "R-1001",
         "rule_name": "Encoded PowerShell", "severity": "high",
         "description": "PowerShell with Base64 payload.",
         "explanation": "Encoded commands hide intent.",
         "investigation_notes": "Decode payload; check egress.",
         "host": "WS-0142", "user": "CORP\\alice",
         "process": {"name": "powershell.exe",
                     "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                     "pid": 5120, "ppid": 1024,
                     "cmdline": "powershell -nop -w hidden -enc SQBFAFgA",
                     "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
         "source": "endpoint-edr", "raw": {"session_id": 42}},
        {"event_id": "evt-1001b", "timestamp": t(118), "rule_id": "R-1001",
         "rule_name": "Encoded PowerShell", "severity": "high",
         "description": "PowerShell with Base64 payload.",
         "explanation": "Encoded commands hide intent.",
         "host": "WS-0142", "user": "CORP\\alice",
         "process": {"name": "powershell.exe",
                     "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                     "pid": 5121, "ppid": 1024,
                     "cmdline": "powershell -nop -w hidden -enc SQBFAFgA",
                     "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
         "source": "endpoint-edr"},
        {"event_id": "evt-1002", "timestamp": t(60), "rule_id": "R-2002",
         "rule_name": "Credential Dumping", "severity": "critical",
         "description": "LSASS memory accessed.",
         "explanation": "Classic credential theft.",
         "investigation_notes": "Isolate host; capture memory.",
         "host": "WS-0177", "user": "CORP\\bob",
         "process": {"name": "mimikatz.exe",
                     "path": "C:\\Users\\Public\\mimikatz.exe",
                     "pid": 8844, "ppid": 4200,
                     "cmdline": "mimikatz.exe sekurlsa::logonpasswords",
                     "hash": "8f14e45fceea167a5a36dedd4bea2543"},
         "source": "endpoint-edr"},
        {"event_id": "evt-1003", "timestamp": t(30), "rule_id": "R-3003",
         "rule_name": "Unusual outbound", "severity": "medium",
         "description": "Outbound to untrusted ASN.",
         "explanation": "First-seen endpoint.",
         "host": "SRV-DC-01", "user": "NT AUTHORITY\\SYSTEM",
         "process": {"name": "svchost.exe", "pid": 908},
         "source": "network-monitor"},
        {"event_id": "evt-1004", "timestamp": t(15), "rule_id": "R-4004",
         "rule_name": "Run key persistence", "severity": "low",
         "description": "New Run key entry.",
         "explanation": "Common autorun location.",
         "investigation_notes": "Confirm with user.",
         "host": "WS-0101", "user": "CORP\\carol",
         "process": {"name": "reg.exe", "pid": 2244},
         "source": "endpoint-edr"},
        {"event_id": "evt-1005", "timestamp": t(10), "rule_id": "R-9999",
         "rule_name": "Echoed keyword (likely FP)", "severity": "high",
         "description": "User typed powershell -enc in an echo.",
         "explanation": "Command merely echoed a suspicious string.",
         "host": "WS-0101", "user": "CORP\\carol",
         "process": {"name": "cmd.exe", "pid": 2245,
                     "cmdline": 'echo "powershell -enc AAAA"'},
         "source": "endpoint-edr"},
    ]
    return [DetectionEvent.from_mapping(s) for s in raw]


# ═════════════════════════════════════════════════════════════════════════════
#  GUI (Tkinter)
# ═════════════════════════════════════════════════════════════════════════════

DARK_BG = "#0B1F3A"
PANEL_BG = "#16283F"
FG = "#E6EDF7"
ACCENT = "#00A3FF"
_SEV_COLOR = {"low": "#5CB85C", "medium": "#F0AD4E",
              "high": "#E67E22", "critical": "#E74C3C"}


class _MonitorWorker(threading.Thread):
    def __init__(self, q: "queue.Queue[dict]", interval: float = 3.0):
        super().__init__(daemon=True)
        self.q = q
        self.interval = interval
        self._stop = threading.Event()

    def stop(self): self._stop.set()

    def run(self):
        while not self._stop.is_set():
            try:
                procs = snapshot_processes()
                conns = snapshot_connections()
                self.q.put({"type": "snapshot", "procs": procs, "conns": conns})
            except Exception as exc:
                log.exception("monitor error: %s", exc)
            self._stop.wait(self.interval)


class VeytrixApp:
    def __new__(cls, *args, **kwargs):
        if not HAS_TK:
            raise RuntimeError(
                "tkinter not available. Install python3-tk on Linux "
                "or use the standard Python installer on Windows.")
        return super().__new__(cls)

    def __init__(self, db_path: str = "veytrix.db",
                 base_dir: Optional[str] = None):
        if not HAS_TK:
            raise RuntimeError("tkinter unavailable")
        self.root = tk.Tk()
        self.root.title("Veytrix 2.0 — Endpoint Security Monitoring")
        self.root.geometry("1280x800")
        self.root.configure(bg=DARK_BG)
        self.base_dir = base_dir or os.path.expanduser("~/.veytrix")
        os.makedirs(self.base_dir, mode=0o700, exist_ok=True)
        self.db = EventDatabase(db_path, base_dir=self.base_dir,
                                create_base=True)
        self.db.connect()
        self.q: "queue.Queue[dict]" = queue.Queue()
        self.worker: Optional[_MonitorWorker] = None
        self.current_view = "dashboard"
        self._last_snapshot = {"procs": [], "conns": []}
        self._build_styles()
        self._build_ui()
        self._start_monitor()
        self.root.after(500, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Treeview", background=PANEL_BG, foreground=FG,
                    fieldbackground=PANEL_BG, font=("Helvetica", 10),
                    rowheight=24)
        s.configure("Treeview.Heading", background=DARK_BG, foreground=ACCENT,
                    font=("Helvetica", 10, "bold"))
        s.configure("TNotebook", background=DARK_BG, borderwidth=0)

    def _build_ui(self):
        sidebar = tk.Frame(self.root, bg=DARK_BG, width=180)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="VEYTRIX", bg=DARK_BG, fg=ACCENT,
                 font=("Helvetica", 20, "bold")).pack(pady=(24, 4))
        tk.Label(sidebar, text="Endpoint Security", bg=DARK_BG, fg=FG,
                 font=("Helvetica", 9)).pack(pady=(0, 24))
        nav = [("Dashboard", "dashboard"), ("Alerts", "alerts"),
               ("Processes", "procs"), ("Network", "net"),
               ("Reports", "reports"), ("Settings", "settings")]
        for name, key in nav:
            tk.Button(sidebar, text=name, anchor="w", padx=20,
                      bg=PANEL_BG if key != "dashboard" else ACCENT,
                      fg=FG if key != "dashboard" else "#FFFFFF",
                      activebackground=ACCENT, activeforeground="#FFFFFF",
                      relief="flat", bd=0, font=("Helvetica", 11),
                      command=lambda k=key: self._switch(k)
                      ).pack(fill="x", padx=8, pady=2)
        self.status = tk.Label(sidebar, text="Ready", bg=DARK_BG, fg=FG,
                               font=("Helvetica", 8), anchor="w", padx=20)
        self.status.pack(side="bottom", fill="x", pady=8)
        self.content = tk.Frame(self.root, bg=DARK_BG)
        self.content.pack(side="left", fill="both", expand=True,
                          padx=12, pady=12)
        self.views: dict[str, tk.Frame] = {}
        for key in ["dashboard", "alerts", "procs", "net", "reports",
                    "settings"]:
            f = tk.Frame(self.content, bg=DARK_BG)
            self.views[key] = f
            self._build_view(key, f)
        self._show("dashboard")

    def _title(self, parent, text):
        tk.Label(parent, text=text, bg=DARK_BG, fg="#FFFFFF",
                 font=("Helvetica", 18, "bold"), anchor="w"
                 ).pack(fill="x", pady=(0, 12))

    def _build_view(self, key, f):
        if key == "dashboard":
            self._build_dashboard(f)
        elif key == "alerts":
            self._build_alerts(f)
        elif key == "procs":
            self._build_procs(f)
        elif key == "net":
            self._build_net(f)
        elif key == "reports":
            self._build_reports(f)
        elif key == "settings":
            self._build_settings(f)

    def _build_dashboard(self, f):
        self._title(f, "Dashboard")
        stats_frame = tk.Frame(f, bg=DARK_BG)
        stats_frame.pack(fill="x")
        self.stat_labels: dict[str, tk.Label] = {}
        for i, (key, label) in enumerate([
            ("events", "Total events"), ("alerts", "Grouped alerts"),
            ("procs", "Running processes"), ("conns", "Active connections"),
            ("high", "High/Critical"),
        ]):
            card = tk.Frame(stats_frame, bg=PANEL_BG, padx=16, pady=12)
            card.grid(row=0, column=i, padx=6, sticky="nsew")
            stats_frame.columnconfigure(i, weight=1)
            tk.Label(card, text=label, bg=PANEL_BG, fg=FG,
                     font=("Helvetica", 9), anchor="w").pack(anchor="w")
            self.stat_labels[key] = tk.Label(
                card, text="0", bg=PANEL_BG, fg=ACCENT,
                font=("Helvetica", 22, "bold"))
            self.stat_labels[key].pack(anchor="w")
        tk.Label(f, text="Recent alerts", bg=DARK_BG, fg="#FFFFFF",
                 font=("Helvetica", 12, "bold"), anchor="w"
                 ).pack(fill="x", pady=(20, 6))
        cols = ("time", "sev", "rule", "host", "process")
        self.recent_tree = ttk.Treeview(f, columns=cols, show="headings",
                                         height=12)
        for c, w in [("time", 180), ("sev", 90), ("rule", 260),
                      ("host", 140), ("process", 200)]:
            self.recent_tree.heading(c, text=c.title())
            self.recent_tree.column(c, width=w)
        for sev, col in _SEV_COLOR.items():
            self.recent_tree.tag_configure(sev, foreground=col)
        self.recent_tree.pack(fill="both", expand=True)
        self._refresh_dashboard()

    def _build_alerts(self, f):
        self._title(f, "Alerts")
        bar = tk.Frame(f, bg=DARK_BG)
        bar.pack(fill="x", pady=(0, 8))
        tk.Label(bar, text="Search:", bg=DARK_BG, fg=FG).pack(side="left")
        self.alert_query = tk.Entry(bar, bg=PANEL_BG, fg=FG,
                                     insertbackground=FG)
        self.alert_query.pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(bar, text="Refresh", bg=ACCENT, fg="#FFFFFF", relief="flat",
                  command=self._refresh_alerts).pack(side="left")
        cols = ("time", "sev", "conf", "rule", "host", "process",
                "count", "live")
        self.alert_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("time", 180), ("sev", 80), ("conf", 60),
                      ("rule", 260), ("host", 120), ("process", 180),
                      ("count", 60), ("live", 60)]:
            self.alert_tree.heading(c, text=c.title())
            self.alert_tree.column(c, width=w)
        for sev, col in _SEV_COLOR.items():
            self.alert_tree.tag_configure(sev, foreground=col)
        self.alert_tree.pack(fill="both", expand=True)
        self._refresh_alerts()

    def _build_procs(self, f):
        self._title(f, "Processes")
        if not HAS_PSUTIL:
            tk.Label(f, text="psutil not installed — process monitoring disabled.",
                     bg=DARK_BG, fg="#E74C3C",
                     font=("Helvetica", 11)).pack()
            return
        cols = ("pid", "name", "cpu", "mem", "cmdline")
        self.proc_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("pid", 60), ("name", 200), ("cpu", 80),
                      ("mem", 80), ("cmdline", 700)]:
            self.proc_tree.heading(c, text=c.title())
            self.proc_tree.column(c, width=w)
        self.proc_tree.tag_configure("suspicious", foreground="#E67E22")
        self.proc_tree.pack(fill="both", expand=True)

    def _build_net(self, f):
        self._title(f, "Network Connections")
        if not HAS_PSUTIL:
            tk.Label(f, text="psutil not installed — network monitoring disabled.",
                     bg=DARK_BG, fg="#E74C3C",
                     font=("Helvetica", 11)).pack()
            return
        cols = ("proc", "local", "remote", "status")
        self.net_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("proc", 200), ("local", 220),
                      ("remote", 220), ("status", 120)]:
            self.net_tree.heading(c, text=c.title())
            self.net_tree.column(c, width=w)
        self.net_tree.tag_configure("suspicious", foreground="#E74C3C")
        self.net_tree.pack(fill="both", expand=True)

    def _build_reports(self, f):
        self._title(f, "Reports")
        tk.Label(f, text="Generate a professional PDF report from stored events.",
                 bg=DARK_BG, fg=FG).pack(anchor="w", pady=(0, 12))
        row = tk.Frame(f, bg=DARK_BG)
        row.pack(fill="x", pady=4)
        tk.Label(row, text="Title:", bg=DARK_BG, fg=FG, width=8,
                 anchor="w").pack(side="left")
        self.report_title = tk.Entry(row, bg=PANEL_BG, fg=FG,
                                      insertbackground=FG)
        self.report_title.insert(0, "Veytrix Detection Report")
        self.report_title.pack(side="left", fill="x", expand=True, padx=6)
        row2 = tk.Frame(f, bg=DARK_BG)
        row2.pack(fill="x", pady=4)
        tk.Label(row2, text="Min sev:", bg=DARK_BG, fg=FG, width=8,
                 anchor="w").pack(side="left")
        self.min_sev = ttk.Combobox(row2, values=["(all)"] + list(SEVERITY_LEVELS),
                                     state="readonly")
        self.min_sev.set("(all)")
        self.min_sev.pack(side="left", padx=6)
        tk.Button(f, text="Generate PDF…", bg=ACCENT, fg="#FFFFFF",
                  relief="flat", font=("Helvetica", 11, "bold"),
                  command=self._generate_report
                  ).pack(anchor="w", pady=16)

    def _build_settings(self, f):
        self._title(f, "Settings")
        info = [
            ("Database", self.db.db_path),
            ("Base directory", self.base_dir),
            ("Behavior engine", "enabled, 300s window"),
            ("Scoring weights", "default"),
            ("psutil", "available" if HAS_PSUTIL else "not installed"),
            ("reportlab", "available" if HAS_REPORTLAB else "not installed"),
        ]
        for label, value in info:
            row = tk.Frame(f, bg=DARK_BG)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label + ":", bg=DARK_BG, fg=FG, width=18,
                     anchor="w", font=("Helvetica", 10, "bold")).pack(side="left")
            tk.Label(row, text=value, bg=DARK_BG, fg=FG,
                     font=("Courier", 10), anchor="w").pack(side="left")

    def _switch(self, key):
        self._show(key)
        if key == "dashboard":
            self._refresh_dashboard()
        elif key == "alerts":
            self._refresh_alerts()

    def _show(self, key):
        for f in self.views.values():
            f.pack_forget()
        self.views[key].pack(fill="both", expand=True)
        self.current_view = key

    def _start_monitor(self):
        self.worker = _MonitorWorker(self.q, interval=3.0)
        self.worker.start()

    def _drain_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg.get("type") == "snapshot":
                    self._apply_snapshot(msg)
        except queue.Empty:
            pass
        self.root.after(500, self._drain_queue)

    def _apply_snapshot(self, msg):
        self._last_snapshot = msg
        if self.current_view == "procs" and HAS_PSUTIL:
            self._fill_procs(msg["procs"])
        elif self.current_view == "net" and HAS_PSUTIL:
            self._fill_net(msg["conns"])
        if self.current_view == "dashboard":
            self._refresh_dashboard()

    def _fill_procs(self, procs):
        tree = self.proc_tree
        tree.delete(*tree.get_children())
        suspicious = {s.pid for s in find_suspicious_processes(procs)}
        for s in procs:
            tag = "suspicious" if s.pid in suspicious else ""
            tree.insert("", "end", values=(
                s.pid, s.name, f"{s.cpu_percent:.1f}",
                f"{s.memory_percent:.1f}", s.cmdline[:200]), tags=(tag,))

    def _fill_net(self, conns):
        tree = self.net_tree
        tree.delete(*tree.get_children())
        susp = {id(c) for c in find_suspicious_connections(conns)}
        for c in conns:
            tag = "suspicious" if id(c) in susp else ""
            tree.insert("", "end", values=(
                c.process_name[:30],
                f"{c.local_ip}:{c.local_port}",
                f"{c.remote_ip}:{c.remote_port}",
                c.status), tags=(tag,))

    def _refresh_dashboard(self):
        with self.db:
            count = self.db.count()
            events = self.db.search(limit=200)
        groups = group_events(events)
        stats = summarize(groups)
        high = sum(1 for e in events if e.severity in ("high", "critical"))
        self.stat_labels["events"].config(text=str(count))
        self.stat_labels["alerts"].config(text=str(stats["unique_groups"]))
        self.stat_labels["procs"].config(
            text=str(len(self._last_snapshot["procs"])))
        self.stat_labels["conns"].config(
            text=str(len(self._last_snapshot["conns"])))
        self.stat_labels["high"].config(text=str(high))
        tree = self.recent_tree
        tree.delete(*tree.get_children())
        for g in groups[:30]:
            e = g.representative
            tree.insert("", "end", values=(
                e.timestamp[:19].replace("T", " "),
                e.severity.upper(), e.rule_name[:40],
                e.host, e.process_name), tags=(e.severity,))

    def _refresh_alerts(self):
        q = self.alert_query.get().strip() if hasattr(self, "alert_query") else ""
        with self.db:
            events = self.db.search(text=q or None, limit=500)
        groups = group_events(events)
        tree = self.alert_tree
        tree.delete(*tree.get_children())
        for g in groups:
            e = g.representative
            tree.insert("", "end", values=(
                e.timestamp[:19].replace("T", " "),
                e.severity.upper(), f"{int(e.confidence*100)}%",
                e.rule_name[:40], e.host, e.process_name,
                g.occurrence_count, "●" if g.any_running else ""),
                tags=(e.severity,))

    def _generate_report(self):
        if not HAS_REPORTLAB:
            messagebox.showerror("Veytrix",
                                 "reportlab is not installed.\n"
                                 "pip install reportlab")
            return
        title = self.report_title.get() or "Veytrix Detection Report"
        min_sev = self.min_sev.get()
        min_sev = None if min_sev == "(all)" else min_sev
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        with self.db:
            events = self.db.search(min_severity=min_sev, limit=1000)
        if not events:
            messagebox.showinfo("Veytrix", "No events to report on.")
            return
        try:
            out = ReportGenerator().generate(events, path, title=title)
            messagebox.showinfo("Veytrix", f"Report written:\n{out}")
        except Exception as exc:
            log.exception("report generation failed")
            messagebox.showerror("Veytrix", f"Report failed: {exc}")

    def run(self):
        self.root.mainloop()

    def _on_close(self):
        if self.worker:
            self.worker.stop()
        try:
            self.db.close()
        except Exception:
            pass
        self.root.destroy()


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

def _cli(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(
        prog="veytrix",
        description="Veytrix 2.0 — endpoint security logging & reporting")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--base-dir", default=None,
                        help="sandbox directory for paths (recommended)")

    sp = sub.add_parser("init-db", help="initialize database")
    sp.add_argument("--db", required=True); common(sp)

    sp = sub.add_parser("ingest", help="ingest a JSON file")
    sp.add_argument("--db", required=True)
    sp.add_argument("--json", required=True); common(sp)

    sp = sub.add_parser("search", help="search events")
    sp.add_argument("--db", required=True)
    sp.add_argument("--severity"); sp.add_argument("--min-severity")
    sp.add_argument("--text"); sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--json", action="store_true"); common(sp)

    sp = sub.add_parser("report", help="generate PDF report")
    sp.add_argument("--db", required=True); sp.add_argument("--out", required=True)
    sp.add_argument("--min-severity"); sp.add_argument("--since")
    sp.add_argument("--until"); sp.add_argument("--limit", type=int, default=500)
    sp.add_argument("--title", default="Veytrix Detection Report")
    sp.add_argument("--include-raw", action="store_true")
    sp.add_argument("--weights"); common(sp)

    sp = sub.add_parser("retention", help="apply retention policy")
    sp.add_argument("--db", required=True)
    sp.add_argument("--max-age-days", type=int)
    sp.add_argument("--max-events", type=int)
    sp.add_argument("--vacuum", action="store_true"); common(sp)

    sp = sub.add_parser("correlate", help="run behavior engine")
    sp.add_argument("--db", required=True)
    sp.add_argument("--window", type=int, default=300)
    sp.add_argument("--limit", type=int, default=1000); common(sp)

    sp = sub.add_parser("monitor-procs", help="snapshot running processes")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("monitor-net", help="snapshot network connections")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("demo", help="seed sample DB + PDF")
    sp.add_argument("--outdir", default="./veytrix_demo")

    sp = sub.add_parser("ui", help="launch the Tkinter dashboard")

    args = p.parse_args(argv)

    # ── subcommand dispatch ─────────────────────────────────────────────────
    if args.cmd == "demo":
        outdir = os.path.realpath(os.path.abspath(args.outdir))
        os.makedirs(outdir, mode=0o700, exist_ok=True)
        db = EventDatabase("events.db", base_dir=outdir, create_base=True)
        with db:
            n = db.insert_many(make_sample_events())
            events = db.search(limit=500)
            alerts = correlate(events)
            for a in alerts:
                db.insert(a.to_event())
            events = db.search(limit=500)
            report = None
            if HAS_REPORTLAB:
                report = ReportGenerator(base_dir=outdir).generate(
                    events, "report.pdf",
                    subtitle="Demonstration report", include_raw=True)
        print(f"Inserted {n} events (+{len(alerts)} behavioral)")
        print(f"Database: {db.db_path}")
        if report:
            print(f"Report:   {report}")
        else:
            print("Report:   (skipped — reportlab not installed)")
        return

    if args.cmd == "ui":
        if not HAS_TK:
            print("tkinter is not available on this system.", file=sys.stderr)
            sys.exit(1)
        app = VeytrixApp()
        app.run()
        return

    if args.cmd == "monitor-procs":
        if not HAS_PSUTIL:
            print("psutil is required. pip install psutil", file=sys.stderr)
            sys.exit(1)
        snaps = snapshot_processes()
        if args.json:
            print(json.dumps([s.as_dict() for s in snaps], indent=2))
        else:
            for s in snaps[:100]:
                print(f"{s.pid:>6} {s.name:<25} "
                      f"cpu={s.cpu_percent:5.1f}% "
                      f"mem={s.memory_percent:5.1f}% "
                      f"{s.cmdline[:60]}")
        return

    if args.cmd == "monitor-net":
        if not HAS_PSUTIL:
            print("psutil is required. pip install psutil", file=sys.stderr)
            sys.exit(1)
        conns = snapshot_connections()
        if args.json:
            print(json.dumps([c.__dict__ for c in conns], indent=2))
        else:
            for c in conns[:100]:
                print(f"{c.process_name[:20]:<20} "
                      f"{c.local_ip}:{c.local_port} → "
                      f"{c.remote_ip}:{c.remote_port} [{c.status}]")
        return

    base_dir = getattr(args, "base_dir", None)

    if args.cmd == "init-db":
        with EventDatabase(args.db, base_dir=base_dir):
            print(f"Initialized: {args.db}")
        return

    if args.cmd == "ingest":
        with open(args.json, "r", encoding="utf-8") as f:
            payload = json.load(f)
        records = payload if isinstance(payload, list) else [payload]
        events: list[DetectionEvent] = []
        for i, rec in enumerate(records):
            try:
                events.append(DetectionEvent.from_mapping(rec))
            except ValidationError as exc:
                print(f"[skip] record {i}: {exc}", file=sys.stderr)
        with EventDatabase(args.db, base_dir=base_dir) as db:
            n = db.insert_many(events)
        print(f"Ingested {n}/{len(records)} events")
        return

    if args.cmd == "search":
        with EventDatabase(args.db, base_dir=base_dir) as db:
            evs = db.search(severity=args.severity,
                             min_severity=args.min_severity,
                             text=args.text, limit=args.limit)
        if args.json:
            print(json.dumps([{
                "event_id": e.event_id, "timestamp": e.timestamp,
                "severity": e.severity, "rule_id": e.rule_id,
                "rule_name": e.rule_name, "host": e.host,
                "process_name": e.process_name,
                "process_cmdline": e.process_cmdline,
                "confidence": e.confidence,
            } for e in evs], indent=2))
        else:
            for e in evs:
                print(f"{e.timestamp[:19]} [{e.severity:>8}] "
                      f"{e.rule_id} {e.rule_name} "
                      f"host={e.host} proc={e.process_name}")
        return

    if args.cmd == "report":
        if not HAS_REPORTLAB:
            print("reportlab required. pip install reportlab", file=sys.stderr)
            sys.exit(1)
        weights = load_weights(args.weights) if args.weights else None
        with EventDatabase(args.db, base_dir=base_dir) as db:
            evs = db.search(min_severity=args.min_severity,
                             since=args.since, until=args.until,
                             limit=args.limit)
        path = ReportGenerator(base_dir=base_dir).generate(
            evs, args.out, title=args.title,
            include_raw=args.include_raw,
            score_events=weights is None)
        print(f"Report written: {path}")
        return

    if args.cmd == "retention":
        with EventDatabase(args.db, base_dir=base_dir) as db:
            print(db.apply_retention(max_age_days=args.max_age_days,
                                      max_events=args.max_events,
                                      vacuum=args.vacuum))
        return

    if args.cmd == "correlate":
        with EventDatabase(args.db, base_dir=base_dir) as db:
            events = db.search(limit=args.limit)
            alerts = correlate(events, window_seconds=args.window)
            for a in alerts:
                db.insert(a.to_event())
        print(json.dumps([a.__dict__ for a in alerts],
                         indent=2, default=str))
        return


# ═════════════════════════════════════════════════════════════════════════════
#  Tests
# ═════════════════════════════════════════════════════════════════════════════

def _test_event(**kw) -> DetectionEvent:
    base = {"event_id": str(uuid.uuid4()), "timestamp": _now_utc_iso(),
            "rule_id": "r1", "rule_name": "R", "severity": "medium"}
    base.update(kw)
    return DetectionEvent.from_mapping(base)


class TestSanitize(unittest.TestCase):
    def test_strip_control(self):
        self.assertEqual(sanitize_text("a\x00b\x07c"), "abc")

    def test_truncate(self):
        s = sanitize_text("x" * 100, max_len=10)
        self.assertTrue(s.startswith("x" * 10))
        self.assertIn("truncated", s)


class TestValidation(unittest.TestCase):
    def test_missing_rule(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping(
                {"severity": "high", "timestamp": "2024-01-01T00:00:00Z"})

    def test_bad_severity(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping(
                {"rule_id": "r", "rule_name": "n", "severity": "bogus",
                 "timestamp": "2024-01-01T00:00:00Z"})

    def test_bad_timestamp(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping(
                {"rule_id": "r", "rule_name": "n", "severity": "low",
                 "timestamp": "not a date"})

    def test_aliases(self):
        e = DetectionEvent.from_mapping({
            "id": "r1", "name": "T", "risk_level": "high",
            "time": "2024-01-01T00:00:00Z", "pid": 42, "cmdline": "x"})
        self.assertEqual(e.rule_id, "r1")
        self.assertEqual(e.rule_name, "T")
        self.assertEqual(e.severity, "high")
        self.assertEqual(e.process_pid, 42)

    def test_negative_pid(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping({
                "rule_id": "r", "rule_name": "n", "severity": "low",
                "timestamp": "2024-01-01T00:00:00Z", "pid": -1})


class TestPathSafety(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp()
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ok(self):
        p = safe_path(self.tmp, "out.pdf", allowed_extensions={".pdf"})
        self.assertTrue(p.startswith(os.path.realpath(self.tmp)))

    def test_absolute(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "/etc/passwd")

    def test_traversal(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "../evil.pdf", allowed_extensions={".pdf"})

    def test_bad_ext(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "out.exe", allowed_extensions={".pdf"})

    def test_nul(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "a\x00b.pdf", allowed_extensions={".pdf"})


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = EventDatabase("events.db", base_dir=self.tmp,
                                create_base=True)
        self.db.connect()

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_insert_search(self):
        e1 = _test_event(severity="high", host="h1")
        e2 = _test_event(severity="low", host="h2")
        self.assertEqual(self.db.insert_many([e1, e2]), 2)
        high = self.db.search(severity="high")
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].event_id, e1.event_id)

    def test_duplicate_ignored(self):
        e = _test_event()
        self.db.insert_many([e])
        self.db.insert_many([e])
        self.assertEqual(self.db.count(), 1)

    def test_retention_max(self):
        for i in range(5):
            self.db.insert_many([_test_event(event_id=f"e{i}")])
        res = self.db.apply_retention(max_events=2)
        self.assertEqual(self.db.count(), 2)
        self.assertEqual(res["remaining"], 2)

    def test_retention_age(self):
        self.db.insert_many([_test_event(timestamp="2000-01-01T00:00:00Z"),
                             _test_event()])
        self.db.apply_retention(max_age_days=30)
        self.assertEqual(self.db.count(), 1)

    def test_min_severity(self):
        self.db.insert_many([_test_event(severity="low"),
                             _test_event(severity="critical")])
        got = self.db.search(min_severity="high")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].severity, "critical")

    def test_text(self):
        self.db.insert_many([_test_event(description="evil thing")])
        self.assertEqual(len(self.db.search(text="evil")), 1)
        self.assertEqual(len(self.db.search(text="good")), 0)

    def test_migrations_idempotent(self):
        self.db.close()
        self.db = EventDatabase("events.db", base_dir=self.tmp,
                                create_base=True)
        self.db.connect()
        rows = self.db.conn.execute(
            "SELECT version FROM schema_version ORDER BY version").fetchall()
        self.assertEqual([r[0] for r in rows], [1, 2, 3])


class TestDedupe(unittest.TestCase):
    def test_identical_grouped(self):
        evs = [_test_event(event_id=f"e{i}",
                           timestamp=f"2024-06-01T12:0{i}:00Z",
                           process={"name": "cmd.exe",
                                    "cmdline": "cmd /c dir"})
               for i in range(5)]
        g = group_events(evs)
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0].occurrence_count, 5)
        self.assertEqual(g[0].first_seen, "2024-06-01T12:00:00.000000Z")
        self.assertEqual(g[0].last_seen, "2024-06-01T12:04:00.000000Z")

    def test_different_not_grouped(self):
        evs = [_test_event(event_id="a",
                           process={"name": "cmd.exe", "cmdline": "cmd /c dir"}),
               _test_event(event_id="b",
                           process={"name": "cmd.exe", "cmdline": "cmd /c copy"})]
        self.assertEqual(len(group_events(evs)), 2)

    def test_historical_preserved(self):
        evs = [_test_event(event_id="e1", currently_running=False,
                           process={"name": "cmd.exe", "cmdline": "x"}),
               _test_event(event_id="e2", currently_running=True,
                           process={"name": "cmd.exe", "cmdline": "x"})]
        g = group_events(evs)[0]
        self.assertEqual(sorted(m.event_id for m in g.members), ["e1", "e2"])
        self.assertTrue(g.any_running)

    def test_summary(self):
        evs = [_test_event(event_id=f"e{i}",
                           process={"name": "cmd.exe", "cmdline": "x"})
               for i in range(3)]
        s = summarize(group_events(evs))
        self.assertEqual(s["unique_events"], 3)
        self.assertEqual(s["unique_groups"], 1)
        self.assertEqual(s["unique_processes"], 1)


class TestScoring(unittest.TestCase):
    def test_encoded_high(self):
        e = _test_event(
            severity="high",
            process={"name": "powershell.exe",
                     "cmdline": "powershell -nop -w hidden -enc " + "A" * 60})
        r = score_event(e)
        self.assertGreaterEqual(r.score, 80)
        inds = [x["indicator"] for x in r.evidence]
        self.assertIn("encoded_command", inds)
        self.assertIn("hidden_window", inds)

    def test_echo_penalised(self):
        e = _test_event(
            severity="high",
            process={"name": "cmd.exe",
                     "cmdline": 'echo "powershell -enc AAAA"'})
        r = score_event(e)
        self.assertTrue(r.is_echoed)
        self.assertLessEqual(r.score, 15)
        self.assertLessEqual(r.confidence, 0.25)

    def test_custom_weights(self):
        w = load_weights()
        w["encoded_cmd"] = 0
        e = _test_event(
            severity="medium",
            process={"name": "powershell.exe",
                     "cmdline": "powershell -enc " + "A" * 40})
        self.assertLess(score_event(e, w).score, score_event(e).score)

    def test_clamp(self):
        e = _test_event(
            severity="critical",
            process={"name": "powershell.exe",
                     "cmdline": "powershell -enc " + "A" * 100 +
                                " -w hidden lsass :4444"})
        self.assertLessEqual(score_event(e).score, 100)


class TestBehavior(unittest.TestCase):
    def test_encoded_ps_plus_net(self):
        evs = [
            _test_event(event_id="e1", host="h",
                        process={"name": "powershell.exe",
                                 "cmdline": "powershell -enc AAAA"}),
            _test_event(event_id="e2", host="h", event_type="network",
                        process={"name": "svchost"}),
        ]
        evs[0].evidence = [{"indicator": "encoded_command",
                            "weight": 15, "detail": "x"}]
        alerts = correlate(evs, window_seconds=300)
        self.assertTrue(any(a.rule_id == "R-BEH-01" for a in alerts))

    def test_office_spawn(self):
        evs = [_test_event(
            event_id="e1", host="h",
            process={"name": "cmd.exe",
                     "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                     "cmdline": "cmd /c whoami"})]
        a = _rule_office_spawns_shell(evs, 300)
        self.assertIsNotNone(a)
        self.assertEqual(a.rule_id, "R-BEH-02")

    def test_no_cross_host(self):
        evs = [
            _test_event(event_id="e1", host="h1",
                        process={"name": "powershell.exe",
                                 "cmdline": "powershell -enc AAAA"}),
            _test_event(event_id="e2", host="h2", event_type="network"),
        ]
        evs[0].evidence = [{"indicator": "encoded_command",
                            "weight": 15, "detail": "x"}]
        self.assertEqual(
            [a for a in correlate(evs) if a.rule_id == "R-BEH-01"], [])


class TestFIM(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp()
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, content):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_create(self):
        before = snapshot_files([])
        p = self._write("a.txt", "hello")
        after = snapshot_files([p])
        changes = diff_snapshots(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "created")

    def test_modify(self):
        p = self._write("a.txt", "hello")
        before = snapshot_files([p])
        self._write("a.txt", "hello world")
        after = snapshot_files([p])
        changes = diff_snapshots(before, after)
        self.assertEqual(changes[0].change, "modified")

    def test_delete(self):
        p = self._write("a.txt", "hello")
        before = snapshot_files([p])
        os.remove(p)
        after = snapshot_files([p])
        changes = diff_snapshots(before, after)
        self.assertEqual(changes[0].change, "deleted")

    def test_scan(self):
        self._write("a.txt", "x")
        self._write("b.txt", "y")
        self.assertEqual(len(scan_directory(self.tmp)), 2)

    def test_baseline_roundtrip(self):
        p = self._write("a.txt", "hello")
        state = snapshot_files([p])
        bl = os.path.join(self.tmp, "bl.json")
        Baseline(bl).save(state)
        loaded = Baseline(bl).load()
        self.assertEqual(list(loaded.keys()), list(state.keys()))
        self.assertEqual(loaded[p].sha256, state[p].sha256)


class TestQuarantine(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp()
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def test_needs_confirm(self):
        q = QuarantineManager(os.path.join(self.tmp, "q"))
        p = os.path.join(self.tmp, "f.txt")
        with open(p, "w") as f:
            f.write("x")
        with self.assertRaises(PermissionError):
            q.quarantine(p)

    def test_roundtrip(self):
        q = QuarantineManager(os.path.join(self.tmp, "q"))
        p = os.path.join(self.tmp, "f.txt")
        with open(p, "w") as f:
            f.write("x")
        qid = q.quarantine(p, confirm=True)
        self.assertFalse(os.path.exists(p))
        entries = q.list_entries()
        self.assertEqual(len(entries), 1)
        q.restore(qid, confirm=True)
        self.assertTrue(os.path.exists(p))


@unittest.skipUnless(HAS_REPORTLAB, "reportlab required")
class TestReport(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp()
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def test_basic(self):
        p = ReportGenerator(base_dir=self.tmp).generate(
            [_test_event()], "r.pdf")
        with open(p, "rb") as f:
            self.assertEqual(f.read(4), b"%PDF")

    def test_grouped(self):
        evs = [_test_event(event_id=f"e{i}",
                           process={"name": "cmd.exe", "cmdline": "x"})
               for i in range(5)]
        p = ReportGenerator(base_dir=self.tmp).generate(evs, "g.pdf")
        self.assertTrue(os.path.exists(p))

    def test_untrusted_text(self):
        e = _test_event(description="<script>alert(1)</script>",
                        rule_name="<b>evil</b>", event_id="x",
                        process={"name": "<x>",
                                 "cmdline": "a < b & c > d"})
        p = ReportGenerator(base_dir=self.tmp).generate([e], "u.pdf")
        self.assertTrue(os.path.exists(p))

    def test_bad_ext(self):
        with self.assertRaises(SecurityError):
            ReportGenerator(base_dir=self.tmp).generate([], "x.txt")

    def test_many_events(self):
        evs = [_test_event(event_id=f"e{i}", rule_id=f"R{i}",
                           process={"name": "cmd.exe",
                                    "cmdline": f"cmd /c {i}"})
               for i in range(40)]
        p = ReportGenerator(base_dir=self.tmp).generate(evs, "many.pdf")
        self.assertTrue(os.path.exists(p))


@unittest.skipUnless(HAS_PSUTIL, "psutil required")
class TestProcMon(unittest.TestCase):
    def test_snapshot_nonempty(self):
        procs = snapshot_processes()
        self.assertGreater(len(procs), 0)


class TestProcMonitorLogic(unittest.TestCase):
    def test_find_suspicious(self):
        snaps = [ProcessSnapshot(1, "powershell.exe", None, 0.0, 0.0,
                                  "", "powershell -enc x", "", ""),
                 ProcessSnapshot(2, "notepad.exe", None, 0.0, 0.0,
                                  "", "notepad", "", "")]
        hits = find_suspicious_processes(snaps)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].pid, 1)


def _run_tests() -> None:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.dirname(os.path.abspath(__file__))
                             or ".", pattern="veytrix*.py")
    # When run as a single file, discover finds no matching tests; use
    # explicit registration instead.
    suite = unittest.TestSuite()
    for cls in [TestSanitize, TestValidation, TestPathSafety, TestDatabase,
                TestDedupe, TestScoring, TestBehavior, TestFIM,
                TestQuarantine, TestReport, TestProcMon,
                TestProcMonitorLogic]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


# ═════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    argv = sys.argv[1:]
    if "--test" in argv:
        argv = [a for a in argv if a != "--test"]
        _run_tests()
        return
    _cli(argv)


if __name__ == "__main__":
    main()
