"""SQLite storage shared by the collector, engine and dashboard containers.

All connections run in autocommit mode; multi-statement writes use `tx()`,
which takes an IMMEDIATE lock so concurrent writers (engine + analyst
dashboard + watchdog) cannot interleave hash-chain appends.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    event_id TEXT UNIQUE,
    ingest_ts TEXT,
    event_ts TEXT,
    src_ip TEXT, dest_ip TEXT, dest_port INTEGER,
    signature TEXT, category TEXT,
    raw_sha256 TEXT, raw TEXT,
    features TEXT,
    label TEXT, confidence REAL,
    anomaly_score REAL, is_outlier INTEGER,
    validation_flags TEXT,
    explanation TEXT,
    attack TEXT,
    llm_summary TEXT,
    decision TEXT, decision_reasons TEXT,
    status TEXT,
    incident_id TEXT,
    analyst_label TEXT, analyst TEXT, analyst_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_raw ON alerts(raw_sha256);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_ts TEXT, updated_ts TEXT,
    src_ip TEXT, dest_ip TEXT,
    label TEXT, severity TEXT,
    status TEXT,
    alert_count INTEGER,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY,
    incident_id TEXT,
    action TEXT,          -- block_ip | quarantine_host | unblock_ip | release_host
    target TEXT,
    status TEXT,          -- pending | approved | rejected | executed | refused | rolled_back
    requested_ts TEXT, requested_by TEXT,
    decided_ts TEXT, decided_by TEXT,
    reason TEXT,
    result TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    seq INTEGER PRIMARY KEY,
    ts TEXT,
    actor TEXT,
    event_type TEXT,
    ref TEXT,
    payload TEXT,
    prev_hash TEXT,
    record_hash TEXT
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def connect(path=None) -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(str(path or config.DB_PATH), timeout=30, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def tx(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
