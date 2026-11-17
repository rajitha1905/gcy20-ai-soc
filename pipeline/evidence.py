"""Tamper-evident evidence log.

Every record stores the hash of the previous record, so editing or deleting
any row breaks the chain from that point on. `verify()` recomputes the chain.

CLI (used by the host watchdog through `podman exec`):
    python -m pipeline.evidence verify
    python -m pipeline.evidence export-jsonl /data/exports/evidence.jsonl
    python -m pipeline.evidence ops-event --actor watchdog --type service_restarted --ref soc-collector --detail "..."
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys

from . import db

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _hash_record(rec: dict) -> str:
    return hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest()


def append_in_tx(conn: sqlite3.Connection, actor: str, event_type: str, ref: str | None,
                 payload: dict) -> dict:
    """Append one record. Caller must already hold a `db.tx()` transaction."""
    last = conn.execute("SELECT seq, record_hash FROM evidence ORDER BY seq DESC LIMIT 1").fetchone()
    seq = (last["seq"] + 1) if last else 1
    prev_hash = last["record_hash"] if last else GENESIS
    rec = {
        "seq": seq,
        "ts": db.utcnow(),
        "actor": actor,
        "event_type": event_type,
        "ref": ref,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    rec_hash = _hash_record(rec)
    conn.execute(
        "INSERT INTO evidence(seq, ts, actor, event_type, ref, payload, prev_hash, record_hash) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (seq, rec["ts"], actor, event_type, ref, canonical(payload), prev_hash, rec_hash),
    )
    rec["record_hash"] = rec_hash
    return rec


def append(conn: sqlite3.Connection, actor: str, event_type: str, ref: str | None, payload: dict) -> dict:
    with db.tx(conn):
        return append_in_tx(conn, actor, event_type, ref, payload)


def row_to_record(row) -> dict:
    return {
        "seq": row["seq"], "ts": row["ts"], "actor": row["actor"], "event_type": row["event_type"],
        "ref": row["ref"], "payload": json.loads(row["payload"]), "prev_hash": row["prev_hash"],
    }


def verify(conn: sqlite3.Connection) -> dict:
    """Recompute the whole chain. Returns {'ok', 'records', 'first_bad_seq', 'reason'}."""
    prev = GENESIS
    count = 0
    for row in conn.execute("SELECT * FROM evidence ORDER BY seq"):
        count += 1
        rec = row_to_record(row)
        if rec["prev_hash"] != prev:
            return {"ok": False, "records": count, "first_bad_seq": rec["seq"],
                    "reason": "prev_hash does not match previous record (row deleted or reordered)"}
        if _hash_record(rec) != row["record_hash"]:
            return {"ok": False, "records": count, "first_bad_seq": rec["seq"],
                    "reason": "record contents changed after it was written"}
        prev = row["record_hash"]
    return {"ok": True, "records": count, "first_bad_seq": None, "reason": None, "head_hash": prev}


def export_jsonl(conn: sqlite3.Connection, path, where: str = "", params: tuple = ()) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for row in conn.execute(f"SELECT * FROM evidence {where} ORDER BY seq", params):
            rec = row_to_record(row)
            rec["record_hash"] = row["record_hash"]
            f.write(canonical(rec) + "\n")
            n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.evidence")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify")
    ex = sub.add_parser("export-jsonl")
    ex.add_argument("path")
    ops = sub.add_parser("ops-event")
    ops.add_argument("--actor", required=True)
    ops.add_argument("--type", required=True)
    ops.add_argument("--ref", default=None)
    ops.add_argument("--detail", default="")
    args = ap.parse_args(argv)

    conn = db.connect()
    if args.cmd == "verify":
        result = verify(conn)
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 2
    if args.cmd == "export-jsonl":
        print(f"exported {export_jsonl(conn, args.path)} records to {args.path}")
        return 0
    if args.cmd == "ops-event":
        rec = append(conn, args.actor, args.type, args.ref, {"detail": args.detail})
        print(json.dumps({"seq": rec["seq"], "record_hash": rec["record_hash"]}))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
