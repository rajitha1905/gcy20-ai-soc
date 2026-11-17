"""Forensic export package for one incident (or the whole system).

    python -m pipeline.export_case INC-20261116-0002 --analyst raji
    python -m pipeline.export_case ALL --analyst raji

Produces a ZIP with: incident record, related alerts (including the exact raw
lines and their SHA-256), related actions, matching evidence records, a full
evidence-chain verification result, model card / metrics / version, policy
file, blocklist + quarantine snapshots, and a manifest of SHA-256 hashes for
every file. The export itself is recorded in the evidence log.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from datetime import datetime, timezone

from . import classifier, config, db, evidence


def _rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params)]


def build(conn, incident_id: str, analyst: str) -> tuple[str, bytes]:
    if not analyst.strip():
        raise ValueError("analyst name is required for exports (chain of custody)")
    if incident_id == "ALL":
        incidents = _rows(conn, "SELECT * FROM incidents")
        alerts = _rows(conn, "SELECT * FROM alerts ORDER BY id")
        actions = _rows(conn, "SELECT * FROM actions ORDER BY id")
        ev_rows = conn.execute("SELECT * FROM evidence ORDER BY seq").fetchall()
    else:
        incidents = _rows(conn, "SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not incidents:
            raise ValueError(f"unknown incident {incident_id}")
        alerts = _rows(conn, "SELECT * FROM alerts WHERE incident_id=? ORDER BY id", (incident_id,))
        actions = _rows(conn, "SELECT * FROM actions WHERE incident_id=? ORDER BY id", (incident_id,))
        refs = [incident_id] + [a["event_id"] for a in alerts]
        marks = ",".join("?" * len(refs))
        ev_rows = conn.execute(f"SELECT * FROM evidence WHERE ref IN ({marks}) ORDER BY seq", refs).fetchall()

    raw_check = [{"event_id": a["event_id"], "raw_sha256": a["raw_sha256"],
                  "recomputed_ok": hashlib.sha256(a["raw"].encode("utf-8")).hexdigest() == a["raw_sha256"]}
                 for a in alerts]
    ev_records = []
    for r in ev_rows:
        rec = evidence.row_to_record(r)
        rec["record_hash"] = r["record_hash"]
        ev_records.append(rec)

    files: dict[str, bytes] = {
        "incident.json": json.dumps(incidents, indent=2).encode(),
        "alerts.json": json.dumps(alerts, indent=2).encode(),
        "raw_events.jsonl": "".join(a["raw"] + "\n" for a in alerts).encode(),
        "raw_hash_check.json": json.dumps(raw_check, indent=2).encode(),
        "actions.json": json.dumps(actions, indent=2).encode(),
        "evidence_records.jsonl": "".join(evidence.canonical(r) + "\n" for r in ev_records).encode(),
        "evidence_chain_verification.json": json.dumps(evidence.verify(conn), indent=2).encode(),
        "model/metadata.json": json.dumps(classifier.model_metadata(), indent=2).encode(),
        "config/policy.json": config.POLICY_PATH.read_bytes(),
    }
    for name in ("model_card.md", "tree_rules.txt"):
        p = config.MODEL_DIR / name
        if p.exists():
            files[f"model/{name}"] = p.read_bytes()
    for p in (config.BLOCKLIST_FILE, config.QUARANTINE_FILE):
        files[f"response/{p.name}"] = p.read_bytes() if p.exists() else b""

    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "incident_id": incident_id, "exported_at": exported_at, "exported_by": analyst,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    data = buf.getvalue()
    package_sha = hashlib.sha256(data).hexdigest()
    filename = f"forensic_{incident_id}_{exported_at.replace(':', '').replace('-', '')[:15]}.zip"

    config.EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    (config.EXPORT_DIR / filename).write_bytes(data)
    evidence.append(conn, f"analyst:{analyst}", "forensic_export", incident_id,
                    {"file": filename, "package_sha256": package_sha, "alerts": len(alerts),
                     "evidence_records": len(ev_records)})
    return filename, data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.export_case")
    ap.add_argument("incident_id", help="incident id or ALL")
    ap.add_argument("--analyst", required=True)
    args = ap.parse_args(argv)
    name, data = build(db.connect(), args.incident_id, args.analyst)
    print(f"wrote {config.EXPORT_DIR / name} ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
