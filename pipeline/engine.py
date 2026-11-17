"""Detection engine: validate -> features -> classify -> decide -> respond -> evidence."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from . import attack_map, classifier, config, db, decision, evidence, health, llm_enrich, response
from .features import FeatureState
from .validator import validate

OFFSET_FILE = config.STATE_DIR / "engine.offset"
POLL_SECONDS = 1.0
TIME_FLAGS = ("timestamp_unparseable", "timestamp_in_future", "timestamp_stale_or_replayed")


def rebuild_state(conn) -> FeatureState:
    """Restore sliding-window counters after a restart so repeat counts survive."""
    state = FeatureState()
    cutoff = (datetime.now(timezone.utc) - state.window).isoformat()
    for row in conn.execute("SELECT src_ip, dest_ip, ingest_ts FROM alerts "
                            "WHERE src_ip IS NOT NULL AND ingest_ts >= ? ORDER BY id", (cutoff,)):
        state.observe(row["src_ip"], row["dest_ip"], datetime.fromisoformat(row["ingest_ts"]))
    return state


def process_record(conn, state: FeatureState, record: dict) -> dict:
    event_id = f"EVT-{int(record['collector_seq']):06d}"
    if conn.execute("SELECT 1 FROM alerts WHERE event_id=?", (event_id,)).fetchone():
        return {"event_id": event_id, "skipped": "already processed"}

    ingest_time = datetime.fromisoformat(record["ingest_ts"])
    raw = record["raw"]
    seen = conn.execute("SELECT 1 FROM alerts WHERE raw_sha256=? LIMIT 1", (record["raw_sha256"],)).fetchone()

    try:
        event_dict = json.loads(raw)
        if not isinstance(event_dict, dict):
            raise ValueError("top-level JSON is not an object")
        vr = validate(event_dict, ingest_time=ingest_time, seen_raw_hash=bool(seen))
    except ValueError as exc:  # json.JSONDecodeError is a ValueError
        event_dict = None
        vr = validate({}, ingest_time=ingest_time)
        vr.flags = ["malformed_json"] + (["duplicate_replay"] if seen else [])
        vr.errors = [str(exc)]

    pred = feats = attack = None
    if vr.parsed:
        ev = vr.event.model_dump()
        use_event_time = vr.event_time is not None and not any(f in vr.flags for f in TIME_FLAGS)
        ts = vr.event_time if use_event_time else ingest_time
        feats = state.compute(ev, ts)
        pred = classifier.predict(feats)
        attack = attack_map.map_technique(ev["alert"]["signature"], pred.label)

    dec = decision.decide(pred.label if pred else None, pred.confidence if pred else None,
                          vr.flags, pred.is_outlier if pred else False, vr.parsed)

    src = vr.event.src_ip if vr.parsed else (event_dict or {}).get("src_ip")
    dest = vr.event.dest_ip if vr.parsed else (event_dict or {}).get("dest_ip")
    sig = vr.event.alert.signature if vr.parsed else None
    model = classifier.load()

    with db.tx(conn):
        incident_id, action_id, auto_result = None, None, None
        if dec.decision in (decision.TICKET, decision.ESCALATE):
            incident_id, _ = response.upsert_incident(conn, pred.label, src, dest,
                                                      f"{pred.label}: {sig} ({src} -> {dest})")
            if dec.request_containment:
                action_id = response.request_containment(conn, incident_id, pred.label, src, dest)
                if action_id and dec.auto_execute_containment:
                    auto_result = response.auto_execute(conn, action_id)

        conn.execute(
            "INSERT INTO alerts(event_id, ingest_ts, event_ts, src_ip, dest_ip, dest_port, signature, category, "
            "raw_sha256, raw, features, label, confidence, anomaly_score, is_outlier, validation_flags, explanation, "
            "attack, decision, decision_reasons, status, incident_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, record["ingest_ts"], vr.event.timestamp if vr.parsed else None, src, dest,
             vr.event.dest_port if vr.parsed else None, sig, vr.event.alert.category if vr.parsed else None,
             record["raw_sha256"], raw, json.dumps(feats) if feats else None,
             pred.label if pred else None, pred.confidence if pred else None,
             pred.anomaly_score if pred else None, int(pred.is_outlier) if pred else None,
             json.dumps(vr.flags), json.dumps(pred.explanation) if pred else None,
             json.dumps(attack) if attack else None, dec.decision, json.dumps(dec.reasons),
             decision.STATUS_FOR[dec.decision], incident_id))

        evidence.append_in_tx(conn, "engine", "decision", event_id, {
            "collector_seq": record["collector_seq"],
            "ingest_ts": record["ingest_ts"],
            "raw_sha256": record["raw_sha256"],
            "parsed": vr.parsed,
            "schema_errors": vr.errors,
            "validation_flags": vr.flags,
            "model_version": model["version"],
            "policy_sha256": config.policy_sha256(),
            "features": feats,
            "label": pred.label if pred else None,
            "confidence": pred.confidence if pred else None,
            "probabilities": pred.probabilities if pred else None,
            "explanation": pred.explanation if pred else None,
            "anomaly_score": pred.anomaly_score if pred else None,
            "is_outlier": pred.is_outlier if pred else None,
            "attack": attack,
            "decision": dec.decision,
            "reasons": dec.reasons,
            "incident_id": incident_id,
            "containment_action_id": action_id,
            "auto_containment": auto_result,
        })

    if dec.decision == decision.ESCALATE and vr.parsed:
        enr = llm_enrich.enrich(vr.event.model_dump(), pred.label, pred.confidence, vr.flags)
        if enr is not None:
            with db.tx(conn):
                conn.execute("UPDATE alerts SET llm_summary=? WHERE event_id=?", (json.dumps(enr), event_id))
                evidence.append_in_tx(conn, "engine", "llm_enrichment", event_id, enr)

    return {"event_id": event_id, "label": pred.label if pred else None,
            "confidence": pred.confidence if pred else None, "decision": dec.decision,
            "flags": vr.flags, "incident_id": incident_id}


def run_once(conn, state, offset: int) -> tuple[int, int]:
    q = config.QUEUE_FILE
    if not q.exists() or q.stat().st_size <= offset:
        return offset, 0
    with open(q, "rb") as f:
        f.seek(offset)
        chunk = f.read()
    end = chunk.rfind(b"\n")
    if end < 0:
        return offset, 0
    n = 0
    pos = offset
    for line in chunk[: end + 1].splitlines(keepends=True):
        pos += len(line)
        if line.strip():
            result = process_record(conn, state, json.loads(line))
            n += 1
            if "skipped" not in result:
                print(f"[engine] {result['event_id']}: {result['decision']:<12} "
                      f"label={result['label']} conf={result['confidence']} flags={result['flags']}", flush=True)
        OFFSET_FILE.write_text(str(pos))
    return pos, n


def main() -> None:
    config.ensure_dirs()
    conn = db.connect()
    model = classifier.load()
    try:
        offset = int(OFFSET_FILE.read_text())
    except (FileNotFoundError, ValueError):
        offset = 0
    state = rebuild_state(conn)
    evidence.append(conn, "engine", "engine_started", "engine",
                    {"model_version": model["version"], "policy_sha256": config.policy_sha256(),
                     "resume_offset": offset, "llm_enabled": llm_enrich.ENABLED})
    print(f"[engine] started with {model['version']} (offset={offset})", flush=True)
    while True:
        offset, _ = run_once(conn, state, offset)
        health.beat("engine")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
