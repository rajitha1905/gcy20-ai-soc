"""Response actions: incidents, containment requests, approvals, rollback.

All containment is SIMULATED: it writes to blocklist.txt / quarantine.txt in
the data volume. Nothing touches a real firewall or host.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from . import config, db, evidence

SEVERITY_FOR = {
    "suspicious": "medium",
    "credential_attack": "high",
    "lateral_movement": "high",
    "high_severity": "critical",
}


def _next_incident_id(conn) -> str:
    n = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] + 1
    return f"INC-{datetime.now(timezone.utc):%Y%m%d}-{n:04d}"


LABEL_RANK = {"suspicious": 1, "credential_attack": 2, "lateral_movement": 2, "high_severity": 3}


def upsert_incident(conn: sqlite3.Connection, label: str, src_ip: str, dest_ip: str, summary: str) -> tuple[str, bool]:
    """Attach to an open incident for the same source inside the merge window
    (reduces analyst fatigue: one brute-force burst = one incident), upgrading
    its label/severity if the new alert is worse. Otherwise open a new one.
    Returns (incident_id, created). Must run inside db.tx()."""
    window = config.policy().get("incident_merge_window_minutes", 30)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window)).isoformat()
    row = conn.execute(
        "SELECT id, label FROM incidents WHERE src_ip=? AND status='open' AND updated_ts>=? "
        "ORDER BY updated_ts DESC LIMIT 1", (src_ip, cutoff)).fetchone()
    now = db.utcnow()
    if row:
        conn.execute("UPDATE incidents SET alert_count=alert_count+1, updated_ts=? WHERE id=?", (now, row["id"]))
        if LABEL_RANK.get(label, 0) > LABEL_RANK.get(row["label"], 0):
            conn.execute("UPDATE incidents SET label=?, severity=?, summary=? WHERE id=?",
                         (label, SEVERITY_FOR.get(label, "medium"), summary, row["id"]))
            evidence.append_in_tx(conn, "engine", "incident_upgraded", row["id"],
                                  {"from_label": row["label"], "to_label": label})
        return row["id"], False
    inc_id = _next_incident_id(conn)
    conn.execute(
        "INSERT INTO incidents(id, created_ts, updated_ts, src_ip, dest_ip, label, severity, status, alert_count, summary) "
        "VALUES (?,?,?,?,?,?,?, 'open', 1, ?)",
        (inc_id, now, now, src_ip, dest_ip, label, SEVERITY_FOR.get(label, "medium"), summary))
    evidence.append_in_tx(conn, "engine", "incident_opened", inc_id,
                          {"label": label, "src_ip": src_ip, "dest_ip": dest_ip, "summary": summary})
    return inc_id, True


def choose_containment(label: str, src_ip: str, dest_ip: str) -> tuple[str, str]:
    """External attacker -> block their IP. Internal host acting badly -> quarantine it.
    Internal host talking to a bad external IP -> block the external IP (egress)."""
    if not config.is_internal(src_ip):
        return "block_ip", src_ip
    if label == "high_severity" and not config.is_internal(dest_ip):
        return "block_ip", dest_ip
    return "quarantine_host", src_ip


def request_containment(conn, incident_id: str, label: str, src_ip: str, dest_ip: str,
                        requested_by: str = "engine") -> int | None:
    """Create a pending action for the incident (once per incident+target). Inside db.tx()."""
    action, target = choose_containment(label, src_ip, dest_ip)
    exists = conn.execute(
        "SELECT id FROM actions WHERE incident_id=? AND action=? AND target=? "
        "AND status IN ('pending','approved','executed','refused')",
        (incident_id, action, target)).fetchone()
    if exists:
        return None
    cur = conn.execute(
        "INSERT INTO actions(incident_id, action, target, status, requested_ts, requested_by) "
        "VALUES (?,?,?,'pending',?,?)", (incident_id, action, target, db.utcnow(), requested_by))
    evidence.append_in_tx(conn, requested_by, "containment_requested", incident_id,
                          {"action_id": cur.lastrowid, "action": action, "target": target})
    return cur.lastrowid


def _read_lines(path) -> list[str]:
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def list_entries(path) -> list[str]:
    return [ln.split()[0] for ln in _read_lines(path) if not ln.startswith("#")]


def _apply(action: str, target: str, incident_id: str, actor: str) -> str:
    """Perform the simulated action on disk. Returns a result string."""
    protected = config.policy().get("protected_assets", {})
    if action in ("block_ip", "quarantine_host") and target in protected:
        return f"refused: {target} is a protected asset ({protected[target]}); escalate to IT operations"
    path = config.BLOCKLIST_FILE if action in ("block_ip", "unblock_ip") else config.QUARANTINE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    if action in ("block_ip", "quarantine_host"):
        if target in list_entries(path):
            return f"already present in {path.name}"
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{target}  # {incident_id} by {actor} at {db.utcnow()}\n")
        return f"added {target} to {path.name}"
    # rollback
    kept = [ln for ln in _read_lines(path) if ln.split()[0] != target]
    path.write_text("".join(ln + "\n" for ln in kept), encoding="utf-8")
    return f"removed {target} from {path.name}"


def decide_action(conn, action_id: int, approve: bool, analyst: str, reason: str) -> dict:
    """Analyst approves or rejects a pending containment action."""
    if not analyst.strip():
        raise ValueError("analyst name is required for approval decisions")
    with db.tx(conn):
        row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if row is None or row["status"] != "pending":
            raise ValueError(f"action {action_id} is not pending")
        now = db.utcnow()
        if not approve:
            conn.execute("UPDATE actions SET status='rejected', decided_ts=?, decided_by=?, reason=? WHERE id=?",
                         (now, analyst, reason, action_id))
            evidence.append_in_tx(conn, f"analyst:{analyst}", "containment_rejected", row["incident_id"],
                                  {"action_id": action_id, "action": row["action"], "target": row["target"],
                                   "reason": reason})
            return {"status": "rejected"}
        result = _apply(row["action"], row["target"], row["incident_id"], analyst)
        status = "refused" if result.startswith("refused") else "executed"
        conn.execute("UPDATE actions SET status=?, decided_ts=?, decided_by=?, reason=?, result=? WHERE id=?",
                     (status, now, analyst, reason, result, action_id))
        evidence.append_in_tx(conn, f"analyst:{analyst}", f"containment_{status}", row["incident_id"],
                              {"action_id": action_id, "action": row["action"], "target": row["target"],
                               "reason": reason, "result": result})
        return {"status": status, "result": result}


def auto_execute(conn, action_id: int) -> dict:
    """Used only when policy.auto_contain is true. Runs inside the caller's db.tx()."""
    row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
    result = _apply(row["action"], row["target"], row["incident_id"], "engine-auto")
    status = "refused" if result.startswith("refused") else "executed"
    conn.execute("UPDATE actions SET status=?, decided_ts=?, decided_by='engine-auto', result=? WHERE id=?",
                 (status, db.utcnow(), result, action_id))
    evidence.append_in_tx(conn, "engine", f"containment_auto_{status}", row["incident_id"],
                          {"action_id": action_id, "action": row["action"], "target": row["target"], "result": result})
    return {"status": status, "result": result}


def rollback(conn, action_id: int, analyst: str, reason: str) -> dict:
    if not analyst.strip():
        raise ValueError("analyst name is required for rollback")
    with db.tx(conn):
        row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if row is None or row["status"] != "executed":
            raise ValueError(f"action {action_id} has not been executed")
        undo = {"block_ip": "unblock_ip", "quarantine_host": "release_host"}[row["action"]]
        result = _apply(undo, row["target"], row["incident_id"], analyst)
        conn.execute("UPDATE actions SET status='rolled_back', result=? WHERE id=?",
                     (row["result"] + f" | rollback: {result}", action_id))
        evidence.append_in_tx(conn, f"analyst:{analyst}", "containment_rolled_back", row["incident_id"],
                              {"action_id": action_id, "target": row["target"], "reason": reason, "result": result})
        return {"status": "rolled_back", "result": result}


def resolve_review(conn, alert_id: int, analyst: str, verdict: str, note: str) -> dict:
    """Analyst resolves a needs_review alert. verdict: benign | suspicious | credential_attack | lateral_movement | high_severity."""
    if not analyst.strip():
        raise ValueError("analyst name is required")
    with db.tx(conn):
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if a is None:
            raise ValueError("unknown alert")
        incident_id = a["incident_id"]
        if verdict == "benign":
            status = "closed_analyst"
        else:
            status = "escalated" if verdict in SEVERITY_FOR and verdict != "suspicious" else "ticketed"
            incident_id, _ = upsert_incident(conn, verdict, a["src_ip"] or "unknown", a["dest_ip"] or "unknown",
                                             f"Analyst-escalated: {a['signature'] or 'unparsed event'}")
            if verdict != "suspicious" and a["src_ip"]:
                request_containment(conn, incident_id, verdict, a["src_ip"], a["dest_ip"] or "",
                                    requested_by=f"analyst:{analyst}")
        conn.execute("UPDATE alerts SET status=?, analyst_label=?, analyst=?, analyst_note=?, incident_id=? WHERE id=?",
                     (status, verdict, analyst, note, incident_id, alert_id))
        evidence.append_in_tx(conn, f"analyst:{analyst}", "analyst_override", a["event_id"],
                              {"model_label": a["label"], "model_confidence": a["confidence"],
                               "analyst_label": verdict, "note": note, "new_status": status,
                               "incident_id": incident_id})
        return {"status": status, "incident_id": incident_id}
