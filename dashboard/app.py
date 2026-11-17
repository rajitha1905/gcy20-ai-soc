"""Analyst console for the AI-assisted SOC pipeline (Streamlit)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from pipeline import classifier, config, db, evidence, export_case, health, response  # noqa: E402

st.set_page_config(page_title="GCY20 AI-SOC Console", page_icon="🛡️", layout="wide")

VERDICTS = ["benign", "suspicious", "credential_attack", "lateral_movement", "high_severity"]


@st.cache_resource
def get_conn():
    return db.connect()


conn = get_conn()


def df(sql, params=()):
    return pd.DataFrame([dict(r) for r in conn.execute(sql, params)])


def flags_str(raw):
    try:
        return ", ".join(json.loads(raw or "[]"))
    except (TypeError, ValueError):
        return ""


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.title("🛡️ AI-SOC Console")
    analyst = st.text_input("Analyst name", key="analyst",
                            help="Required for approvals, overrides and exports. Recorded in the evidence log.")
    if not analyst.strip():
        st.warning("Enter your name to enable actions.")
    st.divider()
    try:
        meta = classifier.model_metadata()
        st.caption(f"**Model:** `{meta['version']}`")
        st.caption(f"Trained {meta['trained_at']} · accuracy {meta['metrics'].get('accuracy', 'n/a')}")
    except FileNotFoundError:
        st.error("Model artifacts missing. Run `python -m models.train`.")
    st.caption(f"**Policy:** `{config.policy_sha256()[:12]}` · auto-contain "
               f"{'ON' if config.policy().get('auto_contain') else 'OFF'}")
    st.divider()
    for svc in ("collector", "engine"):
        a = health.age(svc)
        limit = config.policy()["health"]["max_heartbeat_age_seconds"]
        if a is None:
            st.error(f"{svc}: no heartbeat")
        elif a <= limit:
            st.success(f"{svc}: healthy ({a:.0f}s)")
        else:
            st.error(f"{svc}: UNHEALTHY ({a:.0f}s since heartbeat)")
    if st.button("Refresh", width="stretch"):
        st.rerun()

tab_over, tab_review, tab_inc, tab_alerts, tab_ev, tab_sys = st.tabs(
    ["Overview", "Review queue", "Incidents & approvals", "Alerts", "Evidence log", "System"])


# ------------------------------------------------------------------ overview
with tab_over:
    @st.fragment(run_every=3)
    def overview():
        c = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
        total = c("SELECT COUNT(*) FROM alerts")
        auto = c("SELECT COUNT(*) FROM alerts WHERE decision='AUTO_CLOSE'")
        review = c("SELECT COUNT(*) FROM alerts WHERE status='needs_review'")
        open_inc = c("SELECT COUNT(*) FROM incidents WHERE status='open'")
        pending = c("SELECT COUNT(*) FROM actions WHERE status='pending'")
        cols = st.columns(6)
        cols[0].metric("Alerts processed", total)
        cols[1].metric("Auto-closed", auto)
        cols[2].metric("Workload reduction", f"{(auto / total * 100) if total else 0:.0f}%",
                       help="Share of alerts closed without analyst effort")
        cols[3].metric("Review queue", review)
        cols[4].metric("Open incidents", open_inc, help="Related alerts are merged into one incident per source")
        cols[5].metric("Pending approvals", pending)

        left, right = st.columns([1, 2])
        with left:
            st.subheader("Decisions")
            d = df("SELECT decision, COUNT(*) AS n FROM alerts GROUP BY decision")
            if not d.empty:
                st.bar_chart(d.set_index("decision"))
        with right:
            st.subheader("Latest alerts")
            recent = df("SELECT event_id, ingest_ts, src_ip, dest_ip, dest_port, signature, label, confidence, "
                        "decision, validation_flags FROM alerts ORDER BY id DESC LIMIT 15")
            if not recent.empty:
                recent["validation_flags"] = recent["validation_flags"].map(flags_str)
                st.dataframe(recent, hide_index=True, width="stretch")
            else:
                st.info("No alerts yet. Run the generator to send events.")
    overview()


# ------------------------------------------------------------------ review queue
with tab_review:
    st.subheader("Alerts needing a human decision")
    st.caption("Anything with validation flags, low confidence or an outlier score lands here. "
               "The system never auto-closes these.")
    rows = conn.execute("SELECT * FROM alerts WHERE status='needs_review' ORDER BY id LIMIT 50").fetchall()
    if not rows:
        st.success("Review queue is empty.")
    for a in rows:
        flags = flags_str(a["validation_flags"])
        title = f"{a['event_id']} · {a['signature'] or '(unparsed event)'}"
        with st.expander(f"{title}  —  ⚠️ {flags or 'low confidence'}"):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Raw event (as received)**")
                st.code(a["raw"][:3000], language="json")
                st.caption(f"SHA-256 `{a['raw_sha256']}`")
            with c2:
                st.markdown(f"**Model:** `{a['label']}` · confidence `{a['confidence']}` · "
                            f"anomaly `{a['anomaly_score']}`")
                st.markdown("**Why it is here**")
                for r in json.loads(a["decision_reasons"] or "[]"):
                    st.markdown(f"- {r}")
                if a["explanation"]:
                    st.markdown("**Decision path**")
                    st.code("\n".join(json.loads(a["explanation"])))
            with st.form(f"review-{a['id']}"):
                verdict = st.selectbox("Analyst verdict", VERDICTS, key=f"v-{a['id']}")
                note = st.text_input("Note / justification", key=f"n-{a['id']}")
                if st.form_submit_button("Submit decision", disabled=not analyst.strip()):
                    if not note.strip():
                        st.error("A justification note is required.")
                    else:
                        res = response.resolve_review(conn, a["id"], analyst, verdict, note)
                        st.success(f"Recorded: {res['status']}"
                                   + (f" · incident {res['incident_id']}" if res["incident_id"] else ""))
                        st.rerun()


# ------------------------------------------------------------------ incidents
with tab_inc:
    inc = df("SELECT id, severity, label, status, alert_count, src_ip, dest_ip, created_ts, updated_ts, summary "
             "FROM incidents ORDER BY created_ts DESC")
    if inc.empty:
        st.info("No incidents yet.")
    else:
        st.dataframe(inc, hide_index=True, width="stretch")
        sel = st.selectbox("Open incident", inc["id"].tolist())
        if sel:
            i = conn.execute("SELECT * FROM incidents WHERE id=?", (sel,)).fetchone()
            st.markdown(f"### {sel} · {i['severity'].upper()} · {i['label']}")
            st.caption(i["summary"])

            st.markdown("#### Containment actions")
            acts = conn.execute("SELECT * FROM actions WHERE incident_id=? ORDER BY id", (sel,)).fetchall()
            if not acts:
                st.caption("No containment requested for this incident.")
            for act in acts:
                box = st.container(border=True)
                box.markdown(f"**#{act['id']} `{act['action']}` → `{act['target']}`** · status **{act['status']}**")
                if act["result"]:
                    box.caption(act["result"])
                if act["decided_by"]:
                    box.caption(f"Decided by {act['decided_by']} at {act['decided_ts']}: {act['reason'] or ''}")
                if act["status"] == "pending":
                    reason = box.text_input("Reason", key=f"r-{act['id']}")
                    b1, b2 = box.columns(2)
                    if b1.button("✅ Approve", key=f"ap-{act['id']}", disabled=not analyst.strip()):
                        res = response.decide_action(conn, act["id"], True, analyst, reason or "approved")
                        (st.warning if res["status"] == "refused" else st.success)(res.get("result", res["status"]))
                        st.rerun()
                    if b2.button("❌ Reject", key=f"rj-{act['id']}", disabled=not analyst.strip()):
                        response.decide_action(conn, act["id"], False, analyst, reason or "rejected")
                        st.rerun()
                elif act["status"] == "executed":
                    if box.button("↩️ Roll back", key=f"rb-{act['id']}", disabled=not analyst.strip()):
                        response.rollback(conn, act["id"], analyst, "analyst rollback")
                        st.rerun()

            st.markdown("#### Alerts in this incident")
            ia = df("SELECT event_id, ingest_ts, src_ip, dest_ip, dest_port, signature, label, confidence, decision "
                    "FROM alerts WHERE incident_id=? ORDER BY id", (sel,))
            st.dataframe(ia, hide_index=True, width="stretch")

            c1, c2 = st.columns(2)
            if c1.button("🔒 Close incident", disabled=not analyst.strip()):
                with db.tx(conn):
                    conn.execute("UPDATE incidents SET status='closed', updated_ts=? WHERE id=?", (db.utcnow(), sel))
                    evidence.append_in_tx(conn, f"analyst:{analyst}", "incident_closed", sel, {})
                st.rerun()
            if c2.button("📦 Build forensic export", disabled=not analyst.strip()):
                name, data = export_case.build(conn, sel, analyst)
                st.session_state["export"] = (name, data)
            if st.session_state.get("export"):
                name, data = st.session_state["export"]
                st.download_button(f"Download {name}", data, file_name=name, mime="application/zip")


# ------------------------------------------------------------------ alerts
with tab_alerts:
    decisions = st.multiselect("Decision", ["AUTO_CLOSE", "TICKET", "ESCALATE", "NEEDS_REVIEW"],
                               default=["AUTO_CLOSE", "TICKET", "ESCALATE", "NEEDS_REVIEW"])
    if decisions:
        marks = ",".join("?" * len(decisions))
        al = df(f"SELECT event_id, ingest_ts, src_ip, dest_ip, dest_port, signature, label, confidence, decision, "
                f"status, analyst_label, validation_flags, incident_id FROM alerts WHERE decision IN ({marks}) "
                f"ORDER BY id DESC LIMIT 500", tuple(decisions))
        if not al.empty:
            al["validation_flags"] = al["validation_flags"].map(flags_str)
            st.dataframe(al, hide_index=True, width="stretch")
            pick = st.selectbox("Inspect alert", al["event_id"].tolist())
            if pick:
                r = dict(conn.execute("SELECT * FROM alerts WHERE event_id=?", (pick,)).fetchone())
                c1, c2 = st.columns(2)
                c1.markdown("**Features**")
                c1.json(json.loads(r["features"]) if r["features"] else {})
                c2.markdown("**Decision path (explainability)**")
                c2.code("\n".join(json.loads(r["explanation"])) if r["explanation"] else "not classified")
                c2.markdown("**ATT&CK mapping**")
                c2.json(json.loads(r["attack"]) if r["attack"] else {})
                if r["llm_summary"]:
                    c2.markdown("**LLM enrichment (advisory only)**")
                    c2.json(json.loads(r["llm_summary"]))


# ------------------------------------------------------------------ evidence
with tab_ev:
    c1, c2 = st.columns([1, 3])
    if c1.button("🔍 Verify hash chain"):
        res = evidence.verify(conn)
        if res["ok"]:
            c2.success(f"Chain intact: {res['records']} records · head `{res['head_hash'][:16]}…`")
        else:
            c2.error(f"Chain BROKEN at seq {res['first_bad_seq']}: {res['reason']}")
    ev = df("SELECT seq, ts, actor, event_type, ref, substr(record_hash,1,16) AS record_hash "
            "FROM evidence ORDER BY seq DESC LIMIT 300")
    if not ev.empty:
        st.dataframe(ev, hide_index=True, width="stretch")
        seq = st.number_input("Show record #", min_value=1, max_value=int(ev["seq"].max()), value=int(ev["seq"].max()))
        row = conn.execute("SELECT * FROM evidence WHERE seq=?", (int(seq),)).fetchone()
        if row:
            rec = evidence.row_to_record(row)
            rec["record_hash"] = row["record_hash"]
            st.json(rec)
        lines = []
        for r in conn.execute("SELECT * FROM evidence ORDER BY seq"):
            rec = evidence.row_to_record(r)
            rec["record_hash"] = r["record_hash"]
            lines.append(evidence.canonical(rec))
        st.download_button("Download full evidence log (JSONL)", "\n".join(lines) + "\n",
                           file_name="evidence.jsonl", mime="application/json")


# ------------------------------------------------------------------ system
with tab_sys:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Simulated blocklist")
        st.code("\n".join(response.list_entries(config.BLOCKLIST_FILE)) or "(empty)")
        st.markdown("#### Simulated quarantine")
        st.code("\n".join(response.list_entries(config.QUARANTINE_FILE)) or "(empty)")
        st.markdown("#### Protected assets (never auto-contained)")
        st.json(config.policy().get("protected_assets", {}))
    with c2:
        card = config.MODEL_DIR / "model_card.md"
        if card.exists():
            st.markdown(card.read_text())
