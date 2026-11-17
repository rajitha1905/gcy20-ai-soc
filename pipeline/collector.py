"""Log collector: tails the Suricata-style eve.json and forwards each line to the
engine queue, stamping it with an ingest time, sequence number and SHA-256 of
the exact raw bytes (chain of custody starts here).

Fault injection for the self-healing demo:
    podman exec soc-collector touch /data/state/collector.fault
makes the collector "hang" (still running, but no heartbeat and no forwarding).
The healthcheck fails, the host watchdog restarts the container, and on
startup the collector clears the fault, records the recovery, and resumes from
its saved offset, so no events are lost.
"""
from __future__ import annotations

import hashlib
import json
import time

from . import config, db, evidence, health

OFFSET_FILE = config.STATE_DIR / "collector.offset"
SEQ_FILE = config.STATE_DIR / "collector.seq"
POLL_SECONDS = 1.0


def _read_int(path, default=0) -> int:
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return default


def run_once(offset: int, seq: int) -> tuple[int, int, int]:
    """Forward complete new lines. Returns (new_offset, new_seq, forwarded)."""
    src = config.INCOMING_FILE
    if not src.exists():
        return offset, seq, 0
    size = src.stat().st_size
    if size < offset:          # file truncated or replaced: possible log tampering
        conn = db.connect()
        evidence.append(conn, "collector", "source_truncated", str(src),
                        {"previous_offset": offset, "current_size": size})
        conn.close()
        offset = 0
    if size == offset:
        return offset, seq, 0
    with open(src, "rb") as f:
        f.seek(offset)
        chunk = f.read(size - offset)
    end = chunk.rfind(b"\n")
    if end < 0:
        return offset, seq, 0          # partial line still being written
    lines = chunk[: end + 1].splitlines()
    forwarded = 0
    with open(config.QUEUE_FILE, "a", encoding="utf-8") as q:
        for raw in lines:
            if not raw.strip():
                continue
            seq += 1
            text = raw.decode("utf-8", errors="replace")
            q.write(json.dumps({
                "collector_seq": seq,
                "ingest_ts": db.utcnow(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "raw": text,
            }) + "\n")
            forwarded += 1
    new_offset = offset + end + 1
    OFFSET_FILE.write_text(str(new_offset))
    SEQ_FILE.write_text(str(seq))
    return new_offset, seq, forwarded


def main() -> None:
    config.ensure_dirs()
    conn = db.connect()
    offset, seq = _read_int(OFFSET_FILE), _read_int(SEQ_FILE)
    recovered = config.COLLECTOR_FAULT_FLAG.exists()
    if recovered:
        config.COLLECTOR_FAULT_FLAG.unlink()
    evidence.append(conn, "collector", "collector_recovered" if recovered else "collector_started", "collector",
                    {"resume_offset": offset, "resume_seq": seq})
    conn.close()
    print(f"[collector] started (offset={offset}, seq={seq}, recovered={recovered})", flush=True)

    while True:
        if config.COLLECTOR_FAULT_FLAG.exists():
            # Simulated hang: stay alive but stop heartbeating and forwarding.
            time.sleep(POLL_SECONDS)
            continue
        offset, seq, n = run_once(offset, seq)
        if n:
            print(f"[collector] forwarded {n} event(s), seq={seq}", flush=True)
        health.beat("collector")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
