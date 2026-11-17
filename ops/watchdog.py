"""Host-side self-healing watchdog for the Podman deployment (stdlib only).

Run on your Windows host (PowerShell) from the repo folder:
    python ops\\watchdog.py

Every few seconds it checks each pipeline container:
  * not running            -> `podman start`
  * running but unhealthy  -> after N consecutive failed healthchecks, `podman restart`
Each recovery is written to a local hash-chained log (ops/watchdog_log.jsonl)
AND to the central evidence log inside the pipeline (via `podman exec`).

Why on the host and not in a container: giving a container the Podman socket
would let anything in that container control every other container, which is
a privilege-escalation path. The watchdog only needs the same rights you have.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOG = Path(__file__).resolve().parent / "watchdog_log.jsonl"
SERVICES = {"soc-collector": "collector", "soc-engine": "engine"}
EVIDENCE_CONTAINER = "soc-engine"


def podman(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run([PODMAN, *args], capture_output=True, text=True, timeout=timeout)


def last_hash() -> str:
    if not LOG.exists():
        return "0" * 64
    lines = LOG.read_text(encoding="utf-8").strip().splitlines()
    return json.loads(lines[-1])["record_hash"] if lines else "0" * 64


def log_event(event_type: str, container: str, detail: str) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "actor": "watchdog",
           "event_type": event_type, "container": container, "detail": detail, "prev_hash": last_hash()}
    rec["record_hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    print(f"[watchdog] {rec['ts']} {event_type} {container}: {detail}", flush=True)
    # Mirror into the central evidence log (best effort; the engine may be the one that is down).
    try:
        r = podman("exec", EVIDENCE_CONTAINER, "python", "-m", "pipeline.evidence", "ops-event",
                   "--actor", "watchdog", "--type", event_type, "--ref", container, "--detail", detail)
        if r.returncode != 0:
            print(f"[watchdog]   (central evidence log unavailable: {r.stderr.strip()[:120]})", flush=True)
    except subprocess.TimeoutExpired:
        print("[watchdog]   (central evidence log timed out)", flush=True)


def status(container: str) -> str:
    r = podman("inspect", "--format", "{{.State.Status}}", container)
    return r.stdout.strip() if r.returncode == 0 else "missing"


def healthy(container: str, service: str) -> tuple[bool, str]:
    r = podman("healthcheck", "run", container)
    if r.returncode in (0, 1) and "no defined healthcheck" not in (r.stderr or "").lower():
        return r.returncode == 0, (r.stdout or r.stderr).strip() or ("healthy" if r.returncode == 0 else "unhealthy")
    # Fallback if the compose provider did not register a healthcheck
    r = podman("exec", container, "python", "-m", "pipeline.health", service)
    return r.returncode == 0, (r.stdout or r.stderr).strip()


def main(argv=None) -> int:
    global PODMAN
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--failures", type=int, default=2, help="consecutive failed checks before restart")
    args = ap.parse_args(argv)

    PODMAN = shutil.which("podman")
    if not PODMAN:
        print("podman not found on PATH", file=sys.stderr)
        return 1
    fails = {c: 0 for c in SERVICES}
    print(f"[watchdog] monitoring {', '.join(SERVICES)} every {args.interval}s (Ctrl+C to stop)", flush=True)
    log_event("watchdog_started", "-", f"interval={args.interval}s failures={args.failures}")
    try:
        while True:
            for container, service in SERVICES.items():
                st = status(container)
                if st == "missing":
                    continue
                if st != "running":
                    r = podman("start", container)
                    log_event("service_started", container,
                              f"was '{st}'; podman start -> {'ok' if r.returncode == 0 else r.stderr.strip()}")
                    fails[container] = 0
                    continue
                ok, msg = healthy(container, service)
                if ok:
                    fails[container] = 0
                    continue
                fails[container] += 1
                print(f"[watchdog] {container} unhealthy ({fails[container]}/{args.failures}): {msg}", flush=True)
                if fails[container] >= args.failures:
                    r = podman("restart", "--time", "3", container, timeout=60)
                    log_event("service_restarted", container,
                              f"{fails[container]} failed healthchecks ({msg}); podman restart -> "
                              f"{'ok' if r.returncode == 0 else r.stderr.strip()}")
                    fails[container] = 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log_event("watchdog_stopped", "-", "stopped by operator")
    return 0


PODMAN = "podman"

if __name__ == "__main__":
    sys.exit(main())
