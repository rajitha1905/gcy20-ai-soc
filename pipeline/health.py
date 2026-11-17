"""Heartbeat helpers + healthcheck entry point.

    python -m pipeline.health collector   # exit 0 healthy, 1 unhealthy
"""
from __future__ import annotations

import sys
import time

from . import config


def heartbeat_path(service: str):
    return config.STATE_DIR / f"{service}.heartbeat"


def beat(service: str) -> None:
    p = heartbeat_path(service)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(time.time()))


def age(service: str) -> float | None:
    try:
        return time.time() - float(heartbeat_path(service).read_text())
    except (FileNotFoundError, ValueError):
        return None


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    service = argv[0] if argv else "collector"
    limit = config.policy()["health"]["max_heartbeat_age_seconds"]
    a = age(service)
    if a is None:
        print(f"{service}: no heartbeat")
        return 1
    healthy = a <= limit
    print(f"{service}: heartbeat {a:.1f}s ago ({'healthy' if healthy else 'UNHEALTHY'}, limit {limit}s)")
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
