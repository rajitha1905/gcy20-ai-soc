"""Central configuration: paths, policy and reputation data."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
from functools import lru_cache
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", APP_DIR / "runtime"))

POLICY_PATH = Path(os.environ.get("POLICY_PATH", APP_DIR / "config" / "policy.json"))
REPUTATION_PATH = APP_DIR / "data" / "reputation.csv"
MODEL_DIR = APP_DIR / "models" / "artifacts"

INCOMING_FILE = DATA_DIR / "incoming" / "eve.json"   # where sensors / the generator write
QUEUE_FILE = DATA_DIR / "queue" / "events.jsonl"      # collector -> engine hand-off
STATE_DIR = DATA_DIR / "state"
DB_PATH = DATA_DIR / "soc.db"
BLOCKLIST_FILE = DATA_DIR / "response" / "blocklist.txt"
QUARANTINE_FILE = DATA_DIR / "response" / "quarantine.txt"
EXPORT_DIR = DATA_DIR / "exports"

COLLECTOR_FAULT_FLAG = STATE_DIR / "collector.fault"  # fault injection for the self-healing demo


def ensure_dirs() -> None:
    for p in (INCOMING_FILE.parent, QUEUE_FILE.parent, STATE_DIR,
              BLOCKLIST_FILE.parent, EXPORT_DIR):
        p.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def policy() -> dict:
    with open(POLICY_PATH, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def policy_sha256() -> str:
    return hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()


@lru_cache(maxsize=1)
def internal_networks():
    return [ipaddress.ip_network(n) for n in policy()["internal_networks"]]


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in internal_networks())


@lru_cache(maxsize=1)
def reputation_table() -> dict[str, int]:
    table: dict[str, int] = {}
    with open(REPUTATION_PATH, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            table[row["ip"].strip()] = int(row["score"])
    return table


def reputation(ip: str) -> int:
    """0 (trusted) .. 100 (known bad). Internal hosts default to 0."""
    table = reputation_table()
    if ip in table:
        return table[ip]
    if is_internal(ip):
        return 0
    return int(policy().get("default_external_reputation", 20))
