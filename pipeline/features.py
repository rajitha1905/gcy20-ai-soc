"""Feature extraction shared by training and live scoring.

The same `FeatureState` is used when building the training set and when the
engine scores live events, so the model never sees features computed a
different way in production than in training.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from . import config

FEATURES = [
    "sev_score",          # 3 = Suricata severity 1 (highest) ... 0 = severity 4
    "src_internal",
    "dest_internal",
    "int_to_int",
    "dest_port_admin",    # SSH, RDP, SMB, WinRM, Kerberos, LDAP, RPC
    "dest_port_web",
    "src_reputation",     # 0..100
    "dest_reputation",
    "cat_scan",
    "cat_credential",
    "cat_exploit",
    "cat_c2",
    "cat_lateral",
    "cat_policy_info",
    "repeat_5m",          # alerts from this source in the sliding window
    "distinct_dest_5m",   # distinct internal destinations from this source in the window
    "off_hours",
    "bytes_log",
]

ADMIN_PORTS = {22, 23, 88, 135, 139, 389, 445, 636, 3389, 5985, 5986}
WEB_PORTS = {80, 443, 8080, 8443}

KW = {
    "cat_scan": re.compile(r"\bscan|nmap|masscan|sweep|probe", re.I),
    "cat_credential": re.compile(r"brute|login|logon|auth|password|kerberos|ntlm|credential|spray", re.I),
    "cat_exploit": re.compile(r"exploit|cve-|overflow|injection|rce|eternalblue|shellcode", re.I),
    "cat_c2": re.compile(r"\bc2\b|beacon|cobalt|trojan|botnet|callback|command and control|meterpreter", re.I),
    "cat_lateral": re.compile(r"psexec|wmi|winrm|dcerpc|remote service|smb.*(admin|exec)|admin\$|lateral", re.I),
    "cat_policy_info": re.compile(r"\bpolicy\b|\binfo\b|update|dns query|stream", re.I),
}
CATEGORY_HINTS = {
    "Detection of a Network Scan": "cat_scan",
    "Attempted User Privilege Gain": "cat_credential",
    "Unsuccessful User Privilege Gain": "cat_credential",
    "A Network Trojan was detected": "cat_c2",
    "Web Application Attack": "cat_exploit",
    "Attempted Administrator Privilege Gain": "cat_exploit",
    "Potential Corporate Privacy Violation": "cat_policy_info",
    "Not Suspicious Traffic": "cat_policy_info",
    "Generic Protocol Command Decode": "cat_policy_info",
}


def category_flags(signature: str, category: str) -> dict[str, int]:
    out = {k: int(bool(rx.search(signature))) for k, rx in KW.items()}
    hint = CATEGORY_HINTS.get(category)
    if hint:
        out[hint] = 1
    return out


class FeatureState:
    """Sliding-window counters per source IP."""

    def __init__(self, window_minutes: int | None = None):
        pol = config.policy()
        self.window = timedelta(minutes=window_minutes or pol.get("feature_window_minutes", 5))
        bh = pol["business_hours"]
        self.bh_start, self.bh_end = bh["start"], bh["end"]
        self.tz = timezone(timedelta(hours=bh["utc_offset_hours"]))
        self.events: dict[str, deque] = defaultdict(deque)   # src -> deque[(ts, dest)]

    def _prune(self, src: str, now: datetime) -> None:
        dq = self.events[src]
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

    def observe(self, src: str, dest: str, ts: datetime) -> None:
        self.events[src].append((ts, dest))

    def compute(self, ev: dict, ts: datetime, observe: bool = True) -> dict[str, float]:
        src, dest = ev["src_ip"], ev["dest_ip"]
        alert = ev["alert"]
        flow = ev.get("flow") or {}
        if observe:
            self.observe(src, dest, ts)
        self._prune(src, ts)
        window = self.events[src]
        src_int, dest_int = config.is_internal(src), config.is_internal(dest)
        port = int(ev.get("dest_port") or 0)
        local_hour = ts.astimezone(self.tz).hour
        feats = {
            "sev_score": max(0, 4 - int(alert.get("severity", 3))),
            "src_internal": int(src_int),
            "dest_internal": int(dest_int),
            "int_to_int": int(src_int and dest_int),
            "dest_port_admin": int(port in ADMIN_PORTS),
            "dest_port_web": int(port in WEB_PORTS),
            "src_reputation": config.reputation(src),
            "dest_reputation": config.reputation(dest),
            "repeat_5m": len(window),
            "distinct_dest_5m": len({d for _, d in window if config.is_internal(d)}),
            "off_hours": int(not (self.bh_start <= local_hour < self.bh_end)),
            "bytes_log": round(math.log10(1 + int(flow.get("bytes_toserver", 0) or 0)), 3),
        }
        feats.update(category_flags(alert.get("signature", ""), alert.get("category", "")))
        return {k: float(feats[k]) for k in FEATURES}
