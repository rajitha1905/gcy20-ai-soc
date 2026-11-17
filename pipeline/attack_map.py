"""Static MITRE ATT&CK mapping.

Deliberately a lookup table, not an LLM: the technique IDs shown to analysts
can never be invented, and every mapping is reviewable in code.
"""
from __future__ import annotations

import re

RULES = [
    (re.compile(r"kerberos|kerberoast|tgs", re.I), ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")),
    (re.compile(r"spray", re.I), ("T1110.003", "Brute Force: Password Spraying")),
    (re.compile(r"brute|login|logon|auth fail|password", re.I), ("T1110", "Brute Force")),
    (re.compile(r"psexec|admin\$|smb.*exec", re.I), ("T1021.002", "Remote Services: SMB/Windows Admin Shares")),
    (re.compile(r"winrm", re.I), ("T1021.006", "Remote Services: Windows Remote Management")),
    (re.compile(r"\brdp\b|3389", re.I), ("T1021.001", "Remote Services: Remote Desktop Protocol")),
    (re.compile(r"wmi", re.I), ("T1047", "Windows Management Instrumentation")),
    (re.compile(r"beacon|cobalt|\bc2\b|callback|trojan", re.I), ("T1071", "Application Layer Protocol (C2)")),
    (re.compile(r"exploit|cve-|rce|injection", re.I), ("T1190", "Exploit Public-Facing Application")),
    (re.compile(r"scan|sweep|probe", re.I), ("T1046", "Network Service Discovery")),
]

LABEL_DEFAULTS = {
    "credential_attack": ("T1110", "Brute Force"),
    "lateral_movement": ("T1021", "Remote Services"),
    "high_severity": ("T1071", "Application Layer Protocol (C2)"),
}


def map_technique(signature: str, label: str) -> dict | None:
    for rx, (tid, name) in RULES:
        if rx.search(signature or ""):
            return {"technique_id": tid, "name": name, "source": "static-rule"}
    if label in LABEL_DEFAULTS:
        tid, name = LABEL_DEFAULTS[label]
        return {"technique_id": tid, "name": name, "source": "label-default"}
    return None
