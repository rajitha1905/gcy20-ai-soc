"""Input validation and evasion / bypass detection.

Two layers:
  1. Schema validation (Pydantic). If the event cannot be parsed into the
     expected Suricata alert shape, it is NOT classified; it goes straight to
     human review.
  2. Evasion heuristics. The event parses, but something about it looks like
     an attempt to slip past the classifier (encoded strings, look-alike
     characters, downgraded severity, injected instructions, replayed lines).
     Any flag here prevents auto-closure regardless of what the model says.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

KNOWN_CATEGORIES = {
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "Attempted Information Leak",
    "A Network Trojan was detected",
    "Detection of a Network Scan",
    "Potentially Bad Traffic",
    "Misc activity",
    "Misc Attack",
    "Generic Protocol Command Decode",
    "Potential Corporate Privacy Violation",
    "Not Suspicious Traffic",
    "Unknown Traffic",
    "Web Application Attack",
    "Executable code was detected",
    "Successful Administrator Privilege Gain",
    "Unsuccessful User Privilege Gain",
}

# Signatures that should never arrive with the lowest severity
HIGH_RISK_KEYWORDS = re.compile(
    r"mimikatz|cobalt\s*strike|ransom|eternalblue|psexec|lsass|dcsync|kerberoast|meterpreter|c2|beacon",
    re.IGNORECASE,
)
PROMPT_INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior) instructions|disregard .*instructions|you are now|"
    r"system prompt|mark (this|it) as benign|classify (this|it) as benign|do not escalate",
    re.IGNORECASE,
)
B64_TOKEN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
HEX_ESCAPE = re.compile(r"(\\x[0-9a-fA-F]{2}){3,}")
PCT_ESCAPE = re.compile(r"(%[0-9a-fA-F]{2}){3,}")
ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}
MAX_FIELD_LEN = 512


class AlertBody(BaseModel):
    model_config = ConfigDict(extra="allow")
    signature: str
    signature_id: int
    category: str
    severity: int = Field(ge=1, le=4)
    action: Optional[str] = "allowed"


class FlowBody(BaseModel):
    model_config = ConfigDict(extra="allow")
    bytes_toserver: int = 0
    bytes_toclient: int = 0
    pkts_toserver: int = 0


class SuricataAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    timestamp: str
    event_type: str
    src_ip: str
    dest_ip: str
    src_port: Optional[int] = None
    dest_port: int = Field(ge=0, le=65535)
    proto: str
    alert: AlertBody
    flow: FlowBody = FlowBody()

    @field_validator("event_type")
    @classmethod
    def must_be_alert(cls, v: str) -> str:
        if v != "alert":
            raise ValueError("event_type must be 'alert'")
        return v


@dataclass
class ValidationResult:
    parsed: bool
    event: Optional[SuricataAlert] = None
    event_time: Optional[datetime] = None
    flags: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def trusted(self) -> bool:
        return self.parsed and not self.flags


def parse_ts(value: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            pass
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _looks_base64(token: str) -> bool:
    if not B64_TOKEN.match(token):
        return False
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    printable = sum(32 <= b < 127 for b in decoded)
    return len(decoded) >= 8 and printable / len(decoded) > 0.85


def string_flags(name: str, value: str) -> list[str]:
    flags = []
    if len(value) > MAX_FIELD_LEN:
        flags.append(f"oversized_field:{name}")
    if any(ch in ZERO_WIDTH for ch in value):
        flags.append(f"zero_width_chars:{name}")
    non_ascii = [ch for ch in value if ord(ch) > 127]
    if non_ascii:
        # Letters from other scripts mixed into an ASCII signature = homoglyph trick
        if any(unicodedata.category(ch).startswith("L") for ch in non_ascii):
            flags.append(f"homoglyph_or_non_ascii:{name}")
        else:
            flags.append(f"non_ascii:{name}")
    if any(_looks_base64(tok) for tok in value.split()):
        flags.append(f"base64_encoded:{name}")
    if HEX_ESCAPE.search(value) or PCT_ESCAPE.search(value):
        flags.append(f"escaped_encoding:{name}")
    if len(value) > 24 and " " not in value and shannon_entropy(value) > 4.2:
        flags.append(f"high_entropy:{name}")
    if PROMPT_INJECTION.search(value):
        flags.append(f"prompt_injection_pattern:{name}")
    return flags


def ip_flags(name: str, value: str) -> list[str]:
    try:
        ipaddress.ip_address(value)
        return []
    except ValueError:
        return [f"invalid_or_encoded_ip:{name}"]


def validate(event_dict: dict, ingest_time: Optional[datetime] = None,
             seen_raw_hash: bool = False) -> ValidationResult:
    ingest_time = ingest_time or datetime.now(timezone.utc)
    try:
        ev = SuricataAlert.model_validate(event_dict)
    except ValidationError as exc:
        errors = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        return ValidationResult(parsed=False, errors=errors, flags=["schema_violation"])

    flags: list[str] = []
    flags += ip_flags("src_ip", ev.src_ip)
    flags += ip_flags("dest_ip", ev.dest_ip)
    flags += string_flags("signature", ev.alert.signature)
    flags += string_flags("category", ev.alert.category)

    if ev.alert.category not in KNOWN_CATEGORIES and not any(f.endswith(":category") for f in flags):
        flags.append("unknown_category")

    if HIGH_RISK_KEYWORDS.search(ev.alert.signature) and ev.alert.severity >= 3:
        flags.append("severity_mismatch")

    event_time = parse_ts(ev.timestamp)
    if event_time is None:
        flags.append("timestamp_unparseable")
    else:
        if event_time - ingest_time > timedelta(minutes=5):
            flags.append("timestamp_in_future")
        elif ingest_time - event_time > timedelta(hours=24):
            flags.append("timestamp_stale_or_replayed")

    if seen_raw_hash:
        flags.append("duplicate_replay")

    return ValidationResult(parsed=True, event=ev, event_time=event_time, flags=flags)
