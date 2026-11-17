"""Decision policy: turns model output + validation flags into a routing decision.

Safety properties (covered by tests):
  * An event that failed schema validation is never classified or auto-closed.
  * An event with ANY evasion flag is never auto-closed.
  * High-risk labels are never downgraded because of flags; they escalate AND
    are marked for review.
  * Containment is requested, not executed, unless auto_contain is enabled
    AND confidence is very high AND the event is fully trusted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import config

HIGH_RISK = {"credential_attack", "lateral_movement", "high_severity"}

AUTO_CLOSE = "AUTO_CLOSE"
TICKET = "TICKET"
ESCALATE = "ESCALATE"
NEEDS_REVIEW = "NEEDS_REVIEW"

STATUS_FOR = {
    AUTO_CLOSE: "closed_auto",
    TICKET: "ticketed",
    ESCALATE: "escalated",
    NEEDS_REVIEW: "needs_review",
}


@dataclass
class Decision:
    decision: str
    reasons: list[str] = field(default_factory=list)
    request_containment: bool = False
    auto_execute_containment: bool = False
    needs_human: bool = False


def decide(label: str | None, confidence: float | None, flags: list[str],
           is_outlier: bool, parsed: bool) -> Decision:
    th = config.policy()["thresholds"]
    auto_contain = bool(config.policy().get("auto_contain", False))

    if not parsed or label is None:
        return Decision(NEEDS_REVIEW, ["event failed schema validation; not classified"], needs_human=True)

    reasons: list[str] = []
    if flags:
        reasons.append("validation flags present: " + ", ".join(flags))
    if is_outlier:
        reasons.append("feature vector is an outlier vs. training data (Isolation Forest)")

    if label in HIGH_RISK and confidence >= th["escalate_min_confidence"]:
        reasons.insert(0, f"model label '{label}' with confidence {confidence:.2f}")
        trusted = not flags and not is_outlier
        auto_exec = auto_contain and trusted and confidence >= th["auto_contain_min_confidence"]
        if not auto_exec:
            reasons.append("containment requires analyst approval")
        return Decision(ESCALATE, reasons, request_containment=True,
                        auto_execute_containment=auto_exec, needs_human=not trusted or not auto_exec)

    if flags or is_outlier:
        reasons.insert(0, f"model said '{label}' ({confidence:.2f}) but input is not trusted")
        return Decision(NEEDS_REVIEW, reasons, needs_human=True)

    if confidence < th["review_below_confidence"]:
        return Decision(NEEDS_REVIEW, [f"low confidence {confidence:.2f} for '{label}'"], needs_human=True)

    if label == "benign":
        if confidence >= th["auto_close_min_confidence"]:
            return Decision(AUTO_CLOSE, [f"benign with confidence {confidence:.2f}; no flags"])
        return Decision(NEEDS_REVIEW, [f"benign but confidence {confidence:.2f} below auto-close threshold"],
                        needs_human=True)

    if label in HIGH_RISK:   # high-risk label but confidence below escalate threshold
        return Decision(NEEDS_REVIEW, [f"possible {label} at low confidence {confidence:.2f}"], needs_human=True)

    return Decision(TICKET, [f"suspicious activity ({confidence:.2f}); ticket opened for analyst queue"])
