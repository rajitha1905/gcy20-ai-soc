"""Decision-tree classifier + Isolation Forest outlier check, with explanations."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache

import joblib
import numpy as np

from . import config
from .features import FEATURES

LABELS = ["benign", "suspicious", "credential_attack", "lateral_movement", "high_severity"]
MODEL_FILE = config.MODEL_DIR / "model.joblib"


@dataclass
class Prediction:
    label: str
    confidence: float
    probabilities: dict[str, float]
    explanation: list[str]
    anomaly_score: float
    is_outlier: bool


@lru_cache(maxsize=1)
def load():
    bundle = joblib.load(MODEL_FILE)
    sha = hashlib.sha256(MODEL_FILE.read_bytes()).hexdigest()
    bundle["sha256"] = sha
    bundle["version"] = f"{bundle['name']}@{sha[:12]}"
    return bundle


def model_metadata() -> dict:
    b = load()
    meta_path = config.MODEL_DIR / "metrics.json"
    metrics = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    return {"version": b["version"], "sha256": b["sha256"], "trained_at": b["trained_at"],
            "sklearn": b["sklearn_version"], "features": b["features"], "labels": b["labels"],
            "metrics": metrics}


def explain(tree, x: np.ndarray) -> list[str]:
    """Return the decision path as human-readable conditions."""
    t = tree.tree_
    node_ids = tree.decision_path(x.reshape(1, -1)).indices
    steps = []
    for node in node_ids:
        if t.children_left[node] == t.children_right[node]:   # leaf
            continue
        feat = FEATURES[t.feature[node]]
        thr = t.threshold[node]
        val = x[t.feature[node]]
        op = "<=" if val <= thr else ">"
        steps.append(f"{feat} = {val:g} ({op} {thr:.2f})")
    return steps


def predict(features: dict[str, float]) -> Prediction:
    b = load()
    x = np.array([features[f] for f in FEATURES], dtype=float)
    tree, iforest = b["tree"], b["iforest"]
    proba = tree.predict_proba(x.reshape(1, -1))[0]
    classes = list(tree.classes_)
    idx = int(np.argmax(proba))
    score = float(iforest.decision_function(x.reshape(1, -1))[0])
    return Prediction(
        label=classes[idx],
        confidence=round(float(proba[idx]), 4),
        probabilities={c: round(float(p), 4) for c, p in zip(classes, proba)},
        explanation=explain(tree, x),
        anomaly_score=round(score, 4),
        is_outlier=bool(iforest.predict(x.reshape(1, -1))[0] == -1),
    )
