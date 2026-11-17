"""Train the decision tree + Isolation Forest and write a model card.

    python -m models.train

Training data is generated deterministically (seed 42) by the same generator
and feature code the live pipeline uses. Outputs go to models/artifacts/.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from generator.generate import training_events
from pipeline import config
from pipeline.classifier import LABELS
from pipeline.features import FEATURES, FeatureState
from pipeline.validator import parse_ts

SEED = 42
LABEL_NOISE = 0.02   # simulate imperfect analyst labelling


def build_dataset():
    state = FeatureState()
    rng = random.Random(SEED)
    X, y = [], []
    for ev, label in training_events(episodes=1200, seed=SEED):
        feats = state.compute(ev, parse_ts(ev["timestamp"]))
        if rng.random() < LABEL_NOISE:
            label = rng.choice(LABELS)
        X.append([feats[f] for f in FEATURES])
        y.append(label)
    return np.array(X), np.array(y)


def main() -> None:
    X, y = build_dataset()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=SEED, stratify=y)

    tree = DecisionTreeClassifier(max_depth=6, min_samples_leaf=4, class_weight="balanced", random_state=SEED)
    tree.fit(X_tr, y_tr)
    iforest = IsolationForest(n_estimators=150, contamination=0.01, random_state=SEED).fit(X_tr)

    y_pred = tree.predict(X_te)
    report = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_te, y_pred, labels=LABELS).tolist()
    importances = sorted(zip(FEATURES, tree.feature_importances_), key=lambda kv: -kv[1])

    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    joblib.dump({"name": "soc-dtree", "tree": tree, "iforest": iforest, "features": FEATURES,
                 "labels": LABELS, "trained_at": trained_at, "seed": SEED,
                 "sklearn_version": sklearn.__version__}, config.MODEL_DIR / "model.joblib")

    metrics = {
        "trained_at": trained_at, "samples_total": int(len(y)), "samples_test": int(len(y_te)),
        "class_counts": {c: int((y == c).sum()) for c in LABELS},
        "accuracy": round(report["accuracy"], 4),
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "per_class": {c: {k: round(report[c][k], 4) for k in ("precision", "recall", "f1-score")}
                      for c in LABELS if c in report},
        "confusion_matrix": {"labels": LABELS, "matrix": cm},
        "feature_importance": {f: round(float(v), 4) for f, v in importances if v > 0},
        "tree_depth": int(tree.get_depth()), "tree_leaves": int(tree.get_n_leaves()),
    }
    (config.MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (config.MODEL_DIR / "tree_rules.txt").write_text(export_text(tree, feature_names=FEATURES))

    rows = "\n".join(f"| {c} | {v['precision']:.2f} | {v['recall']:.2f} | {v['f1-score']:.2f} |"
                     for c, v in metrics["per_class"].items())
    top = "\n".join(f"- `{f}`: {v:.3f}" for f, v in list(metrics["feature_importance"].items())[:8])
    card = f"""# Model card: soc-dtree

**Trained:** {trained_at}  **scikit-learn:** {sklearn.__version__}  **Seed:** {SEED}

## Purpose
Triage support for Suricata alerts in a lab SOC. Labels: {", ".join(LABELS)}.
Outputs are recommendations routed through a decision policy; containment always
requires analyst approval unless `auto_contain` is explicitly enabled.

## Data
{len(y)} synthetic alerts from `generator.generate.training_events` (seed {SEED}), with
{int(LABEL_NOISE*100)}% random label noise to mimic imperfect labelling. No real network data.

## Hold-out performance (25% split)
Accuracy {metrics['accuracy']:.3f}, macro F1 {metrics['macro_f1']:.3f}

| Class | Precision | Recall | F1 |
|---|---|---|---|
{rows}

## Most influential features
{top}

## Known limitations
- Trained and tested on synthetic data from the same generator, so these scores are
  optimistic and will not transfer to real traffic without retraining.
- Sees only alert metadata, not payloads or host telemetry.
- Window counters are per source IP; distributed attacks across many sources are under-counted.
- Isolation Forest flags unusual feature combinations, not every evasion; evasion is mainly
  caught by the validator.
"""
    (config.MODEL_DIR / "model_card.md").write_text(card)
    print(card)


if __name__ == "__main__":
    main()
