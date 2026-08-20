"""Deterministic smoke evaluation for the hybrid rule + anomaly detector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from app.detection import ALERT_THRESHOLD, MODEL_VERSION, DetectionEngine


def event(**values):
    defaults = {
        "timestamp": datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        "event_type": "api_access",
        "outcome": "success",
        "role": "user",
        "ip_address": "10.0.0.20",
        "user_id": "evaluation-user",
        "country": "TR",
        "endpoint": "/api/profile",
        "details": {},
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def dataset():
    rows = []
    base = datetime(2026, 8, 20, 8, 0, tzinfo=UTC)
    for index in range(120):
        rows.append((event(timestamp=base + timedelta(minutes=index * 5)), 0, []))
    for index in range(20):
        rows.append((event(timestamp=base.replace(hour=2) + timedelta(minutes=index)), 1, []))
    for _index in range(20):
        rows.append((event(event_type="role_change", outcome="denied", endpoint="/admin/roles"), 1, []))
    for index in range(20):
        recent = [event(event_type="login", outcome="failure", ip_address=f"203.0.113.{index + 1}") for _ in range(4)]
        rows.append((event(event_type="login", outcome="failure", ip_address=f"203.0.113.{index + 1}"), 1, recent))
    return rows


def main() -> None:
    engine = DetectionEngine()
    labels, predictions = [], []
    for current, label, recent in dataset():
        result = engine.analyze(current, recent)
        labels.append(label)
        predictions.append(int(result.risk_score >= ALERT_THRESHOLD))
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, predictions).ravel()
    report = {
        "model_version": MODEL_VERSION,
        "evaluation_type": "deterministic synthetic smoke evaluation",
        "samples": len(labels),
        "accuracy": round(accuracy_score(labels, predictions), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "limitations": "This validates deterministic regression behavior; it is not a production benchmark.",
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
