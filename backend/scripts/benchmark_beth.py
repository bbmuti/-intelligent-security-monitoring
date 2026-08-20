"""Evaluate Isolation Forest on the real, labeled BETH process-event dataset."""

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

FEATURE_NAMES = [
    "time_sin",
    "time_cos",
    "process_is_non_kernel",
    "parent_is_non_kernel",
    "user_is_unprivileged",
    "mount_namespace_is_unusual",
    "event_id_bucket",
    "argument_count",
    "return_value_class",
]


def numeric(row: dict[str, str], key: str, default: float = 0.0) -> float:
    try:
        return float(row.get(key, default))
    except (TypeError, ValueError):
        return default


def beth_features(row: dict[str, str]) -> list[float]:
    timestamp = numeric(row, "timestamp")
    angle = 2 * np.pi * ((timestamp % 86_400) / 86_400)
    process_id = numeric(row, "processId")
    parent_id = numeric(row, "parentProcessId")
    user_id = numeric(row, "userId")
    mount_namespace = numeric(row, "mountNamespace")
    event_id = numeric(row, "eventId")
    return_value = numeric(row, "returnValue")
    return [
        float(np.sin(angle)),
        float(np.cos(angle)),
        float(process_id not in {0, 1, 2}),
        float(parent_id not in {0, 1, 2}),
        float(user_id >= 1000),
        float(mount_namespace != 4_026_531_840),
        float((int(event_id) % 1024) / 1024),
        float(min(numeric(row, "argsNum"), 20) / 20),
        float(0 if return_value == 0 else 1 if return_value > 0 else -1),
    ]


def beth_label(row: dict[str, str]) -> int:
    return int(str(row.get("evil", "0")).strip().lower() in {"1", "true", "yes"})


def reservoir(path: Path, limit: int, *, benign_only: bool, seed: int) -> tuple[np.ndarray, np.ndarray, int]:
    rng = np.random.default_rng(seed)
    features: list[list[float]] = []
    labels: list[int] = []
    eligible = 0
    csv.field_size_limit(10_000_000)
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            label = beth_label(row)
            if benign_only and label:
                continue
            eligible += 1
            values = beth_features(row)
            if len(features) < limit:
                features.append(values)
                labels.append(label)
                continue
            replacement = int(rng.integers(0, eligible))
            if replacement < limit:
                features[replacement] = values
                labels[replacement] = label
    if not features:
        raise ValueError(f"No eligible BETH records found in {path}")
    return np.asarray(features, dtype=float), np.asarray(labels, dtype=int), eligible


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def metrics(labels: np.ndarray, predictions: np.ndarray, scores: np.ndarray) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(labels, predictions)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(labels, scores)), 4),
        "average_precision": round(float(average_precision_score(labels, scores)), 4),
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def select_threshold(scores: np.ndarray, percentile: float) -> float:
    """Select a threshold from the separate benign validation distribution."""

    if not 0 < percentile < 100:
        raise ValueError("Threshold percentile must be between 0 and 100")
    return float(np.percentile(scores, percentile))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a reproducible Isolation Forest benchmark on BETH")
    parser.add_argument("--train", type=Path, required=True, help="BETH labelled training CSV")
    parser.add_argument("--validation", type=Path, required=True, help="BETH labelled validation CSV")
    parser.add_argument("--test", type=Path, required=True, help="BETH labelled testing CSV")
    parser.add_argument("--max-train", type=int, default=100_000)
    parser.add_argument("--max-validation", type=int, default=100_000)
    parser.add_argument("--max-test", type=int, default=100_000)
    parser.add_argument("--threshold-percentile", type=float, default=95.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    train_x, _, train_eligible = reservoir(args.train, args.max_train, benign_only=True, seed=42)
    validation_x, validation_y, validation_eligible = reservoir(
        args.validation, args.max_validation, benign_only=False, seed=43
    )
    test_x, test_y, test_eligible = reservoir(args.test, args.max_test, benign_only=False, seed=44)
    if len(np.unique(test_y)) < 2:
        raise ValueError("The sampled test data must contain both benign and malicious labels")
    if validation_y.any():
        raise ValueError("BETH validation calibration expects the official benign-only split")

    model = IsolationForest(n_estimators=240, contamination="auto", random_state=42, n_jobs=-1)
    model.fit(train_x)
    validation_scores = -model.decision_function(validation_x)
    threshold = select_threshold(validation_scores, args.threshold_percentile)
    validation_predictions = (validation_scores >= threshold).astype(int)
    test_scores = -model.decision_function(test_x)
    predictions = (test_scores >= threshold).astype(int)

    report = {
        "benchmark": "BETH real cybersecurity process events",
        "algorithm": "IsolationForest",
        "evaluation_scope": "Algorithm-family validation; not an end-to-end authentication detector benchmark.",
        "dataset": {
            "paper": "BETH Dataset: Real Cybersecurity Data for Unsupervised Anomaly Detection Research",
            "license": "CC0-1.0",
            "source": "https://www.kaggle.com/datasets/katehighnam/beth-dataset",
            "version": 3,
            "train_sha256": digest(args.train),
            "validation_sha256": digest(args.validation),
            "test_sha256": digest(args.test),
        },
        "features": FEATURE_NAMES,
        "sampling": {
            "seeds": {"train": 42, "validation": 43, "test": 44},
            "eligible_benign_train_rows": train_eligible,
            "sampled_train_rows": len(train_x),
            "eligible_validation_rows": validation_eligible,
            "sampled_validation_rows": len(validation_x),
            "validation_attack_rows": int(validation_y.sum()),
            "eligible_test_rows": test_eligible,
            "sampled_test_rows": len(test_x),
            "test_attack_rows": int(test_y.sum()),
        },
        "threshold": {
            "method": "percentile of the separate benign validation anomaly scores",
            "percentile": args.threshold_percentile,
            "value": round(threshold, 6),
        },
        "validation_false_positive_rate": round(float(validation_predictions.mean()), 4),
        "metrics": metrics(test_y, predictions, test_scores),
        "limitations": [
            "BETH contains host process telemetry rather than SentinelScope authentication/API events.",
            "Results validate the Isolation Forest algorithm family, not the full hybrid rule engine.",
            "The decision threshold is calibrated on the official benign-only validation split.",
            "Class imbalance makes accuracy insufficient; recall, precision, AUROC, AP, and FPR are reported.",
        ],
    }
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
