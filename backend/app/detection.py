from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

import numpy as np
from sklearn.ensemble import IsolationForest


class EventLike(Protocol):
    timestamp: datetime
    event_type: str
    outcome: str
    role: str
    ip_address: str
    user_id: str
    endpoint: str
    details: dict


@dataclass
class DetectionResult:
    risk_score: float
    anomaly_score: float
    severity: str
    title: str
    mitre_technique: str
    evidence: list[str] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        if not self.evidence:
            return "Activity is consistent with the current behavioral baseline."
        return "Risk increased because " + "; ".join(item.lower() for item in self.evidence) + "."


class BehaviorModel:
    """Small deterministic baseline model for demonstrable local behavior scoring."""

    def __init__(self) -> None:
        rng = np.random.default_rng(42)
        normal_hours = np.clip(rng.normal(13, 3, 300), 7, 22)
        baseline = np.column_stack(
            [
                normal_hours,
                np.zeros(300),
                rng.choice([0, 1], 300, p=[0.9, 0.1]),
                np.zeros(300),
                rng.poisson(2, 300),
            ]
        )
        self.model = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
        self.model.fit(baseline)

    @staticmethod
    def features(event: EventLike, recent_events: list[EventLike]) -> list[float]:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        same_ip = sum(1 for item in recent_events if item.ip_address == event.ip_address)
        return [
            float(timestamp.hour),
            float(event.outcome != "success"),
            float(event.role == "admin"),
            float(event.event_type in {"authorization_failure", "role_change"}),
            float(min(same_ip, 20)),
        ]

    def score(self, event: EventLike, recent_events: list[EventLike]) -> float:
        features = np.array([self.features(event, recent_events)])
        raw = -float(self.model.decision_function(features)[0])
        return round(max(0.0, min(100.0, 50.0 + raw * 180.0)), 1)


class DetectionEngine:
    def __init__(self) -> None:
        self.behavior_model = BehaviorModel()

    def analyze(self, event: EventLike, recent_events: list[EventLike]) -> DetectionResult:
        evidence: list[str] = []
        rule_risk = 0.0
        title = "Behavioral anomaly detected"
        mitre = "T1078 — Valid Accounts"

        failed_logins = sum(
            1
            for item in recent_events
            if item.ip_address == event.ip_address
            and item.event_type == "login"
            and item.outcome == "failure"
        )
        if event.event_type == "login" and event.outcome == "failure" and failed_logins >= 4:
            rule_risk += 75
            title = "Possible brute-force authentication attack"
            mitre = "T1110 — Brute Force"
            evidence.append(f"{failed_logins + 1} failed logins were observed from {event.ip_address}")

        event_hour = event.timestamp.hour
        if event.event_type == "login" and event.outcome == "success" and (event_hour < 6 or event_hour > 23):
            rule_risk += 35
            title = "Unusual-hour successful login"
            evidence.append(f"A successful login occurred at {event_hour:02d}:00 UTC")

        denied_requests = sum(
            1
            for item in recent_events
            if item.user_id == event.user_id and item.event_type == "authorization_failure"
        )
        if event.event_type == "authorization_failure" and denied_requests >= 2:
            rule_risk += 55
            title = "Repeated unauthorized resource access"
            mitre = "T1069 — Permission Groups Discovery"
            evidence.append(f"{denied_requests + 1} denied requests were made by {event.user_id}")

        if event.event_type == "role_change" and event.outcome == "denied":
            rule_risk += 85
            title = "Privilege-escalation attempt"
            mitre = "T1098 — Account Manipulation"
            evidence.append("A denied role change targeted administrative privileges")

        anomaly = self.behavior_model.score(event, recent_events)
        if anomaly >= 65:
            evidence.append(f"Behavioral model returned an anomaly score of {anomaly:.0f}/100")

        combined = min(100.0, rule_risk + max(0.0, anomaly - 50.0) * 0.45)
        severity = "critical" if combined >= 85 else "high" if combined >= 70 else "medium" if combined >= 50 else "low"
        return DetectionResult(round(combined, 1), anomaly, severity, title, mitre, evidence)
