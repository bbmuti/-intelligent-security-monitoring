from dataclasses import dataclass, field
from datetime import UTC, datetime
from math import cos, pi, sin
from typing import Protocol

import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_VERSION = "iforest-v2"
ALERT_THRESHOLD = 50
MINIMUM_PERSONAL_BASELINE = 30


class EventLike(Protocol):
    timestamp: datetime
    event_type: str
    outcome: str
    role: str
    ip_address: str
    user_id: str
    country: str
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
    triggered_rules: list[str] = field(default_factory=list)
    model_version: str = MODEL_VERSION

    @property
    def explanation(self) -> str:
        if not self.evidence:
            return "Activity is consistent with the current behavioral baseline."
        return "Risk increased because " + "; ".join(item.lower() for item in self.evidence) + "."


class BehaviorModel:
    """Isolation Forest with a deterministic fallback and interpretable feature signals."""

    def __init__(self, baseline_events: list[EventLike] | None = None) -> None:
        self.model = IsolationForest(n_estimators=160, contamination=0.06, random_state=42)
        if baseline_events and len(baseline_events) >= MINIMUM_PERSONAL_BASELINE:
            baseline = np.array([self.features(item, []) for item in baseline_events])
            self.baseline_kind = "personal"
        else:
            baseline = self._fallback_baseline()
            self.baseline_kind = "global-fallback"
        self.model.fit(baseline)

    @staticmethod
    def _fallback_baseline() -> np.ndarray:
        rng = np.random.default_rng(42)
        hours = np.clip(rng.normal(13, 3.1, 800), 6, 22)
        return np.column_stack(
            [
                np.sin(2 * pi * hours / 24),
                np.cos(2 * pi * hours / 24),
                rng.choice([0, 1], 800, p=[0.985, 0.015]),
                rng.choice([0, 1], 800, p=[0.94, 0.06]),
                np.zeros(800),
                np.clip(rng.poisson(1.5, 800), 0, 7),
            ]
        )

    @staticmethod
    def features(event: EventLike, recent_events: list[EventLike]) -> list[float]:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        same_ip = sum(1 for item in recent_events if item.ip_address == event.ip_address)
        angle = 2 * pi * timestamp.hour / 24
        return [
            sin(angle),
            cos(angle),
            float(event.outcome != "success"),
            float(event.role == "admin"),
            float(event.event_type in {"authorization_failure", "role_change"}),
            float(min(same_ip, 20)),
        ]

    def score(self, event: EventLike, recent_events: list[EventLike]) -> float:
        features = np.array([self.features(event, recent_events)])
        decision = float(self.model.decision_function(features)[0])
        score = 100.0 / (1.0 + np.exp(decision * 18.0))
        return round(max(0.0, min(100.0, score)), 1)

    @staticmethod
    def explain(event: EventLike, recent_events: list[EventLike]) -> list[str]:
        reasons: list[str] = []
        if event.timestamp.hour < 6 or event.timestamp.hour >= 23:
            reasons.append("activity occurred outside the expected 06:00–23:00 UTC window")
        if event.outcome != "success":
            reasons.append("the event outcome was unsuccessful or denied")
        if event.event_type in {"authorization_failure", "role_change"}:
            reasons.append("the event involved a sensitive authorization action")
        same_ip = sum(1 for item in recent_events if item.ip_address == event.ip_address)
        if same_ip >= 5:
            reasons.append(f"{same_ip + 1} events originated from the same IP in ten minutes")
        return reasons


class DetectionEngine:
    RULES = [
        "brute_force",
        "unusual_login_time",
        "repeated_authorization_failure",
        "privilege_escalation",
        "rapid_country_change",
        "behavioral_anomaly",
    ]

    def __init__(self) -> None:
        self.fallback_model = BehaviorModel()

    def analyze(
        self,
        event: EventLike,
        recent_events: list[EventLike],
        baseline_events: list[EventLike] | None = None,
    ) -> DetectionResult:
        evidence: list[str] = []
        rules: list[str] = []
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
            rule_risk = max(rule_risk, 75)
            title = "Possible brute-force authentication attack"
            mitre = "T1110 — Brute Force"
            rules.append("brute_force")
            evidence.append(f"{failed_logins + 1} failed logins were observed from {event.ip_address}")

        event_hour = event.timestamp.hour
        if event.event_type == "login" and event.outcome == "success" and (event_hour < 6 or event_hour >= 23):
            rule_risk = max(rule_risk, 45)
            title = "Unusual-hour successful login"
            rules.append("unusual_login_time")
            evidence.append(f"A successful login occurred at {event_hour:02d}:00 UTC")

        denied_requests = sum(
            1
            for item in recent_events
            if item.user_id == event.user_id and item.event_type == "authorization_failure"
        )
        if event.event_type == "authorization_failure" and denied_requests >= 2:
            rule_risk = max(rule_risk, 60)
            title = "Repeated unauthorized resource access"
            discovery_target = "user" in event.endpoint.lower() or "account" in event.endpoint.lower()
            mitre = "T1087 — Account Discovery" if discovery_target else "T1078 — Valid Accounts"
            rules.append("repeated_authorization_failure")
            evidence.append(f"{denied_requests + 1} denied requests were made by {event.user_id}")

        if event.event_type == "role_change" and event.outcome == "denied":
            rule_risk = max(rule_risk, 85)
            title = "Privilege-escalation attempt"
            mitre = "T1098 — Account Manipulation"
            rules.append("privilege_escalation")
            evidence.append("A denied role change targeted administrative privileges")

        successful_logins = [
            item for item in recent_events
            if item.user_id == event.user_id and item.event_type == "login" and item.outcome == "success"
        ]
        if (
            event.event_type == "login"
            and event.outcome == "success"
            and successful_logins
            and successful_logins[0].country != event.country
        ):
            rule_risk = max(rule_risk, 72)
            title = "Rapid country change detected"
            mitre = "T1078 — Valid Accounts"
            rules.append("rapid_country_change")
            evidence.append(
                f"The account moved from {successful_logins[0].country} to {event.country} inside the analysis window"
            )

        model = (
            BehaviorModel(baseline_events)
            if baseline_events and len(baseline_events) >= MINIMUM_PERSONAL_BASELINE
            else self.fallback_model
        )
        anomaly = model.score(event, recent_events)
        anomaly_risk = 0.0 if anomaly < 55 else min(80.0, (anomaly - 50.0) * 1.6)
        if anomaly >= 65:
            anomaly_risk = max(50.0, anomaly_risk)
            if event.event_type == "login" and event.outcome == "failure" and failed_logins < 2:
                anomaly_risk *= 0.35
            rules.append("behavioral_anomaly")
            evidence.append(
                f"The {model.baseline_kind} behavioral model returned an anomaly score of {anomaly:.0f}/100"
            )
            evidence.extend(reason for reason in model.explain(event, recent_events) if reason not in evidence)

        combined = 100.0 - ((100.0 - rule_risk) * (100.0 - anomaly_risk) / 100.0)
        if not rules and combined < ALERT_THRESHOLD:
            title = "Normal activity"
            mitre = ""
        severity = (
            "critical" if combined >= 85 else
            "high" if combined >= 70 else
            "medium" if combined >= ALERT_THRESHOLD else
            "low"
        )
        return DetectionResult(
            round(combined, 1), anomaly, severity, title, mitre, evidence, rules
        )
