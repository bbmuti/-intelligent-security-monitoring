import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.detection import DetectionEngine


def event(**overrides):
    defaults = {
        "timestamp": datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        "event_type": "login",
        "outcome": "success",
        "role": "user",
        "ip_address": "10.0.0.8",
        "user_id": "beren",
        "country": "TR",
        "endpoint": "/auth/login",
        "details": {},
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class DetectionEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()

    def test_normal_event_does_not_create_high_risk(self):
        result = self.engine.analyze(event(event_type="api_access", endpoint="/api/profile"), [])
        self.assertLess(result.risk_score, 50)

    def test_fifth_failed_login_triggers_brute_force(self):
        now = datetime(2026, 8, 20, 13, 0, tzinfo=UTC)
        history = [
            event(timestamp=now - timedelta(seconds=i), outcome="failure", ip_address="203.0.113.42")
            for i in range(4)
        ]
        result = self.engine.analyze(event(timestamp=now, outcome="failure", ip_address="203.0.113.42"), history)
        self.assertGreaterEqual(result.risk_score, 70)
        self.assertIn("T1110", result.mitre_technique)

    def test_denied_role_change_is_critical(self):
        result = self.engine.analyze(
            event(event_type="role_change", outcome="denied", endpoint="/admin/roles"), []
        )
        self.assertEqual(result.severity, "critical")
        self.assertIn("Privilege", result.title)

    def test_unusual_hour_has_explanation(self):
        result = self.engine.analyze(event(timestamp=datetime(2026, 8, 20, 2, 0, tzinfo=UTC)), [])
        self.assertGreaterEqual(result.risk_score, 50)
        self.assertTrue(any("02:00" in item for item in result.evidence))

    def test_rapid_country_change_is_high_risk(self):
        history = [event(country="TR")]
        result = self.engine.analyze(event(country="DE"), history)
        self.assertGreaterEqual(result.risk_score, 70)
        self.assertIn("rapid_country_change", result.triggered_rules)

    def test_strong_behavioral_anomaly_can_create_alert(self):
        history = [event(event_type="api_access") for _ in range(7)]
        result = self.engine.analyze(
            event(
                timestamp=datetime(2026, 8, 20, 2, 0, tzinfo=UTC),
                event_type="api_access",
                outcome="failure",
            ),
            history,
        )
        self.assertGreaterEqual(result.risk_score, 50)
        self.assertIn("behavioral_anomaly", result.triggered_rules)


if __name__ == "__main__":
    unittest.main()
