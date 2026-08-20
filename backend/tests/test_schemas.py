import unittest
from datetime import UTC, datetime

from pydantic import ValidationError

from app.schemas import BatchIngestRequest, EventCreate


class EventSchemaTests(unittest.TestCase):
    def test_rejects_invalid_ip(self):
        with self.assertRaises(ValidationError):
            EventCreate(
                user_id="test",
                event_type="login",
                outcome="success",
                ip_address="not-an-ip",
            )

    def test_normalizes_naive_timestamp_to_utc(self):
        payload = EventCreate(
            user_id="test",
            event_type="login",
            outcome="success",
            ip_address="10.0.0.2",
            timestamp=datetime(2026, 1, 1, 10, 0),
        )
        self.assertEqual(payload.timestamp.tzinfo, UTC)

    def test_rejects_oversized_details(self):
        with self.assertRaises(ValidationError):
            EventCreate(
                user_id="test",
                event_type="api_access",
                outcome="success",
                ip_address="10.0.0.2",
                details={"payload": "x" * 17_000},
            )

    def test_batch_limit(self):
        event = EventCreate(
            user_id="test",
            event_type="api_access",
            outcome="success",
            ip_address="10.0.0.2",
        )
        with self.assertRaises(ValidationError):
            BatchIngestRequest(events=[event] * 101)


if __name__ == "__main__":
    unittest.main()
