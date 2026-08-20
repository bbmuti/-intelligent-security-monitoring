from datetime import UTC, datetime, timedelta

from .schemas import EventCreate


def build_scenario(name: str) -> list[EventCreate]:
    now = datetime.now(UTC)
    if name == "brute_force":
        return [
            EventCreate(
                user_id="beren",
                event_type="login",
                outcome="failure",
                ip_address="203.0.113.42",
                country="TR",
                endpoint="/auth/login",
                source="simulator",
                timestamp=now + timedelta(seconds=i),
                details={"scenario": name, "attempt": i + 1},
            )
            for i in range(6)
        ]
    if name == "privilege_escalation":
        return [
            EventCreate(
                user_id="user-104",
                event_type="role_change",
                outcome="denied",
                ip_address="198.51.100.18",
                country="TR",
                endpoint="/admin/users/user-104/role",
                role="user",
                source="simulator",
                timestamp=now,
                details={"scenario": name, "requested_role": "admin"},
            )
        ]
    if name == "unusual_login":
        unusual = now.replace(hour=2, minute=17, second=0, microsecond=0)
        return [
            EventCreate(
                user_id="finance-analyst",
                event_type="login",
                outcome="success",
                ip_address="192.0.2.77",
                country="DE",
                endpoint="/auth/login",
                source="simulator",
                timestamp=unusual,
                details={"scenario": name},
            )
        ]
    if name == "normal":
        return [
            EventCreate(
                user_id="user-204",
                event_type="api_access",
                outcome="success",
                ip_address="10.0.0.24",
                country="TR",
                endpoint="/api/profile",
                source="simulator",
                timestamp=now,
                details={"scenario": name},
            )
        ]
    if name == "rapid_country_change":
        return [
            EventCreate(
                user_id="traveling-admin",
                event_type="login",
                outcome="success",
                ip_address="192.0.2.14",
                country="TR",
                endpoint="/auth/login",
                source="simulator",
                timestamp=now,
                details={"scenario": name, "step": 1},
            ),
            EventCreate(
                user_id="traveling-admin",
                event_type="login",
                outcome="success",
                ip_address="198.51.100.91",
                country="DE",
                endpoint="/auth/login",
                source="simulator",
                timestamp=now + timedelta(minutes=2),
                details={"scenario": name, "step": 2},
            ),
        ]
    raise ValueError("Unknown scenario")
