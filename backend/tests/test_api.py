import os
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite:///./test_security_monitor.db"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password-123"
os.environ["INGESTION_API_KEY"] = "test-ingestion-key"
os.environ["JWT_SECRET"] = "test-jwt-secret-with-sufficient-length"

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.auth import PASSWORD_ITERATIONS, create_access_token, decode_token, password_digest
from app.config import Settings
from app.database import Base, SessionLocal, engine
from app.integrations.linux_auth import parse_linux_auth_line
from app.main import app
from app.models import AnalystUser, AuditLog, RefreshSession


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "test-password-123"},
    )
    assert response.status_code == 200
    return response.json()


def auth_headers(tokens: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("sentinelscope_csrf")}


def test_health_and_readiness(client: TestClient):
    assert client.get("/health").status_code == 200
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_sqlite_foreign_key_enforcement_is_enabled(client: TestClient):
    with engine.connect() as connection:
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1


def test_login_returns_rotatable_token_pair(client: TestClient):
    tokens = login(client)
    assert tokens["access_token"]
    assert tokens["expires_in"] == 1200
    original_refresh = client.cookies.get("sentinelscope_refresh")
    assert original_refresh
    assert "sentinelscope_refresh" not in tokens

    rotated = client.post(
        "/api/v1/auth/refresh",
        headers=csrf_headers(client),
    )
    assert rotated.status_code == 200
    rotated_refresh = client.cookies.get("sentinelscope_refresh")
    assert rotated_refresh != original_refresh
    client.cookies.set("sentinelscope_refresh", original_refresh, path="/api/v1/auth")
    reused = client.post(
        "/api/v1/auth/refresh",
        headers=csrf_headers(client),
    )
    assert reused.status_code == 401
    client.cookies.set("sentinelscope_refresh", rotated_refresh, path="/api/v1/auth")
    assert client.post(
        "/api/v1/auth/refresh",
        headers=csrf_headers(client),
    ).status_code == 401


def test_refresh_reuse_is_audited_and_revokes_the_token_family(client: TestClient):
    tokens = login(client)
    original_refresh = client.cookies.get("sentinelscope_refresh")
    assert client.post(
        "/api/v1/auth/refresh",
        headers=csrf_headers(client),
    ).status_code == 200
    rotated_refresh = client.cookies.get("sentinelscope_refresh")
    client.cookies.set("sentinelscope_refresh", original_refresh, path="/api/v1/auth")
    assert client.post(
        "/api/v1/auth/refresh",
        headers=csrf_headers(client),
    ).status_code == 401
    audits = client.get("/api/v1/audit-logs", headers=auth_headers(tokens)).json()
    assert any(item["action"] == "refresh_token_reuse_detected" for item in audits)
    client.cookies.set("sentinelscope_refresh", rotated_refresh, path="/api/v1/auth")
    assert client.post(
        "/api/v1/auth/refresh",
        headers=csrf_headers(client),
    ).status_code == 401


def test_logout_revokes_refresh_session(client: TestClient):
    login(client)
    assert client.post(
        "/api/v1/auth/logout",
        headers=csrf_headers(client),
    ).status_code == 204
    assert client.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": "missing-cookie"},
    ).status_code == 403


def test_refresh_and_logout_require_double_submit_csrf_token(client: TestClient):
    login(client)
    assert client.post("/api/v1/auth/refresh").status_code == 403
    assert client.post("/api/v1/auth/logout").status_code == 403


def test_refresh_for_inactive_user_revokes_the_session_family(client: TestClient):
    login(client)
    with SessionLocal() as db:
        user = db.query(AnalystUser).filter_by(username="admin").one()
        user.is_active = False
        db.commit()

    response = client.post("/api/v1/auth/refresh", headers=csrf_headers(client))
    assert response.status_code == 401
    with SessionLocal() as db:
        sessions = db.query(RefreshSession).all()
        assert sessions and all(session.revoked_at is not None for session in sessions)
        assert db.query(AuditLog).filter_by(action="inactive_user_refresh_rejected").count() == 1


def test_successful_login_upgrades_legacy_password_hash_cost(client: TestClient):
    salt = "legacy-salt"
    with SessionLocal() as db:
        db.add(
            AnalystUser(
                username="legacy-user",
                password_hash=password_digest("legacy-password", salt, 210_000),
                password_salt=salt,
                password_iterations=210_000,
                role="analyst",
            )
        )
        db.commit()
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "legacy-user", "password": "legacy-password"},
    )
    assert response.status_code == 200
    with SessionLocal() as db:
        upgraded = db.query(AnalystUser).filter_by(username="legacy-user").one()
        assert upgraded.password_iterations == PASSWORD_ITERATIONS
        assert upgraded.password_hash == password_digest(
            "legacy-password", upgraded.password_salt, PASSWORD_ITERATIONS
        )


def test_protected_endpoint_rejects_anonymous_request(client: TestClient):
    assert client.get("/api/v1/alerts").status_code == 401


def test_token_decoder_rejects_invalid_and_wrong_type_tokens(client: TestClient):
    with pytest.raises(HTTPException) as invalid:
        decode_token("not-a-jwt", "access")
    assert invalid.value.status_code == 401
    access = create_access_token("admin", "admin")
    with pytest.raises(HTTPException) as wrong_type:
        decode_token(access, "refresh")
    assert wrong_type.value.status_code == 401


def test_non_analyst_role_is_forbidden(client: TestClient):
    password = "viewer-password"
    salt = "viewer-salt"
    with SessionLocal() as db:
        db.add(
            AnalystUser(
                username="viewer",
                password_hash=password_digest(password, salt),
                password_salt=salt,
                role="viewer",
            )
        )
        db.commit()
    tokens = client.post(
        "/api/v1/auth/login", json={"username": "viewer", "password": password}
    ).json()
    assert client.get("/api/v1/alerts", headers=auth_headers(tokens)).status_code == 403


def test_batch_ingestion_requires_service_key(client: TestClient):
    payload = {
        "events": [
            {
                "user_id": "collector-user",
                "event_type": "api_access",
                "outcome": "success",
                "ip_address": "10.0.0.8",
                "source": "integration-test",
            }
        ]
    }
    assert client.post("/api/v1/ingest/events", json=payload).status_code == 422
    assert client.post(
        "/api/v1/ingest/events",
        json=payload,
        headers={"X-Ingestion-Key": "wrong"},
    ).status_code == 403
    response = client.post(
        "/api/v1/ingest/events",
        json=payload,
        headers={"X-Ingestion-Key": "test-ingestion-key"},
    )
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert response.json()["duplicates"] == 0


def test_collector_event_idempotency_prevents_duplicate_events_and_alerts(client: TestClient):
    event = {
        "user_id": "deduplicated-user",
        "event_type": "login",
        "outcome": "failure",
        "ip_address": "203.0.113.80",
        "source": "collector-test",
        "source_event_id": "host-a-record-42",
    }
    headers = {"X-Ingestion-Key": "test-ingestion-key"}
    first = client.post("/api/v1/ingest/events", json={"events": [event]}, headers=headers)
    second = client.post("/api/v1/ingest/events", json={"events": [event]}, headers=headers)
    assert first.json()["accepted"] == 1
    assert second.json()["accepted"] == 0
    assert second.json()["duplicates"] == 1
    assert second.json()["event_ids"] == first.json()["event_ids"]

    tokens = login(client)
    stored = client.get(
        "/api/v1/events?user_id=deduplicated-user",
        headers=auth_headers(tokens),
    ).json()
    assert len(stored) == 1


def test_real_linux_auth_record_reaches_event_stream(client: TestClient):
    event = parse_linux_auth_line(
        "Aug 20 09:15:11 web-01 sshd[1208]: Failed password for invalid user admin from 203.0.113.42 port 49821 ssh2",
        now=datetime(2026, 8, 20, 12, tzinfo=UTC),
    )
    response = client.post(
        "/api/v1/ingest/events",
        json={"events": [event]},
        headers={"X-Ingestion-Key": "test-ingestion-key"},
    )
    assert response.status_code == 200
    tokens = login(client)
    stored = client.get("/api/v1/events?user_id=admin", headers=auth_headers(tokens)).json()
    assert stored[0]["source"] == "linux-auth-log"
    assert stored[0]["details"]["host"] == "web-01"


def test_unusual_login_simulation_creates_explainable_alert(client: TestClient):
    tokens = login(client)
    response = client.post(
        "/api/v1/simulations/unusual_login",
        headers=auth_headers(tokens),
    )
    assert response.status_code == 200
    assert response.json()["alerts_created"] >= 1

    alerts = client.get("/api/v1/alerts", headers=auth_headers(tokens)).json()
    assert alerts[0]["mitre_technique"] == "T1078 — Valid Accounts"
    assert "02:00" in alerts[0]["explanation"]


@pytest.mark.parametrize(
    ("scenario", "minimum_alerts"),
    [("normal", 0), ("brute_force", 1), ("rapid_country_change", 1)],
)
def test_documented_scenarios_execute_through_detection_pipeline(client: TestClient, scenario, minimum_alerts):
    tokens = login(client)
    response = client.post(
        f"/api/v1/simulations/{scenario}",
        headers=auth_headers(tokens),
    )
    assert response.status_code == 200
    assert response.json()["alerts_created"] >= minimum_alerts


def test_unknown_resources_return_not_found(client: TestClient):
    tokens = login(client)
    headers = auth_headers(tokens)
    assert client.post("/api/v1/simulations/not-a-scenario", headers=headers).status_code == 404
    assert client.get("/api/v1/alerts/99999", headers=headers).status_code == 404


def test_alert_lifecycle_updates_summary_and_audit_log(client: TestClient):
    tokens = login(client)
    headers = auth_headers(tokens)
    client.post("/api/v1/simulations/privilege_escalation", headers=headers)
    alert = client.get("/api/v1/alerts", headers=headers).json()[0]
    assert client.get("/api/v1/dashboard/summary", headers=headers).json()["open_alerts"] == 1

    update = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        headers=headers,
        json={"status": "false_positive"},
    )
    assert update.status_code == 200
    assert client.get("/api/v1/dashboard/summary", headers=headers).json()["open_alerts"] == 0
    audits = client.get("/api/v1/audit-logs", headers=headers).json()
    assert any(item["action"] == "alert_status_changed" for item in audits)
    change_count = sum(item["action"] == "alert_status_changed" for item in audits)
    assert client.patch(
        f"/api/v1/alerts/{alert['id']}",
        headers=headers,
        json={"status": "false_positive"},
    ).status_code == 200
    audits_after_noop = client.get("/api/v1/audit-logs", headers=headers).json()
    assert sum(item["action"] == "alert_status_changed" for item in audits_after_noop) == change_count


def test_event_list_supports_validated_offset_pagination(client: TestClient):
    tokens = login(client)
    headers = auth_headers(tokens)
    for index in range(3):
        response = client.post(
            "/api/v1/events",
            headers=headers,
            json={
                "user_id": f"page-user-{index}",
                "event_type": "api_access",
                "outcome": "success",
                "ip_address": f"192.0.2.{index + 1}",
            },
        )
        assert response.status_code == 200
    first = client.get("/api/v1/events?limit=1&offset=0", headers=headers).json()
    second = client.get("/api/v1/events?limit=1&offset=1", headers=headers).json()
    assert len(first) == len(second) == 1
    assert first[0]["id"] != second[0]["id"]
    assert client.get("/api/v1/events?offset=-1", headers=headers).status_code == 422


def test_login_rate_limit_blocks_repeated_password_guessing(client: TestClient):
    payload = {"username": "locked-user", "password": "incorrect"}
    for _attempt in range(5):
        assert client.post("/api/v1/auth/login", json=payload).status_code == 401
    assert client.post("/api/v1/auth/login", json=payload).status_code == 429


def test_future_events_do_not_leak_into_detection_window(client: TestClient):
    future = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    events = [
        {
            "timestamp": (future + timedelta(seconds=index)).isoformat(),
            "user_id": "window-user",
            "event_type": "login",
            "outcome": "failure",
            "ip_address": "203.0.113.25",
            "source": "window-regression-test",
        }
        for index in range(4)
    ]
    events.append(
        {
            "timestamp": (future - timedelta(hours=1)).isoformat(),
            "user_id": "window-user",
            "event_type": "login",
            "outcome": "failure",
            "ip_address": "203.0.113.25",
            "source": "target-earlier-event",
        }
    )
    response = client.post(
        "/api/v1/ingest/events",
        json={"events": events},
        headers={"X-Ingestion-Key": "test-ingestion-key"},
    )
    assert response.status_code == 200

    tokens = login(client)
    stored_events = client.get(
        "/api/v1/events?user_id=window-user",
        headers=auth_headers(tokens),
    ).json()
    earlier = min(stored_events, key=lambda item: item["timestamp"])
    assert earlier["source"] == "target-earlier-event"
    assert earlier["risk_score"] < 50


def test_correlation_is_not_truncated_by_unrelated_high_volume_events(client: TestClient):
    headers = {"X-Ingestion-Key": "test-ingestion-key"}
    base = datetime.now(UTC) - timedelta(minutes=2)
    failures = [
        {
            "timestamp": (base + timedelta(seconds=index)).isoformat(),
            "user_id": "volume-target",
            "event_type": "login",
            "outcome": "failure",
            "ip_address": "203.0.113.90",
            "source": "volume-test",
            "source_event_id": f"target-{index}",
        }
        for index in range(5)
    ]
    assert client.post(
        "/api/v1/ingest/events", json={"events": failures[:4]}, headers=headers
    ).status_code == 200

    noise = [
        {
            "timestamp": (base + timedelta(seconds=10 + index)).isoformat(),
            "user_id": f"noise-{index}",
            "event_type": "api_access",
            "outcome": "success",
            "ip_address": f"198.51.100.{index % 250 + 1}",
            "source": "volume-test",
            "source_event_id": f"noise-{index}",
        }
        for index in range(250)
    ]
    for offset in range(0, len(noise), 100):
        assert client.post(
            "/api/v1/ingest/events",
            json={"events": noise[offset : offset + 100]},
            headers=headers,
        ).status_code == 200

    final = client.post(
        "/api/v1/ingest/events", json={"events": [failures[4]]}, headers=headers
    )
    assert final.status_code == 200
    assert final.json()["alerts_created"] == 1


def test_rejects_events_too_far_in_the_future(client: TestClient):
    response = client.post(
        "/api/v1/ingest/events",
        json={
            "events": [
                {
                    "timestamp": (datetime.now(UTC) + timedelta(minutes=6)).isoformat(),
                    "user_id": "future-user",
                    "event_type": "login",
                    "outcome": "success",
                    "ip_address": "203.0.113.91",
                }
            ]
        },
        headers={"X-Ingestion-Key": "test-ingestion-key"},
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/events?event_type=not-real",
        "/api/v1/events?outcome=not-real",
        "/api/v1/alerts?status=not-real",
        "/api/v1/alerts?severity=not-real",
    ],
)
def test_invalid_filters_return_validation_error(client: TestClient, path: str):
    assert client.get(path, headers=auth_headers(login(client))).status_code == 422


def test_production_rejects_placeholder_secrets():
    production = Settings(
        environment="production",
        jwt_secret="local-development-secret-change-me",
        admin_password="change-me-before-production",
        ingestion_api_key="local-ingestion-key-change-me",
    )
    with pytest.raises(RuntimeError, match="Production security secrets"):
        production.validate_security()


@pytest.mark.parametrize(
    "overrides",
    [
        {"jwt_secret": "replace-with-a-long-random-value"},
        {"ingestion_api_key": "replace-with-a-separate-random-value"},
        {"jwt_secret": "please-change-me-to-a-random-secret-value"},
    ],
)
def test_production_rejects_documented_example_secrets(overrides):
    values = {
        "environment": "production",
        "jwt_secret": "j" * 40,
        "admin_password": "a-strong-admin-password",
        "ingestion_api_key": "i" * 32,
        "cors_origins": "https://security.example.com",
    }
    values.update(overrides)
    with pytest.raises(RuntimeError, match="Production security secrets"):
        Settings(**values).validate_security()


def test_production_accepts_independent_strong_secrets():
    production = Settings(
        environment="production",
        jwt_secret="j" * 40,
        admin_password="a-strong-admin-password",
        ingestion_api_key="i" * 32,
        cors_origins="https://security.example.com",
    )
    production.validate_security()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"jwt_secret": "short"}, "minimum length"),
        ({"ingestion_api_key": "j" * 40}, "independent values"),
        ({"cors_origins": "*"}, "Wildcard CORS"),
    ],
)
def test_production_rejects_weak_security_configuration(overrides, message):
    values = {
        "environment": "production",
        "jwt_secret": "j" * 40,
        "admin_password": "a-strong-admin-password",
        "ingestion_api_key": "i" * 32,
        "cors_origins": "https://security.example.com",
    }
    values.update(overrides)
    with pytest.raises(RuntimeError, match=message):
        Settings(**values).validate_security()
