import os
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite:///./test_security_monitor.db"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password-123"
os.environ["INGESTION_API_KEY"] = "test-ingestion-key"
os.environ["JWT_SECRET"] = "test-jwt-secret-with-sufficient-length"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.database import Base, engine
from app.main import app


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
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
    assert tokens["refresh_token"]
    assert tokens["expires_in"] == 1200

    rotated = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert rotated.status_code == 200
    reused = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert reused.status_code == 401


def test_logout_revokes_refresh_session(client: TestClient):
    tokens = login(client)
    assert client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    ).status_code == 204
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    ).status_code == 401


def test_protected_endpoint_rejects_anonymous_request(client: TestClient):
    assert client.get("/api/v1/alerts").status_code == 403


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


def test_production_rejects_placeholder_secrets():
    production = Settings(
        environment="production",
        jwt_secret="local-development-secret-change-me",
        admin_password="change-me-before-production",
        ingestion_api_key="local-ingestion-key-change-me",
    )
    with pytest.raises(RuntimeError, match="Production security secrets"):
        production.validate_security()


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
