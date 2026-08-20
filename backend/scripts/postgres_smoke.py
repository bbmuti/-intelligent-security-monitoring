"""Exercise the migrated PostgreSQL-backed API in CI."""

from fastapi.testclient import TestClient

from app.main import app


def main() -> None:
    with TestClient(app) as client:
        if client.get("/ready").status_code != 200:
            raise RuntimeError("PostgreSQL readiness check failed")
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "ci-admin-password"},
        )
        login.raise_for_status()
        access_token = login.json()["access_token"]
        created = client.post(
            "/api/v1/events",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "user_id": "postgres-smoke",
                "event_type": "api_access",
                "outcome": "success",
                "ip_address": "192.0.2.10",
                "source": "ci-postgres-smoke",
                "source_event_id": "ci-postgres-smoke-1",
            },
        )
        created.raise_for_status()
        if created.json()["source_event_id"] != "ci-postgres-smoke-1":
            raise RuntimeError("PostgreSQL event round trip returned unexpected data")


if __name__ == "__main__":
    main()
