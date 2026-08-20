from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Alert, AuditLog, RefreshSession, SecurityEvent
from scripts.prune_data import prune


def build_old_records(db: Session, now: datetime) -> None:
    event = SecurityEvent(
        timestamp=now - timedelta(days=100),
        user_id="retention-user",
        event_type="login",
        outcome="failure",
        ip_address="192.0.2.20",
        country="ZZ",
        endpoint="/login",
        role="user",
        source="retention-test",
    )
    db.add(event)
    db.flush()
    db.add(
        Alert(
            event_id=event.id,
            title="Old alert",
            severity="medium",
            risk_score=50,
            mitre_technique="T1078",
            explanation="Old test alert",
            evidence=[],
        )
    )
    db.add(
        AuditLog(
            created_at=now - timedelta(days=400),
            actor="retention-test",
            action="old_action",
            target_type="test",
            target_id="1",
        )
    )
    db.add(
        RefreshSession(
            jti="expired-session",
            family_id="expired-family",
            user_id=1,
            expires_at=now - timedelta(days=1),
        )
    )


def test_retention_dry_run_counts_without_deleting_and_live_run_prunes():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 20, tzinfo=UTC)
    with Session(engine) as db:
        from app.models import AnalystUser

        db.add(
            AnalystUser(
                id=1,
                username="retention-admin",
                password_hash="hash",
                password_salt="salt",
                role="admin",
            )
        )
        build_old_records(db, now)
        db.commit()
        preview = prune(
            db,
            now=now,
            event_retention_days=90,
            audit_retention_days=365,
            dry_run=True,
        )
        assert preview == {"events": 1, "alerts": 1, "audit_logs": 1, "refresh_sessions": 1}
        assert db.scalar(select(func.count(SecurityEvent.id))) == 1
        removed = prune(
            db,
            now=now,
            event_retention_days=90,
            audit_retention_days=365,
            dry_run=False,
        )
        assert removed == preview
        assert db.scalar(select(func.count(SecurityEvent.id))) == 0
        assert db.scalar(select(func.count(Alert.id))) == 0
        assert db.scalar(select(func.count(AuditLog.id))) == 0
        assert db.scalar(select(func.count(RefreshSession.id))) == 0
