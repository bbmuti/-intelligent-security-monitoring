"""Apply configurable retention to events, audits, and expired refresh sessions."""

import argparse
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Alert, AuditLog, RefreshSession, SecurityEvent


def prune(
    db: Session,
    *,
    now: datetime,
    event_retention_days: int,
    audit_retention_days: int,
    dry_run: bool,
) -> dict[str, int]:
    event_cutoff = now - timedelta(days=event_retention_days)
    audit_cutoff = now - timedelta(days=audit_retention_days)
    counts = {
        "events": db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp < event_cutoff)) or 0,
        "alerts": db.scalar(
            select(func.count(Alert.id))
            .join(SecurityEvent, Alert.event_id == SecurityEvent.id)
            .where(SecurityEvent.timestamp < event_cutoff)
        ) or 0,
        "audit_logs": db.scalar(select(func.count(AuditLog.id)).where(AuditLog.created_at < audit_cutoff)) or 0,
        "refresh_sessions": db.scalar(
            select(func.count(RefreshSession.id)).where(RefreshSession.expires_at < now)
        ) or 0,
    }
    if dry_run:
        db.rollback()
        return counts
    expired_event_ids = select(SecurityEvent.id).where(SecurityEvent.timestamp < event_cutoff)
    db.execute(delete(Alert).where(Alert.event_id.in_(expired_event_ids)))
    db.execute(delete(SecurityEvent).where(SecurityEvent.timestamp < event_cutoff))
    db.execute(delete(AuditLog).where(AuditLog.created_at < audit_cutoff))
    db.execute(delete(RefreshSession).where(RefreshSession.expires_at < now))
    db.commit()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Prune SentinelScope data outside the retention window")
    parser.add_argument("--event-days", type=int, default=90)
    parser.add_argument("--audit-days", type=int, default=365)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.event_days < 1 or args.audit_days < 1:
        raise SystemExit("Retention windows must be at least one day")
    with SessionLocal() as db:
        counts = prune(
            db,
            now=datetime.now(UTC),
            event_retention_days=args.event_days,
            audit_retention_days=args.audit_days,
            dry_run=args.dry_run,
        )
    action = "would remove" if args.dry_run else "removed"
    print(f"{action}: " + ", ".join(f"{name}={count}" for name, count in counts.items()))


if __name__ == "__main__":
    main()
