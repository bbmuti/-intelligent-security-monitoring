from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    user_id: Mapped[str] = mapped_column(String(120), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    outcome: Mapped[str] = mapped_column(String(30), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    country: Mapped[str] = mapped_column(String(2), default="TR")
    endpoint: Mapped[str] = mapped_column(String(255), default="/")
    role: Mapped[str] = mapped_column(String(40), default="user")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    title: Mapped[str] = mapped_column(String(180))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    mitre_technique: Mapped[str] = mapped_column(String(120), default="")
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
