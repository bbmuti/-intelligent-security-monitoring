from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EventCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=120)
    event_type: Literal["login", "api_access", "authorization_failure", "role_change"]
    outcome: Literal["success", "failure", "denied"]
    ip_address: str
    country: str = Field(default="TR", min_length=2, max_length=2)
    endpoint: str = "/"
    role: str = "user"
    timestamp: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class EventRead(EventCreate):
    id: int
    timestamp: datetime
    risk_score: float
    anomaly_score: float
    model_config = ConfigDict(from_attributes=True)


class AlertRead(BaseModel):
    id: int
    event_id: int
    created_at: datetime
    title: str
    severity: str
    risk_score: float
    mitre_technique: str
    explanation: str
    evidence: list[str]
    status: str
    model_config = ConfigDict(from_attributes=True)


class StatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]


class DashboardSummary(BaseModel):
    total_events: int
    open_alerts: int
    critical_alerts: int
    average_risk: float
    severity_counts: dict[str, int]
    event_type_counts: dict[str, int]
