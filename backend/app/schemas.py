import json
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class TokenRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=4096)


class EventCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=120)
    event_type: Literal["login", "api_access", "authorization_failure", "role_change"]
    outcome: Literal["success", "failure", "denied"]
    ip_address: IPvAnyAddress
    country: str = Field(default="TR", min_length=2, max_length=2)
    endpoint: str = Field(default="/", min_length=1, max_length=255)
    role: str = Field(default="user", min_length=1, max_length=40)
    source: str = Field(default="api", min_length=1, max_length=80)
    timestamp: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("details")
    @classmethod
    def limit_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, default=str)) > 16_384:
            raise ValueError("details must be smaller than 16 KB")
        return value

    @field_validator("ip_address", mode="after")
    @classmethod
    def stringify_ip(cls, value: IPv4Address | IPv6Address) -> str:
        return str(value)


class EventRead(EventCreate):
    id: int
    timestamp: datetime
    risk_score: float
    anomaly_score: float
    model_version: str
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


class BatchIngestRequest(BaseModel):
    events: list[EventCreate] = Field(min_length=1, max_length=100)


class BatchIngestResponse(BaseModel):
    accepted: int
    alerts_created: int
    event_ids: list[int]


class AuditLogRead(BaseModel):
    id: int
    created_at: datetime
    actor: str
    action: str
    target_type: str
    target_id: str
    details: dict[str, Any]
    model_config = ConfigDict(from_attributes=True)


class DetectionHealth(BaseModel):
    model_version: str
    alert_threshold: int
    minimum_personal_baseline: int
    rules: list[str]
    integrations: list[str]
