import hmac
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    require_analyst,
    verify_password,
)
from .config import get_settings
from .database import Base, SessionLocal, engine, get_db
from .detection import ALERT_THRESHOLD, MINIMUM_PERSONAL_BASELINE, MODEL_VERSION, DetectionEngine
from .models import Alert, AnalystUser, AuditLog, RefreshSession, SecurityEvent
from .rate_limit import SlidingWindowRateLimiter
from .schemas import (
    AlertRead,
    AuditLogRead,
    BatchIngestRequest,
    BatchIngestResponse,
    DashboardSummary,
    DetectionHealth,
    EventCreate,
    EventRead,
    RefreshRequest,
    StatusUpdate,
    TokenRequest,
    TokenResponse,
)
from .simulation import build_scenario

settings = get_settings()
detection_engine = DetectionEngine()
login_limiter = SlidingWindowRateLimiter(limit=5, window_seconds=300)


def seed_admin() -> None:
    with SessionLocal() as db:
        existing = db.scalar(select(AnalystUser).where(AnalystUser.username == settings.admin_username))
        if existing:
            return
        password_hash, salt = hash_password(settings.admin_password)
        db.add(
            AnalystUser(
                username=settings.admin_username,
                password_hash=password_hash,
                password_salt=salt,
                role="admin",
            )
        )
        db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_security()
    Base.metadata.create_all(bind=engine)
    seed_admin()
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description="Explainable authentication and API security monitoring.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Ingestion-Key"],
)


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def issue_token_pair(user: AnalystUser, db: Session) -> TokenResponse:
    jti = uuid.uuid4().hex
    expires = datetime.now(UTC) + timedelta(days=settings.refresh_token_days)
    db.add(RefreshSession(jti=jti, user_id=user.id, expires_at=expires))
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user.username, user.role),
        refresh_token=create_refresh_token(user.username, user.role, jti),
        expires_in=settings.access_token_minutes * 60,
    )


def write_audit(
    db: Session,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    details: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": settings.app_name, "version": "0.2.0"}


@app.get("/ready")
def readiness(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "connected", "model": MODEL_VERSION}


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(payload: TokenRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    client = request.client.host if request.client else "unknown"
    limiter_key = f"{client}:{payload.username.lower()}"
    if not login_limiter.allow(limiter_key):
        raise HTTPException(status_code=429, detail="Too many login attempts; retry in five minutes")

    user = db.scalar(select(AnalystUser).where(AnalystUser.username == payload.username))
    if not user or not user.is_active or not verify_password(
        payload.password, user.password_hash, user.password_salt
    ):
        write_audit(db, payload.username, "login_failed", "session", client)
        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    login_limiter.reset(limiter_key)
    write_audit(db, user.username, "login_succeeded", "session", client)
    db.commit()
    return issue_token_pair(user, db)


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    claims = decode_token(payload.refresh_token, "refresh")
    session = db.scalar(select(RefreshSession).where(RefreshSession.jti == claims.get("jti")))
    if not session or session.revoked_at or aware(session.expires_at) <= datetime.now(UTC):
        raise HTTPException(status_code=401, detail="Refresh token is revoked or expired")
    user = db.get(AnalystUser, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is inactive or unavailable")
    session.revoked_at = datetime.now(UTC)
    write_audit(db, user.username, "token_rotated", "session", session.jti)
    db.commit()
    return issue_token_pair(user, db)


@app.post("/api/v1/auth/logout", status_code=204)
def logout(payload: RefreshRequest, db: Session = Depends(get_db)) -> None:
    claims = decode_token(payload.refresh_token, "refresh")
    session = db.scalar(select(RefreshSession).where(RefreshSession.jti == claims.get("jti")))
    if session and not session.revoked_at:
        session.revoked_at = datetime.now(UTC)
        write_audit(db, claims.get("sub", "unknown"), "logout", "session", session.jti)
        db.commit()


def require_ingestion_key(x_ingestion_key: str = Header(...)) -> None:
    if not hmac.compare_digest(x_ingestion_key, settings.ingestion_api_key):
        raise HTTPException(status_code=403, detail="Invalid ingestion API key")


def ingest_event(payload: EventCreate, db: Session) -> tuple[SecurityEvent, Alert | None]:
    timestamp = payload.timestamp or datetime.now(UTC)
    window_start = timestamp - timedelta(minutes=10)
    recent = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.timestamp >= window_start, SecurityEvent.timestamp <= timestamp)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(200)
        )
    )
    baseline = list(
        db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.user_id == payload.user_id,
                SecurityEvent.outcome == "success",
                SecurityEvent.timestamp < timestamp,
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(500)
        )
    )
    event = SecurityEvent(
        timestamp=timestamp,
        user_id=payload.user_id,
        event_type=payload.event_type,
        outcome=payload.outcome,
        ip_address=str(payload.ip_address),
        country=payload.country.upper(),
        endpoint=payload.endpoint,
        role=payload.role,
        source=payload.source,
        details=payload.details,
        model_version=MODEL_VERSION,
    )
    result = detection_engine.analyze(event, recent, baseline)
    event.risk_score = result.risk_score
    event.anomaly_score = result.anomaly_score
    db.add(event)
    db.flush()

    alert = None
    if result.risk_score >= ALERT_THRESHOLD:
        alert = Alert(
            event_id=event.id,
            title=result.title,
            severity=result.severity,
            risk_score=result.risk_score,
            mitre_technique=result.mitre_technique,
            explanation=result.explanation,
            evidence=result.evidence,
        )
        db.add(alert)
        db.flush()
        write_audit(
            db,
            "detection-engine",
            "alert_created",
            "alert",
            str(alert.id),
            {"rules": result.triggered_rules, "model_version": result.model_version},
        )
    return event, alert


@app.post(
    "/api/v1/ingest/events",
    response_model=BatchIngestResponse,
    dependencies=[Depends(require_ingestion_key)],
)
def ingest_batch(payload: BatchIngestRequest, db: Session = Depends(get_db)) -> BatchIngestResponse:
    event_ids: list[int] = []
    alerts_created = 0
    for event_payload in payload.events:
        event, alert = ingest_event(event_payload, db)
        event_ids.append(event.id)
        alerts_created += int(alert is not None)
    db.commit()
    return BatchIngestResponse(
        accepted=len(event_ids), alerts_created=alerts_created, event_ids=event_ids
    )


@app.post("/api/v1/events", response_model=EventRead)
def create_event(
    payload: EventCreate,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> SecurityEvent:
    event, _ = ingest_event(payload, db)
    db.commit()
    db.refresh(event)
    return event


@app.get("/api/v1/events", response_model=list[EventRead])
def list_events(
    limit: int = Query(50, ge=1, le=200),
    event_type: str | None = None,
    outcome: str | None = None,
    user_id: str | None = None,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[SecurityEvent]:
    statement = select(SecurityEvent)
    if event_type:
        statement = statement.where(SecurityEvent.event_type == event_type)
    if outcome:
        statement = statement.where(SecurityEvent.outcome == outcome)
    if user_id:
        statement = statement.where(SecurityEvent.user_id == user_id)
    return list(db.scalars(statement.order_by(SecurityEvent.timestamp.desc()).limit(limit)))


@app.get("/api/v1/alerts", response_model=list[AlertRead])
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    status: str | None = None,
    severity: str | None = None,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[Alert]:
    statement = select(Alert)
    if status:
        statement = statement.where(Alert.status == status)
    if severity:
        statement = statement.where(Alert.severity == severity)
    return list(db.scalars(statement.order_by(Alert.created_at.desc()).limit(limit)))


@app.get("/api/v1/alerts/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: int,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.patch("/api/v1/alerts/{alert_id}", response_model=AlertRead)
def update_alert(
    alert_id: int,
    payload: StatusUpdate,
    current_user: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    old_status = alert.status
    alert.status = payload.status
    write_audit(
        db,
        current_user.username,
        "alert_status_changed",
        "alert",
        str(alert.id),
        {"from": old_status, "to": payload.status},
    )
    db.commit()
    db.refresh(alert)
    return alert


@app.get("/api/v1/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)))


@app.post("/api/v1/simulations/{scenario}")
def simulate(
    scenario: str,
    current_user: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    try:
        events = build_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    alert_count = 0
    for event_payload in events:
        _, alert = ingest_event(event_payload, db)
        alert_count += int(alert is not None)
    write_audit(
        db,
        current_user.username,
        "simulation_executed",
        "scenario",
        scenario,
        {"events": len(events), "alerts": alert_count},
    )
    db.commit()
    return {"scenario": scenario, "events_created": len(events), "alerts_created": alert_count}


@app.get("/api/v1/detection/health", response_model=DetectionHealth)
def detection_health(_: AnalystUser = Depends(require_analyst)) -> DetectionHealth:
    return DetectionHealth(
        model_version=MODEL_VERSION,
        alert_threshold=ALERT_THRESHOLD,
        minimum_personal_baseline=MINIMUM_PERSONAL_BASELINE,
        rules=DetectionEngine.RULES,
        integrations=["JSON/JSONL", "Linux OpenSSH auth.log", "Windows Security Event Log"],
    )


@app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> DashboardSummary:
    active_statuses = ("open", "investigating")
    total_events = db.scalar(select(func.count(SecurityEvent.id))) or 0
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status.in_(active_statuses))) or 0
    critical_alerts = db.scalar(
        select(func.count(Alert.id)).where(
            Alert.severity == "critical", Alert.status.in_(active_statuses)
        )
    ) or 0
    average_risk = db.scalar(select(func.avg(SecurityEvent.risk_score))) or 0.0
    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.status.in_(active_statuses))
        .group_by(Alert.severity)
    ).all()
    event_rows = db.execute(
        select(SecurityEvent.event_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.event_type)
    ).all()
    return DashboardSummary(
        total_events=total_events,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        average_risk=round(float(average_risk), 1),
        severity_counts=dict(severity_rows),
        event_type_counts=dict(event_rows),
    )
