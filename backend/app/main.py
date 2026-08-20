import hmac
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import (
    PASSWORD_ITERATIONS,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    require_analyst,
    verify_password,
)
from .config import get_settings
from .database import SessionLocal, get_db
from .detection import (
    ALERT_THRESHOLD,
    MINIMUM_PERSONAL_BASELINE,
    MODEL_VERSION,
    UNATTRIBUTABLE_IPS,
    DetectionEngine,
)
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
    StatusUpdate,
    TokenRequest,
    TokenResponse,
)
from .simulation import build_scenario

settings = get_settings()
detection_engine = DetectionEngine()
login_pair_limiter = SlidingWindowRateLimiter(limit=5, window_seconds=300)
login_ip_limiter = SlidingWindowRateLimiter(limit=25, window_seconds=300)
REFRESH_COOKIE = "sentinelscope_refresh"
CSRF_COOKIE = "sentinelscope_csrf"
APP_VERSION = "0.3.0"


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
    seed_admin()
    yield


app = FastAPI(
    title=settings.app_name,
    version=APP_VERSION,
    description="Explainable authentication and API security monitoring.",
    lifespan=lifespan,
    docs_url=None if settings.environment.lower() == "production" else "/docs",
    redoc_url=None if settings.environment.lower() == "production" else "/redoc",
    openapi_url=None if settings.environment.lower() == "production" else "/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Ingestion-Key", "X-CSRF-Token"],
)


def issue_token_pair(
    user: AnalystUser,
    db: Session,
    *,
    family_id: str | None = None,
    parent_jti: str | None = None,
) -> tuple[TokenResponse, str]:
    jti = uuid.uuid4().hex
    family = family_id or uuid.uuid4().hex
    expires = datetime.now(UTC) + timedelta(days=settings.refresh_token_days)
    db.add(
        RefreshSession(
            jti=jti,
            family_id=family,
            parent_jti=parent_jti,
            user_id=user.id,
            expires_at=expires,
        )
    )
    return (
        TokenResponse(
            access_token=create_access_token(user.username, user.role),
            expires_in=settings.access_token_minutes * 60,
        ),
        create_refresh_token(user.username, user.role, jti),
    )


def set_session_cookies(response: Response, refresh_token: str) -> None:
    secure = settings.environment.lower() == "production"
    max_age = settings.refresh_token_days * 24 * 60 * 60
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api/v1/auth",
    )
    response.set_cookie(
        CSRF_COOKIE,
        uuid.uuid4().hex,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def require_csrf(csrf_cookie: str | None, csrf_header: str | None) -> None:
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def utc_aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


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
    return {"status": "healthy", "service": settings.app_name, "version": APP_VERSION}


@app.get("/ready")
def readiness(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "connected", "model": MODEL_VERSION}


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(
    payload: TokenRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    client = request.client.host if request.client else "unknown"
    limiter_key = f"{client}:{payload.username.lower()}"
    if not login_ip_limiter.allow(client) or not login_pair_limiter.allow(limiter_key):
        raise HTTPException(status_code=429, detail="Too many login attempts; retry in five minutes")

    user = db.scalar(select(AnalystUser).where(AnalystUser.username == payload.username))
    if not user or not user.is_active or not verify_password(
        payload.password,
        user.password_hash,
        user.password_salt,
        user.password_iterations,
    ):
        write_audit(db, payload.username, "login_failed", "session", client)
        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    login_pair_limiter.reset(limiter_key)
    login_ip_limiter.reset(client)
    if user.password_iterations < PASSWORD_ITERATIONS:
        user.password_hash, user.password_salt = hash_password(payload.password)
        user.password_iterations = PASSWORD_ITERATIONS
    write_audit(db, user.username, "login_succeeded", "session", client)
    tokens, refresh_token = issue_token_pair(user, db)
    db.commit()
    set_session_cookies(response, refresh_token)
    return tokens


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    x_csrf_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> TokenResponse:
    require_csrf(csrf_cookie, x_csrf_token)
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh session is unavailable")
    claims = decode_token(refresh_token, "refresh")
    jti = claims.get("jti")
    now = datetime.now(UTC)
    session = db.scalar(
        update(RefreshSession)
        .where(
            RefreshSession.jti == jti,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > now,
        )
        .values(revoked_at=now)
        .returning(RefreshSession)
    )
    if not session:
        replayed = db.scalar(select(RefreshSession).where(RefreshSession.jti == jti))
        if replayed:
            db.execute(
                update(RefreshSession)
                .where(
                    RefreshSession.family_id == replayed.family_id,
                    RefreshSession.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            write_audit(
                db,
                claims.get("sub", "unknown"),
                "refresh_token_reuse_detected",
                "session_family",
                replayed.family_id,
                {"replayed_jti": jti},
            )
            db.commit()
        raise HTTPException(status_code=401, detail="Refresh token is revoked or expired")
    user = db.get(AnalystUser, session.user_id)
    if not user or not user.is_active:
        db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.family_id == session.family_id,
                RefreshSession.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        write_audit(
            db,
            claims.get("sub", "unknown"),
            "inactive_user_refresh_rejected",
            "session_family",
            session.family_id,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="User is inactive or unavailable")
    write_audit(db, user.username, "token_rotated", "session", session.jti)
    tokens, new_refresh_token = issue_token_pair(
        user,
        db,
        family_id=session.family_id,
        parent_jti=session.jti,
    )
    db.commit()
    set_session_cookies(response, new_refresh_token)
    return tokens


@app.post("/api/v1/auth/logout", status_code=204)
def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    x_csrf_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> None:
    require_csrf(csrf_cookie, x_csrf_token)
    if not refresh_token:
        response.delete_cookie(CSRF_COOKIE, path="/")
        return
    claims = decode_token(refresh_token, "refresh")
    session = db.scalar(select(RefreshSession).where(RefreshSession.jti == claims.get("jti")))
    if session:
        db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.family_id == session.family_id,
                RefreshSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
        write_audit(db, claims.get("sub", "unknown"), "logout", "session_family", session.family_id)
        db.commit()
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")


def require_ingestion_key(x_ingestion_key: str = Header(...)) -> None:
    if not hmac.compare_digest(x_ingestion_key, settings.ingestion_api_key):
        raise HTTPException(status_code=403, detail="Invalid ingestion API key")


def ingest_event(payload: EventCreate, db: Session) -> tuple[SecurityEvent, Alert | None, bool]:
    timestamp = payload.timestamp or datetime.now(UTC)
    if timestamp > datetime.now(UTC) + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="Event timestamp cannot be more than five minutes in the future")
    if payload.source_event_id:
        duplicate = db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.source == payload.source,
                SecurityEvent.source_event_id == payload.source_event_id,
            )
        )
        if duplicate:
            return duplicate, duplicate.alert, False
    window_start = timestamp - timedelta(minutes=10)
    recent_by_user = list(
        db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= timestamp,
                SecurityEvent.user_id == payload.user_id,
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(1_000)
        )
    )
    recent_by_ip = []
    if str(payload.ip_address) not in UNATTRIBUTABLE_IPS:
        recent_by_ip = list(
            db.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.timestamp >= window_start,
                    SecurityEvent.timestamp <= timestamp,
                    SecurityEvent.ip_address == str(payload.ip_address),
                )
                .order_by(SecurityEvent.timestamp.desc())
                .limit(1_000)
            )
        )
    recent = sorted(
        {event.id: event for event in recent_by_user + recent_by_ip}.values(),
        key=lambda event: utc_aware(event.timestamp),
        reverse=True,
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
        source_event_id=payload.source_event_id,
        details=payload.details,
        model_version=MODEL_VERSION,
    )
    result = detection_engine.analyze(event, recent, baseline)
    event.risk_score = result.risk_score
    event.anomaly_score = result.anomaly_score
    alert = None
    try:
        with db.begin_nested():
            db.add(event)
            db.flush()
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
    except IntegrityError:
        if payload.source_event_id:
            duplicate = db.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.source == payload.source,
                    SecurityEvent.source_event_id == payload.source_event_id,
                )
            )
            if duplicate:
                return duplicate, duplicate.alert, False
        raise
    return event, alert, True


@app.post(
    "/api/v1/ingest/events",
    response_model=BatchIngestResponse,
    dependencies=[Depends(require_ingestion_key)],
)
def ingest_batch(payload: BatchIngestRequest, db: Session = Depends(get_db)) -> BatchIngestResponse:
    event_ids: list[int] = []
    alerts_created = 0
    duplicates = 0
    for event_payload in payload.events:
        event, alert, created = ingest_event(event_payload, db)
        event_ids.append(event.id)
        alerts_created += int(created and alert is not None)
        duplicates += int(not created)
    db.commit()
    return BatchIngestResponse(
        accepted=len(event_ids) - duplicates,
        duplicates=duplicates,
        alerts_created=alerts_created,
        event_ids=event_ids,
    )


@app.post("/api/v1/events", response_model=EventRead)
def create_event(
    payload: EventCreate,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> SecurityEvent:
    event, _, _ = ingest_event(payload, db)
    db.commit()
    db.refresh(event)
    return event


@app.get("/api/v1/events", response_model=list[EventRead])
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    event_type: Literal["login", "api_access", "authorization_failure", "role_change"] | None = None,
    outcome: Literal["success", "failure", "denied"] | None = None,
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
    return list(
        db.scalars(statement.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit))
    )


@app.get("/api/v1/alerts", response_model=list[AlertRead])
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    status: Literal["open", "investigating", "resolved", "false_positive"] | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[Alert]:
    statement = select(Alert)
    if status:
        statement = statement.where(Alert.status == status)
    if severity:
        statement = statement.where(Alert.severity == severity)
    return list(db.scalars(statement.order_by(Alert.created_at.desc()).offset(offset).limit(limit)))


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
    if old_status == payload.status:
        return alert
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
    offset: int = Query(0, ge=0, le=100_000),
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
        )
    )


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
        _, alert, _ = ingest_event(event_payload, db)
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
