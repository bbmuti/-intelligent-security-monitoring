from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import create_access_token, require_analyst, verify_demo_credentials
from .config import get_settings
from .database import Base, engine, get_db
from .detection import DetectionEngine
from .models import Alert, SecurityEvent
from .schemas import (
    AlertRead,
    DashboardSummary,
    EventCreate,
    EventRead,
    StatusUpdate,
    TokenRequest,
    TokenResponse,
)
from .simulation import build_scenario

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
detection_engine = DetectionEngine()


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": settings.app_name}


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(payload: TokenRequest) -> TokenResponse:
    if not verify_demo_credentials(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return TokenResponse(access_token=create_access_token(payload.username))


def ingest_event(payload: EventCreate, db: Session) -> tuple[SecurityEvent, Alert | None]:
    timestamp = payload.timestamp or datetime.now(timezone.utc)
    window_start = timestamp - timedelta(minutes=10)
    recent = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.timestamp >= window_start)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(200)
        )
    )
    event = SecurityEvent(
        timestamp=timestamp,
        user_id=payload.user_id,
        event_type=payload.event_type,
        outcome=payload.outcome,
        ip_address=payload.ip_address,
        country=payload.country.upper(),
        endpoint=payload.endpoint,
        role=payload.role,
        details=payload.details,
    )
    result = detection_engine.analyze(event, recent)
    event.risk_score = result.risk_score
    event.anomaly_score = result.anomaly_score
    db.add(event)
    db.flush()

    alert = None
    if result.risk_score >= 50:
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
    db.commit()
    db.refresh(event)
    if alert:
        db.refresh(alert)
    return event, alert


@app.post("/api/v1/events", response_model=EventRead, dependencies=[Depends(require_analyst)])
def create_event(payload: EventCreate, db: Session = Depends(get_db)) -> SecurityEvent:
    event, _ = ingest_event(payload, db)
    return event


@app.get("/api/v1/events", response_model=list[EventRead], dependencies=[Depends(require_analyst)])
def list_events(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> list[SecurityEvent]:
    return list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)))


@app.get("/api/v1/alerts", response_model=list[AlertRead], dependencies=[Depends(require_analyst)])
def list_alerts(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> list[Alert]:
    return list(db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit)))


@app.patch("/api/v1/alerts/{alert_id}", response_model=AlertRead, dependencies=[Depends(require_analyst)])
def update_alert(alert_id: int, payload: StatusUpdate, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert


@app.post("/api/v1/simulations/{scenario}", dependencies=[Depends(require_analyst)])
def simulate(scenario: str, db: Session = Depends(get_db)) -> dict:
    try:
        events = build_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    alert_count = 0
    for event_payload in events:
        _, alert = ingest_event(event_payload, db)
        alert_count += int(alert is not None)
    return {"scenario": scenario, "events_created": len(events), "alerts_created": alert_count}


@app.get(
    "/api/v1/dashboard/summary",
    response_model=DashboardSummary,
    dependencies=[Depends(require_analyst)],
)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    total_events = db.scalar(select(func.count(SecurityEvent.id))) or 0
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status != "resolved")) or 0
    critical_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.severity == "critical")) or 0
    average_risk = db.scalar(select(func.avg(SecurityEvent.risk_score))) or 0.0
    severity_rows = db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    event_rows = db.execute(select(SecurityEvent.event_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.event_type)).all()
    return DashboardSummary(
        total_events=total_events,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        average_risk=round(float(average_risk), 1),
        severity_counts=dict(severity_rows),
        event_type_counts=dict(event_rows),
    )
