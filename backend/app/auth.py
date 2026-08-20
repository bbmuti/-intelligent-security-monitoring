import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import AnalystUser

security = HTTPBearer()


def password_digest(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210_000).hex()


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    return password_digest(password, salt), salt


def verify_password(password: str, expected: str, salt: str) -> bool:
    return hmac.compare_digest(password_digest(password, salt), expected)


def create_token(subject: str, role: str, token_type: str, lifetime: timedelta, jti: str | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "role": role,
        "type": token_type,
        "jti": jti or uuid.uuid4().hex,
        "iat": now,
        "exp": now + lifetime,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(subject: str, role: str) -> str:
    settings = get_settings()
    return create_token(subject, role, "access", timedelta(minutes=settings.access_token_minutes))


def create_refresh_token(subject: str, role: str, jti: str) -> str:
    settings = get_settings()
    return create_token(subject, role, "refresh", timedelta(days=settings.refresh_token_days), jti)


def decode_token(token: str, expected_type: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    if payload.get("type") != expected_type:
        raise HTTPException(status_code=401, detail="Incorrect token type")
    return payload


def require_analyst(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> AnalystUser:
    payload = decode_token(credentials.credentials, "access")
    user = db.scalar(select(AnalystUser).where(AnalystUser.username == payload.get("sub")))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is inactive or unavailable")
    if user.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Analyst role required")
    return user
