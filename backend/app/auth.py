import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_settings

security = HTTPBearer()


def _password_digest(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210_000).hex()


def verify_demo_credentials(username: str, password: str) -> bool:
    settings = get_settings()
    user_ok = hmac.compare_digest(username, settings.admin_username)
    expected = _password_digest(settings.admin_password, settings.admin_username)
    supplied = _password_digest(password, settings.admin_username)
    return user_ok and hmac.compare_digest(expected, supplied)


def create_access_token(subject: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def require_analyst(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    if payload.get("role") != "analyst":
        raise HTTPException(status_code=403, detail="Analyst role required")
    return payload
