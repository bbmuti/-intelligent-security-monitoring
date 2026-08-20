"""Parse OpenSSH authentication records from Linux auth logs."""

import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256

SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)
SSH_AUTH = re.compile(
    r"^(?P<result>Accepted|Failed)\s+(?P<method>password|publickey|keyboard-interactive)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def _timestamp(month: str, day: str, clock: str, now: datetime) -> datetime:
    parsed = datetime.strptime(f"{now.year} {month} {day} {clock}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    # Syslog omits the year. Only treat a far-future date as the previous year;
    # a small clock skew must not turn today's record into a year-old event.
    if parsed - now.astimezone(UTC) > timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed


def parse_linux_auth_line(line: str, now: datetime | None = None) -> dict | None:
    """Return a normalized event for an OpenSSH login record, otherwise ``None``."""

    normalized_line = line.strip()
    prefix = SYSLOG_PREFIX.match(normalized_line)
    if not prefix:
        return None
    auth = SSH_AUTH.match(prefix.group("message"))
    if not auth:
        return None

    reference = now or datetime.now(UTC)
    outcome = "success" if auth.group("result") == "Accepted" else "failure"
    return {
        "timestamp": _timestamp(
            prefix.group("month"), prefix.group("day"), prefix.group("clock"), reference
        ).isoformat(),
        "user_id": auth.group("user"),
        "event_type": "login",
        "outcome": outcome,
        "ip_address": auth.group("ip"),
        "country": "ZZ",
        "endpoint": "/ssh",
        "role": "user",
        "source": "linux-auth-log",
        "source_event_id": sha256(normalized_line.encode()).hexdigest(),
        "details": {
            "host": prefix.group("host"),
            "authentication_method": auth.group("method"),
            "source_port": int(auth.group("port")),
            "invalid_user": bool(auth.group("invalid")),
        },
    }
