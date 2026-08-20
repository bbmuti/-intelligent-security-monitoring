from datetime import UTC, datetime

from app.integrations.linux_auth import parse_linux_auth_line


def test_parses_successful_public_key_login():
    event = parse_linux_auth_line(
        "Aug 20 09:14:07 web-01 sshd[1201]: Accepted publickey for beren from 10.0.0.24 port 51822 ssh2",
        now=datetime(2026, 8, 20, 12, tzinfo=UTC),
    )
    assert event["user_id"] == "beren"
    assert event["outcome"] == "success"
    assert event["source"] == "linux-auth-log"
    assert event["details"]["authentication_method"] == "publickey"


def test_parses_failed_invalid_user_login():
    event = parse_linux_auth_line(
        "Aug 20 09:15:11 web-01 sshd[1208]: Failed password for invalid user admin from 203.0.113.42 port 49821 ssh2",
        now=datetime(2026, 8, 20, 12, tzinfo=UTC),
    )
    assert event["outcome"] == "failure"
    assert event["ip_address"] == "203.0.113.42"
    assert event["details"]["invalid_user"] is True


def test_ignores_unrelated_log_record():
    assert parse_linux_auth_line("Aug 20 09:20:01 web-01 sudo: pam_unix session opened") is None


def test_december_record_uses_previous_year_when_reference_is_january():
    event = parse_linux_auth_line(
        "Dec 31 23:59:59 web-01 sshd[1210]: Accepted password for beren from 10.0.0.24 port 51823 ssh2",
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )
    assert event["timestamp"].startswith("2025-12-31")


def test_small_clock_skew_does_not_move_record_to_previous_year():
    event = parse_linux_auth_line(
        "Aug 20 12:05:00 web-01 sshd[1210]: Accepted password for beren from 10.0.0.24 port 51823 ssh2",
        now=datetime(2026, 8, 20, 12, tzinfo=UTC),
    )
    assert event["timestamp"].startswith("2026-08-20")
