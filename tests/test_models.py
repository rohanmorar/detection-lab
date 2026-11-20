from datetime import datetime, timedelta, timezone
from detector.models import AuthEvent, Alert

# One fixed timestamp reused by every test. It is timezone-aware (UTC-6 here),
# matching the aware datetimes your parser will produce.
TS = datetime(2026, 11, 2, 19, 2, 11, tzinfo=timezone(timedelta(hours=-6)))

def make_alert():
    return Alert(
        rule="ssh_brute_force",
        technique="T1110.001",
        severity="high",
        source_ip="192.168.233.128",
        usernames=["rohan"],
        first_seen=TS,
        last_seen=TS,
        event_count=1,
    )

def test_auth_event_fields():
    event = AuthEvent(
        timestamp=TS,
        source_ip="192.168.233.128",
        username="rohan",
        success=False,
        method="password",
        raw="raw line here",
    )
    assert event.timestamp == TS
    assert event.source_ip == "192.168.233.128"
    assert event.username == "rohan"
    assert event.success is False
    assert event.method == "password"
    assert event.raw == "raw line here"


def test_alert_fields():
    alert = make_alert()
    assert alert.technique == "T1110.001"
    assert alert.event_count == 1
    assert alert.rule == "ssh_brute_force"
    assert alert.severity == "high"
    assert alert.usernames == ["rohan"]

def test_alert_defaults():
    alert = make_alert()
    assert alert.evidence == []
    assert alert.description == ""


def test_alert_evidence_not_shared():
    alert1, alert2 = make_alert(), make_alert()
    alert1.evidence.append("raw line here")
    assert alert1.evidence == ["raw line here"]
    assert alert2.evidence == []

def test_timestamps_are_timezone_aware():
    # naive and aware datetimes can't be compared
    event = AuthEvent(
        timestamp=TS,
        source_ip="192.168.233.128",
        username="rohan",
        success=False,
        method="password",
        raw="raw line here",
    )
    assert event.timestamp.tzinfo is not None