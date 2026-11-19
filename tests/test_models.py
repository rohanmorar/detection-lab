from datetime import datetime, timedelta, timezone

from detector.models import AuthEvent, Alert

# One fixed timestamp reused by every test. It is timezone-aware (UTC-6 here),
# matching the aware datetimes your parser will produce.
TS = datetime(2026, 11, 2, 19, 2, 11, tzinfo=timezone(timedelta(hours=-6)))


def test_auth_event_fields():
    # TODO 1: build an AuthEvent using TS, a source_ip, a username,
    #         success=False, method="password", and a raw line string.
    # TODO 2: assert at least three fields hold what you passed in
    #         (e.g. source_ip, success, username).
    pass


def test_alert_fields():
    # TODO 3: build an Alert with every required field
    #         (rule, technique, severity, source_ip, usernames,
    #          first_seen, last_seen, event_count).
    # TODO 4: assert technique and event_count are what you passed in.
    pass


def test_alert_defaults():
    # TODO 5: build an Alert WITHOUT passing evidence or description.
    # TODO 6: assert evidence == [] and description == "".
    pass


def test_alert_evidence_not_shared():
    # TODO 7: build two Alerts, both without evidence.
    # TODO 8: append a string to the first alert's evidence list.
    # TODO 9: assert the second alert's evidence is still empty.
    #         This is the test that proves default_factory=list works.
    pass


def test_timestamps_are_timezone_aware():
    # TODO 10: build an AuthEvent with TS and assert its ts.tzinfo is not None.
    #          This guards against a naive/aware mix-up when
    pass