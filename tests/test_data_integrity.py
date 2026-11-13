import json
from datetime import datetime, timedelta

ATTACK_LABELS = ["brute_force", "password_spray", "low_and_slow"]
OUT_OF_SCOPE_LABEL = "out_of_scope"


def load_labels():
    # Open labels.json and return the list of windows.
    labels_file = open("data/labeled/labels.json")
    labels = json.load(labels_file)
    labels_file.close()
    return labels


def load_sample():
    # Read sample_auth.log and return a list of (timestamp, line) pairs.
    sample_file = open("data/labeled/sample_auth.log")
    all_lines = sample_file.readlines()
    sample_file.close()

    pairs = []
    for line in all_lines:
        first_word = line.split(" ")[0]
        ts = datetime.fromisoformat(first_word)
        pairs.append((ts, line))
    return pairs


def get_window_lines(label, sample):
    # Return only the log lines that fall inside one labeled window.
    start = datetime.fromisoformat(label["start"])
    end = datetime.fromisoformat(label["end"]) + timedelta(seconds=1)

    window_lines = []
    for pair in sample:
        ts = pair[0]
        line = pair[1]
        if ts >= start and ts < end:
            window_lines.append(line)
    return window_lines


def is_failed_login(line):
    # ---- YOUR PART (1) ----
    # Return True if this line is a failed login, otherwise False.
    # Use the two phrases you just saw with grep, and the "in" keyword
    # (example: "abc" in line is True when the line contains abc).
    return "Failed password" in line or "Invalid user" in line


def test_sample_is_in_time_order():
    # Already written for you: each timestamp must not be earlier than the one before it.
    sample = load_sample()
    previous_ts = sample[0][0]
    for pair in sample:
        assert pair[0] >= previous_ts
        previous_ts = pair[0]


def test_attack_windows_have_failed_logins():
    labels = load_labels()
    sample = load_sample()

    for label in labels:
        if label["label"] in ATTACK_LABELS:
            lines = get_window_lines(label, sample)

            failed_count = 0
            for line in lines:
                if is_failed_login(line):
                    failed_count = failed_count + 1

            # ---- YOUR PART (2) ----
            # Write an assert that fails if this attack window has no failed logins.
            assert failed_count > 0, "attack window has no failed login"


def test_out_of_scope_window_has_no_failed_logins():
    # ---- YOUR PART (3) ----
    # Same idea as the test above, but for windows labeled "out_of_scope"
    # (that's A1, the Nmap scan). Count the failed logins in the window,
    # then assert the count is 0.
    labels = load_labels()
    sample = load_sample()

    for label in labels:
        if label["label"] == OUT_OF_SCOPE_LABEL:
            lines = get_window_lines(label, sample)

            failed_count = 0
            for line in lines:
                if is_failed_login(line):
                    failed_count = failed_count + 1

            # ---- YOUR PART (2) ----
            # Write an assert that fails if this attack window has no failed logins.
            assert failed_count == 0, "out_of_scope window has failed logins"

