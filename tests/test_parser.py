from detector.parser import parse_line, parse_file, parse_stats

FAILED_LINE = "2026-10-28T19:27:22.670794+00:00 target sshd[3787]: Failed password for rohan from 192.168.233.128 port 39524 ssh2"
ACCEPTED_LINE = "2026-10-28T19:27:34.322750+00:00 target sshd[3789]: Accepted password for rohan from 192.168.233.128 port 39550 ssh2"
INVALID_USER_LINE = "2026-10-28T18:16:46.981141+00:00 target sshd[2681]: Failed password for invalid user roha from 192.168.233.128 port 54942 ssh2"
SUDO_LINE = "2026-10-28T18:15:06.542410+00:00 target sudo: pam_unix(sudo:auth): conversation failed"
CUT_AFTER_FOR = "2026-10-28T18:16:46.981141+00:00 target sshd[2681]: Failed password for"
CUT_AFTER_FROM = "2026-10-28T19:27:34.322750+00:00 target sshd[3789]: Accepted password for rohan from"
SUDO_GREP_LINE = "2026-10-28T19:36:14.023142+00:00 target sudo:    rohan : TTY=pts/0 ; PWD=/home/rohan ; USER=root ; COMMAND=/usr/bin/grep 'Failed password' /var/log/auth.log"

def test_sudo_line_mentioning_failed_password_returns_none():
    assert parse_line(SUDO_GREP_LINE) is None
    
def test_failed_real_user():
    event = parse_line(FAILED_LINE)
    assert event.username == "rohan"
    assert event.source_ip == "192.168.233.128"
    assert event.success == False
    assert event.timestamp.tzinfo is not None  # must be timezone aware

def test_failed_invalid_user():
    event = parse_line(INVALID_USER_LINE)
    assert event.source_ip == "192.168.233.128"
    assert event.username == "roha"
    assert event.success == False

def test_accepted():
    event = parse_line(ACCEPTED_LINE)
    assert event.success == True
    assert event.method == "password"

def test_sudo_returns_none():
    assert parse_line(SUDO_LINE) is None

def test_truncated_after_for_returns_none():
    assert parse_line(CUT_AFTER_FOR) is None

def test_truncated_after_from_returns_none():
    assert parse_line(CUT_AFTER_FROM) is None

def test_empty_returns_none():
    assert parse_line("") is None

def test_parse_file_counts(tmp_path):
    # 47 good lines + 3 junk lines, written to a temporary file
    good_lines = [FAILED_LINE] * 47
    junk_lines = ["garbage", "", "sudo: not a login line"]
    all_lines = good_lines + junk_lines

    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join(all_lines))

    events = parse_file(str(log_file))
    assert len(events) == 47
    stats = parse_stats()
    assert stats["parsed"] == 47 and stats["skipped"] == 3