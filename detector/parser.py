import re
from datetime import datetime
from detector.models import AuthEvent

_stats = {"parsed": 0, "skipped": 0, "malformed_examples": []}

def parse_line(line: str) -> AuthEvent | None:
    """Parse one auth.log line. Return None for lines we don't care about
    (e.g. 'Accepted publickey', cron, non-SSH daemons — YOU decide and document
    which lines you keep and why). Must handle: missing fields, malformed lines,
    lines from other services. Never raise on bad input — SOC parsers eat garbage daily."""
    
    # TODO: return None unless "sshd[" appears in the line
    if "sshd[" not in line:
        return None
    
    if "Failed password" not in line and "Accepted password" not in line:
        return None
    try:
        words = line.split()
        for_position = words.index("for")
        log_timestamp, source_ip, method = words[0], words[words.index("from") + 1], words[for_position - 1]
        # timestamp branch
        timestamp = datetime.fromisoformat(log_timestamp)
        # username branch
        if words[for_position + 1] == "invalid":
            username = words[for_position + 3]
        else:
            username = words[for_position + 1]
    except (IndexError, ValueError):
        return None
    success = (words[for_position - 2] == "Accepted")
    return AuthEvent(timestamp = timestamp, source_ip = source_ip, username = username, success=success, method = method, raw=line)

def parse_file(path: str) -> list[AuthEvent]:
    """Parse a whole file, sorted by timestamp. Skip unparseable lines silently
    but COUNT them; expose the count via parse_stats()."""
    _stats["parsed"], _stats["skipped"], _stats["malformed_examples"] = 0, 0, []
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            event = parse_line(line.strip())
            if event is not None:
                events.append(event)
                _stats["parsed"] += 1
            else:
                _stats["skipped"] += 1
                _stats["malformed_examples"].append(line.strip())
                if len(_stats["malformed_examples"]) > 5:
                    _stats["malformed_examples"].pop(0)
    events.sort(key=lambda event: event.timestamp)
    return events

def parse_stats() -> dict:
    """Return {'parsed': int, 'skipped': int, 'malformed_examples': list[str]}
    (last 5 skipped lines, for debugging)."""
    return dict(_stats)
