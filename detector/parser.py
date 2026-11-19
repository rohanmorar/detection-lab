"""Parser for Ubuntu auth.log. 
Keeps: <YOU DECIDE + say why>.   Drops: <YOU DECIDE + say why>."""
import re
from detector.models import AuthEvent

# TODO 1: write ONE compiled regex that captures: timestamp, success/failure word,
#         method, optional "invalid user ", username, source ip.
#         Hint: Failed/Accepted are the same shape, so one pattern with a group is enough.
LINE_RE = None

_stats = {"parsed": 0, "skipped": 0, "malformed_examples": []}

def parse_line(line: str) -> AuthEvent | None:
    """Parse one auth.log line. Return None for lines we don't care about
    (e.g. 'Accepted publickey', cron, non-SSH daemons — YOU decide and document
    which lines you keep and why). Must handle: missing fields, malformed lines,
    lines from other services. Never raise on bad input — SOC parsers eat garbage daily."""
    # TODO 2: match LINE_RE; if no match -> return None (never raise).
    # TODO 3: build the datetime from the timestamp group (datetime.fromisoformat
    #         keeps the offset, which is what you want).
    # TODO 4: return an AuthEvent with success = (word == "Accepted").
    #         Wrap the datetime conversion in try/except ValueError -> None.
    pass

def parse_file(path: str) -> list[AuthEvent]:
    """Parse a whole file, sorted by timestamp. Skip unparseable lines silently
    but COUNT them; expose the count via parse_stats()."""
    # TODO 5: reset _stats, read the file line by line, call parse_line,
    #         count parsed vs skipped (keep only the LAST 5 skipped lines),
    #         return events sorted by ts.
    pass


def parse_stats() -> dict:
    """Return {'parsed': int, 'skipped': int, 'malformed_examples': list[str]}
    (last 5 skipped lines, for debugging)."""
    return dict(_stats)
