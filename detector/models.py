from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class AuthEvent:
    """One parsed line of auth.log."""
    timestamp: datetime          # event timestamp
    source_ip: str
    username: str
    success: bool         # True = accepted, False = failed
    method: str           # "password", "publickey", ...
    raw: str              # original line, for evidence

@dataclass
class Alert:
    """A fired detection, tagged for a SOC pipeline."""
    rule: str                      # e.g. "ssh_brute_force"
    technique: str                 # MITRE ATT&CK ID, e.g. "T1110.001"
    severity: str                  # "low" | "medium" | "high"  (you define the mapping)
    source_ip: str
    usernames: list[str]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence: list[str] = field(default_factory=list)   # raw log lines
    description: str = ""