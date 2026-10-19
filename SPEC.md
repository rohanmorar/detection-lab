# DETECTION ENGINEERING LAB — Build Specification
### A CS61B-style assignment: SSH Brute-Force & Password-Spray Detector
**Scaffold:** build plan drafted with Claude and Kimi | **Implementation, tests, and tuning:** Rohan | **Stack:** Python 3.10+, pytest, SQLite, Wireshark, Suricata, Hydra, Nmap
**Estimated effort:** 10 modules × 2–4 hrs each, over ~2 weeks of evenings

---

## 0. BIG PICTURE (read this first, re-read when lost)

```
                    ┌──────────────────────────── LAB ─────────────────────────────┐
 Kali (attacker) ──►│  Nmap SYN scan / Hydra brute force / Hydra spray / low&slow  │
                    │  + benign activity (logins, sudo, fat-finger typos, script)  │
                    └──────┬──────────────────────────────────┬───────────────────┘
                           │ auth.log (Ubuntu target)         │ Suricata eve.json (IDS)
                           ▼                                  ▼
                    ┌─────────────┐                    ┌──────────────┐
                    │  detector/  │  CLI entry point   │  correlate   │
                    │  parser.py  │──► detect.py ─────►│  by time+IP  │
                    └─────────────┘                    └──────────────┘
                           │ alerts (JSON, ATT&CK-tagged)
              ┌────────────┼───────────────────┐
              ▼            ▼                   ▼
      ┌───────────┐ ┌────────────┐   ┌────────────────┐
      │ evaluate  │ │  SQLite DB │   │  Sigma rule    │
      │ vs labels │ │  + queries │   │  (same logic)  │
      └───────────┘ └────────────┘   └────────────────┘
              ▼            ▼
        tuning table   analyst views
        (TP/FP/FN,     (top IPs, by
        thresholds)     technique, timeline)
```

**The one-sentence version:** generate labeled attack & benign activity in a lab, parse
`auth.log` into structured events, run three detection rules over them, tag alerts with
MITRE ATT&CK IDs, score the detector against ground truth while tuning thresholds,
correlate with Suricata network evidence, store everything in SQLite, and ship it all
with tests, CI, and an honest README.

**Why each module exists (your defense script):**
- *Parser* — real data is messy; SOC work is 70% normalization.
- *Three rules, not one* — brute force (volume per IP), spraying (breadth of users per IP),
  low-and-slow (persistence under the threshold). Together they answer "how would an
  attacker evade you?"
- *Labels + evaluation* — a detection you haven't measured is an opinion.
- *Suricata correlation* — host + network agreement is how you escalate with confidence.
- *SQLite* — the query layer is a miniature SIEM; it also rebuilds your SQL.
- *Sigma* — shows you speak the industry's rule format.

---

## 1. GROUND RULES (non-negotiable)

1. **Write every line yourself.** You may use AI/docs to *explain* an error or a concept,
   but if you cannot walk through a line on a whiteboard, delete it and write one you can.
   Target: ~300–400 lines of your own code total (small on purpose).
2. **Tests are part of the module, not an afterthought.** A module is done when its
   acceptance criteria pass AND CI is green.
3. **Never commit secrets, real IPs from outside the lab, or raw attack tooling output
   beyond log samples.** The `data/raw/` directory is gitignored; only small curated
   sample logs + labels live in git.
4. **Everything labeled.** If an attack run isn't in `labels.json`, the evaluation is
   meaningless. Log start/end times with `date -Is` on the target before and after each run.
5. **Interview rule of thumb:** for every module, be ready for "why this way?" and
   "how would an attacker beat it?"

---

## 2. REPO & GITHUB SETUP (Module 0 — do this before anything)

```bash
# Local
mkdir detection-lab && cd detection-lab
git init
mkdir -p detector rules tests/fixtures data/raw data/labeled results writeup .github/workflows

# requirements.txt
pytest>=8.0

# .gitignore
__pycache__/
*.pyc
.pytest_cache/
data/raw/
*.db
*.sqlite
*.pcap
.venv/
```

**GitHub side:** create a PUBLIC repo named `detection-lab` (public = portfolio;
there is nothing sensitive here). Add the Actions workflow below as
`.github/workflows/ci.yml` — this is your "autograder":

```yaml
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: pytest -v
```

**Commit discipline (your checkpoint system):** commit at the end of every module with
the message format `module N: <imperative description>`. Never let CI go red on `main` —
fix forward before starting the next module. Small commits inside a module are fine;
the module boundary commits are the ones an interviewer skims.

---

## 3. LAB ENVIRONMENT SETUP (Module 1)

You already have most of this — this module is verification, not new work.

1. VMware Workstation, **host-only network** (e.g., `vmnet1`, 192.168.XX.0/24). No NAT to
   your home network for the target. Verify: from Kali, `ping <target>` works; target
   cannot reach your home router.
2. **Target = Ubuntu Server or Desktop VM.** Install & enable SSH (`sudo apt install openssh-server`),
   confirm `sshd` logs to `/var/log/auth.log` (default on Ubuntu). Set a real user +
   create 6–8 decoy users for spraying (`sudo useradd` each, no passwords needed).
3. **Kali = attacker.** Tools needed: `nmap`, `hydra`. Password list: make your own
   `passwords.txt` (~50 entries, real target password somewhere in the middle).
4. **Suricata on the target** (`sudo apt install suricata`), enabled on the host-only
   interface, writing alerts to `/var/log/suricata/eve.json`. Use the ET Open ruleset
   (default). Verify: an `nmap -sS` sweep produces alerts in `eve.json`.
5. **Wireshark** on either VM to capture one attack run for the writeup screenshots.

**Acceptance:** one Wireshark screenshot + one `eve.json` alert + matching `auth.log`
lines from the same Nmap scan, pasted into `writeup/module1_verification.md`.

---

## 4. DATA GENERATION & GROUND TRUTH (Module 2)

This module produces everything the detector will be scored against. **Order matters:**
benign first, attacks second, evasive last — so log windows don't blur together.

For every attack run, record in `writeup/run_journal.md`:
```
RUN 03 — hydra brute force
command : hydra -l rohan -P passwords.txt ssh://192.168.XX.10 -t 4
start   : 2026-10-19T19:02:11-05:00   (run `date -Is` on TARGET before starting)
end     : 2026-10-19T19:04:47-05:00
result  : success on password #31 — TARGET PASSWORD CHANGED after run (note new one)
```

**Benign activity (≥ 30 min spread):** normal SSH logins, `sudo` usage, a few genuine
fat-finger failed logins (1–2 per session), a scripted loop of *successful* logins
(`for i in $(seq 1 12); do ssh target true; sleep 20; done`) — this is your engineered
false-positive candidate: successes, but anomalous-looking rhythm.

**Attack runs:**
| ID | Attack | Command sketch | What it must teach the detector |
|----|--------|----------------|--------------------------------|
| A1 | Nmap SYN scan | `nmap -sS -p 1-1000 <target>` | Not an auth attack — must NOT fire auth alerts (background noise discipline) |
| A2 | Brute force | `hydra -l rohan -P passwords.txt ssh://target -t 4` | Volume per IP per window |
| A3 | Password spray | `hydra -L users.txt -p Spring2026! ssh://target -t 4` | Breadth: 1 password, many users, from one IP |
| A4 | Low-and-slow | `hydra -l rohan -P tiny.txt ssh://target -t 1 -W 45` spread over ~45 min | Same IP+user, below volume threshold, over long window |

**Labels:** after all runs, copy `auth.log` to `data/raw/auth_full.log`, `eve.json` to
`data/raw/eve_full.json`, then hand-build `data/labeled/labels.json`:

```json
{
  "attacks": [
    {"id": "A2", "type": "brute_force", "technique": "T1110.001",
     "source_ip": "192.168.XX.5", "start": "...", "end": "..."},
    {"id": "A3", "type": "password_spray", "technique": "T1110.003", ...},
    {"id": "A4", "type": "low_and_slow", "technique": "T1110.001", ...}
  ],
  "benign_windows": [
    {"start": "...", "end": "...", "note": "scripted success loop (should be FP candidate)"}
  ]
}
```

Then extract **small sample files** (`data/labeled/sample_auth.log`, ~200 lines,
one of each attack type + benign) for committed tests.

**Acceptance:** 4 attack runs + benign baseline in journal; `labels.json` complete;
`sample_auth.log` checked in; `pytest tests/test_data_integrity.py` passes (a stub test
you write: sample log parses to ≥ N events, every label window overlaps real log lines).

---

## 5. THE CODE — MODULES 3–8

Below are the stubs. **Type hints and docstrings are the spec.** Implement bodies only.
Each function is one focused unit; if you reach for more than ~25 lines in one function,
split it.

### Module 3 — `detector/models.py` (data structures, ~30 min)

```python
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class AuthEvent:
    """One parsed line of auth.log."""
    ts: datetime          # event timestamp
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
```

**Acceptance:** `python -c "from detector.models import AuthEvent, Alert"` imports clean;
instantiate one of each in a REPL.

### Module 4 — `detector/parser.py` (normalization, ~2–3 hrs)

```python
def parse_line(line: str) -> AuthEvent | None:
    """Parse one auth.log line. Return None for lines we don't care about
    (e.g. 'Accepted publickey', cron, non-SSH daemons — YOU decide and document
    which lines you keep and why). Must handle: missing fields, malformed lines,
    lines from other services. Never raise on bad input — SOC parsers eat garbage daily."""

def parse_file(path: str) -> list[AuthEvent]:
    """Parse a whole file, sorted by timestamp. Skip unparseable lines silently
    but COUNT them; expose the count via parse_stats()."""

def parse_stats() -> dict:
    """Return {'parsed': int, 'skipped': int, 'malformed_examples': list[str]}
    (last 5 skipped lines, for debugging)."""
```

**Tests to write (tests/test_parser.py):** valid `Accepted password` line; valid `Failed
password` line; a `sudo:` line (should be None); a truncated line (None, no raise);
empty string; a file of 50 lines with 3 junk lines → 47 events, stats correct.

**Acceptance:** all parser tests green; module commit.

### Module 5 — `detector/detect.py` (the rules, ~4–6 hrs — the heart)

```python
def detect_brute_force(events: list[AuthEvent],
                       window_sec: int = 300,
                       threshold: int = 5) -> list[Alert]:
    """FAILED logins from ONE source_ip, count >= threshold within window_sec.
    Sliding window (not fixed buckets) — that's the part most candidates get wrong.
    technique='T1110.001'. Severity: scale with count (document your mapping)."""

def detect_password_spray(events: list[AuthEvent],
                          window_sec: int = 600,
                          threshold: int = 5) -> list[Alert]:
    """FAILED logins from one source_ip spread across >= threshold DISTINCT usernames
    within window. Each individual user fails only a few times — that's what separates
    spraying from brute force and what makes A3 fire here but (ideally) NOT in
    detect_brute_force. technique='T1110.003'."""

def detect_low_and_slow(events: list[AuthEvent],
                        window_sec: int = 3600,
                        threshold: int = 10) -> list[Alert]:
    """>= threshold FAILED logins for the SAME (source_ip, username) pair inside a LONG
    window, where no short-window brute force fired. Catch A4. technique='T1110.001'.
    Hint: reuse your sliding-window helper from brute force — factor it out."""

def run_all(events: list[AuthEvent], config: dict) -> list[Alert]:
    """Run all three rules, dedupe overlapping alerts (a run may fire two rules —
    keep the higher-severity one and note the other in description), return sorted by
    first_seen."""
```

Design hint (this is the CS61B "abstract data type" moment): write one private helper
`_sliding_window_events(events, key_fn, window_sec)` that yields groups — brute force and
low-and_slow are the same algorithm with different keys and windows. Three rules should
be ~10 lines each *because* the helper exists.

**Tests (tests/test_detect_*.py):** build synthetic event lists with a small factory
helper `ev(ts_offset_sec, ip, user, ok=False)` you write in `tests/conftest.py`:
- 6 failures in 60s from one IP → exactly one brute-force alert; 4 failures → none.
- 5 distinct users, 1 failure each, one IP, 2 min → spray alert fires; brute force does not.
- 12 failures same user/IP spread across 50 min → low-and-slow fires; brute force does not.
- Benign success loop → nothing fires anywhere.
- A2-style dense volume triggers brute force; run_all dedupes.

**Acceptance:** all detection tests green **on synthetic events** — you are not allowed
to touch real lab data until Module 7. Commit.

### Module 6 — `detector/evaluate.py` + the tuning table (~3–4 hrs)

```python
def evaluate(alerts: list[Alert], labels: dict) -> dict:
    """Score against labels.json:
    TP = alert whose (source_ip, time-window) overlaps a same-type attack label.
    FN = an attack label with no matching alert.  FP = alert matching nothing.
    Return {'tp': int, 'fp': int, 'fn': int,
            'precision': float, 'recall': float, 'per_attack': {...}}"""

def tune(events: list[AuthEvent], labels: dict,
         param_grid: list[dict]) -> list[dict]:
    """For each config dict in param_grid, run_all + evaluate; return rows:
    {'config': {...}, 'tp':..., 'fp':..., 'fn':..., 'precision':..., 'recall':...}"""
```

Then the deliverable: `results/tuning_table.md` — run ≥ 6 configs, e.g. brute-force
threshold ∈ {3, 5, 10} × window ∈ {120, 300, 900}. Markdown table of results + 5-sentence
analysis: *which config would you deploy, what does it miss, what does it over-fire on?*
**This table is the single best artifact in the project — spend real thought on the
paragraph.**

**Acceptance:** table committed; at least one config achieves recall=1.0 on A2/A3 with
documented FP cost; A4 (low-and-slow) correctly shows why short windows alone fail.

### Module 7 — Real-data validation + Suricata correlation (~3–4 hrs)

1. Run your CLI (`python -m detector --log data/raw/auth_full.log --labels
   data/labeled/labels.json`) against the FULL lab data. Results must roughly match
   sample-log behavior; investigate any divergence — that's a writeup paragraph.
2. `detector/correlate.py`:

```python
def load_suricata_alerts(path: str) -> list[dict]:
    """Parse eve.json; keep only records where event_type == 'alert';
    return [{'ts': datetime, 'src_ip': str, 'signature': str, 'gid': int, 'sid': int}]"""

def correlate(alerts: list[Alert], suri: list[dict],
              window_sec: int = 300) -> list[dict]:
    """For each Alert, find Suricata alerts from the same src_ip within +/- window_sec.
    Return [{'alert': Alert, 'nids_signatures': [...], 'correlated': bool}].
    A detection backed by BOTH auth.log evidence and an IDS signature is your
    'escalate with confidence' case."""
```

**Acceptance:** A2 run correlates with an ET brute-force signature; A1 (Nmap) appears in
Suricata but produces NO auth alerts — cite both in the writeup as evidence of noise
discipline.

### Module 8 — SQLite mini-SIEM + Sigma (~3–4 hrs)

```python
# detector/db.py
def init_db(path: str) -> sqlite3.Connection          # alerts + events tables, schema in docstring
def insert_alerts(conn, alerts: list[Alert]) -> None  # parameterized, no string-built SQL
def insert_events(conn, events: list[AuthEvent]) -> None

# analyst queries — each is 1 SQL statement, tests assert exact results on fixture data
def top_source_ips(conn, limit: int = 10) -> list[tuple]          # by failed-login count
def alerts_by_technique(conn) -> list[tuple]
def hourly_failed_logins(conn) -> list[tuple]                     # timeline buckets
```

**Acceptance:** fixture DB in `tests/fixtures/`; each query tested. **Interview bonus:**
be ready to write `top_source_ips` live in a shared doc — it's a `GROUP BY` + `ORDER BY`
+ `LIMIT`.

**Sigma (rules/ssh_bruteforce.yml):** hand-write a Sigma rule expressing your best
brute-force config (logsource: ssh/auth; detection: aggregation on source IP of failed
logins ≥ threshold in window; tags: attack.t1110.001). Add a README note: "logic
identical to detect.py — Sigma describes, Python evaluates; that's why you need both."
Validation: pip install `sigma-cli` and run the check, or paste into a Sigma validator
online; record the result in the writeup.

---

## 6. SHIPPING (Module 9 — README, ~3–4 hrs)

README structure (each section = a checkbox):
1. **TL;DR** — 3 sentences + tuning table preview + CI badge.
2. **Architecture** — the diagram from §0, redrawn.
3. **Lab setup** — Module 1 condensed: someone could rebuild it in an afternoon.
4. **Detection logic** — one short paragraph per rule + the ATT&CK mapping table.
5. **Results** — tuning table, real-data validation, Suricata correlation evidence,
   Wireshark screenshots (2–3, annotated).
6. **Limitations — the section that gets you hired.** Write honestly: single-source-IP
   assumption (real spraying is distributed — your detector can't see it from one host's
   logs; say so), UDP/DNS blind spots, threshold transferability, what you would build
   next (Sysmon/Windows events, JA3, Kerberos 4771 pre-auth fails).
7. **How to run** — clone, pip install, pytest, CLI example.

Final commit: `module 9: README with results, tuning analysis, and limitations`.
Pin the repo on your GitHub profile. Link it from LinkedIn featured section and resume.

---

## 7. COMMIT CHECKPOINT MAP (print this)

| # | Commit message | Gate before moving on |
|---|---|---|
| 0 | `module 0: repo skeleton, CI workflow, gitignore` | CI runs (may have no tests yet) |
| 1 | `module 1: lab environment verified` | verification doc with 3 evidence items |
| 2 | `module 2: attack runs, labels, sample data` | journal complete; data-integrity test green |
| 3 | `module 3: data models` | import + instantiation check |
| 4 | `module 4: auth.log parser with stats` | 7+ parser tests green |
| 5 | `module 5: three detection rules + dedupe` | all synthetic detection tests green |
| 6 | `module 6: evaluation harness + tuning table` | ≥6-config table + analysis paragraph |
| 7 | `module 7: real-data validation + suricata correlation` | A2 correlates; A1 stays silent in auth |
| 8 | `module 8: sqlite storage + analyst queries + sigma rule` | query tests green; sigma validated |
| 9 | `module 9: README with results and limitations` | a stranger could rebuild the lab from README |

---

## 8. DEFENSE PREP (for every module, drill these)

- **M4:** "Why drop publickey lines?" / "What do you do about a log that's 40% garbage?"
- **M5:** "Why sliding window vs. fixed buckets?" (fixed buckets split an attack across
  two buckets and miss it — draw it). / "Why does spraying evade brute-force detection?"
- **M6:** "What does precision/recall trade-off mean at 3 a.m. with a 500-alert queue?"
- **M7:** "When would you escalate WITHOUT Suricata agreement?" / "Nmap isn't an attack
  on auth — why is it in your dataset?" (noise discipline)
- **M8:** "Write top_source_ips in SQL, live." / "Why Sigma AND Python?"
- **M9:** "What's the biggest limitation?" — answer instantly, without defending.
  Hesitating here is the only wrong answer.
