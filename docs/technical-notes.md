# Detection Lab — Technical Notes

Personal reference doc. Breaks down what each command, config change, and rule actually does, piece by piece — for building real understanding, not just copy-pasting. Organized by module, same sequence as the devlog.

---

## Module 1: Lab Environment Setup & Verification

### SSH service

```bash
sudo systemctl enable --now ssh
```
- `systemctl` — the tool that controls services (start/stop/enable/check status) on modern Linux (via `systemd`, the system/service manager).
- `enable` — tells the system to start this service automatically on every future boot (writes a symlink so it's included at startup).
- `--now` — also starts it immediately, in this one command, instead of only taking effect on next reboot.
- `ssh` — the service name (the SSH daemon, `sshd`, is the actual running program).

```bash
sudo systemctl status ssh
```
- `status` — shows whether the service is active/inactive/failed, its process ID, recent log lines, and whether it's enabled for boot. The first thing to check whenever something "isn't working."

**Before fixing it, confirmed the package was actually there at all:**
```bash
dpkg -l | grep openssh-server
```
- `dpkg -l` — lists every package currently installed via Debian's package manager (which Ubuntu is built on).
- `| grep openssh-server` — pipes that full list through `grep` to filter down to just the one package name of interest, instead of scrolling through hundreds of installed packages manually.
- A line starting with `ii` means "installed and configured correctly." No output at all would mean it was never installed in the first place — which would've meant a different fix (`apt install openssh-server`) instead of just starting the service.

### Suricata interface fix

```bash
sudo sed -i 's/eth0/ens33/g' /etc/default/suricata
```
- `sed` — a stream editor; reads a file and applies find/replace (or other text transformations) to it.
- `-i` — "in place": writes the change directly back to the file, instead of just printing the result to the screen.
- `'s/eth0/ens33/g'` — the substitution command itself: `s` = substitute, `/eth0/` = pattern to find, `/ens33/` = replacement, `g` = "global" — replace every match in the file, not just the first one.
- `/etc/default/suricata` — this file holds startup-level settings Suricata's init/systemd script reads before launching — in this case, which network interface to monitor.

```bash
sudo sed -i 's/interface: eth0/interface: ens33/' /etc/suricata/suricata.yaml
```
- Same `sed` mechanics, but the pattern is more specific (`interface: eth0` instead of bare `eth0`) because this file is Suricata's main YAML config, and `eth0` appears elsewhere in it (comments, examples) that shouldn't be touched — only the live `interface:` setting should change.
- `/etc/suricata/suricata.yaml` — Suricata's primary configuration file: detection settings, logging output paths, which interface(s) to capture on, which rule files to load, etc.

### Netplan (networking)

```bash
sudo netplan apply
```
- `netplan` — Ubuntu's current network configuration system (replaced older tools like `dhclient`/`ifupdown` on newer versions).
- `apply` — re-reads netplan's config files (YAML files under `/etc/netplan/`) and pushes the resulting network state live — this includes requesting a new DHCP lease if the interface is configured for DHCP.

```bash
ip -br addr
```
- `ip` — the modern Linux networking command (interfaces, routing, addresses).
- `addr` — show address information for network interfaces.
- `-br` — "brief" output: one compact line per interface (name, state, IP) instead of the full verbose dump.

### Decoy user accounts

```bash
for user in jsmith mgarcia dwilson klee tpatel rjones abrown; do sudo useradd -m $user; done
```
- `for user in name1 name2 ...; do ... ; done` — a bash loop: runs the command between `do` and `done` once per item in the list, with `$user` standing in for whichever name is current on that pass.
- `useradd -m $user` — creates a new user account; `-m` also creates a home directory for them (e.g. `/home/jsmith`), which makes the account look like a normal, real user rather than a bare system entry.
- Looping this way creates several accounts with one command instead of running `useradd` seven separate times.

**What went wrong pasting this:** when a multi-line version of this loop got pasted into the terminal one line at a time, bash treated each line as a separate command typed live. Because it hadn't seen the closing `done` yet, bash kept the loop "open" and waiting (shown by a `>` continuation prompt), and in the process a few of the loop's own syntax words — `for`, `user`, `in` — ended up getting typed in as if they were names in the list, which caused `useradd` to actually create accounts literally named `for`, `user`, and `in`.

```bash
sudo userdel -r for
```
- `userdel` — deletes a user account.
- `-r` — also removes that user's home directory and mail spool, so nothing is left behind.
- A "mail spool not found" message during this is harmless — it just means that account never had a mail file to begin with (expected, since it was never a real, logged-in user).
- Repeated for `user` and `in` to fully clean up the three accidental accounts.

```bash
cut -d: -f1 /etc/passwd | tail -10
```
- `/etc/passwd` — the system file listing every user account, one per line, with fields separated by colons (`:`) — username, UID, home directory, shell, etc.
- `cut -d: -f1` — `-d:` sets the delimiter to colon, `-f1` extracts just the first field from each line — in this case, just the username, dropping everything else.
- `tail -10` — shows only the last 10 lines of that output, since `/etc/passwd` also lists many unrelated system accounts (like `sshd`, `landscape`) that aren't relevant here — this keeps the view focused on the most recently created accounts.

### Suricata rules — installing a ruleset

```bash
sudo suricata-update
```
- `suricata-update` — Suricata's official companion tool for downloading, merging, and enabling detection rule sets (it does NOT write detection logic itself — it manages rule *files* from external sources).
- Running it with no extra flags uses whatever sources are already configured (by default, Emerging Threats Open — a free, community-maintained set of detection signatures) and rebuilds the active ruleset.

```bash
sudo suricata-update update-sources
```
- `update-sources` — specifically refreshes `suricata-update`'s internal index of *available* rule sources (not the rules themselves) — needed once before sources like `et/open` can be resolved and downloaded.

```bash
sudo suricata-update enable-source et/open
```
- `enable-source` — turns on a specific named rule source.
- `et/open` — shorthand ID for "Emerging Threats, Open" ruleset — the free tier of a well-known, widely used signature set covering a broad range of exploit, malware, and policy-violation patterns.
- **What happened the first time this ran:** it succeeded, but printed a warning — `Source index does not exist, will use bundled one... Please run suricata-update update-sources`. That's the tool telling you it fell back to an older, pre-packaged index instead of the current one, and that you should go fetch the real index yourself. This is why `update-sources` (above) is listed as its own step rather than assumed — the tool will technically still run without it, just potentially against stale source info.

**Diagnosing why "enabling" the scan category did nothing:**

After adding `enable-category: scan` (intended to switch on an entire category of rules the ruleset ships but doesn't turn on by default) and re-running `suricata-update`, the output said `Enabled 0 rules` — no error, just nothing happening. Two checks confirmed why:

```bash
ls -la /etc/suricata/update.yaml
```
- Printed "No such file or directory." The config file that was supposed to hold `enable-category: scan` had never actually been created — an earlier step meant to create it had been skipped. `suricata-update` wasn't ignoring the setting; there was no file for it to read in the first place. Lesson embedded here: "the command ran with no errors" and "the command did what I intended" are two different claims — worth checking the actual file/state, not just the exit behavior.

```bash
echo 'enable-category: scan' | sudo tee /etc/suricata/update.yaml
```
- Same `tee` pattern as before, but without the `-a` (append) flag this time — because the file didn't exist yet, there was nothing to append to; this creates it fresh.

Even after the file genuinely existed, running `suricata-update` again still showed `Enabled 0 rules` and `No changes detected, exiting`. That ruled out "the file was missing" as the (only) explanation — the category itself apparently had nothing left to enable, meaning Emerging Threats Open doesn't ship extra disabled scan-category rules waiting to be turned on. Confirmed this directly rather than assuming it:

```bash
grep -i "nmap\|portscan\|port scan" /var/lib/suricata/rules/suricata.rules | grep -v "^#" | wc -l
```
- `grep -i` — case-insensitive text search.
- `"nmap\|portscan\|port scan"` — the `\|` inside the pattern means OR; match any line containing any of these three phrases.
- `grep -v "^#"` — a second grep, inverted (`-v` = exclude matches): drop any line starting with `#` (a comment), since commented-out rules aren't actually active.
- `wc -l` — count the lines that made it through both filters.
- Result: 28 matches — but reading a few of them (same command without `wc -l`, piped to `head -3` instead) showed every one was a rule for a specific, named product vulnerability that happened to mention "nmap" in its description or reference link (e.g., a rule about a specific exploit tool that uses Nmap's scan engine internally) — not a generic "someone is scanning my ports" rule. That's what confirmed writing a custom rule was actually necessary, not just a config toggle away.

**Re-downloading the rule source needed internet again:**

Since the target VM was already switched to host-only (no internet) by this point, running `update-sources` to properly refresh things failed outright — `failed to download index`. Same underlying issue as the very first Suricata install: anything that needs to reach the internet (downloading a package, downloading a rule-source index) requires briefly switching the adapter back to **NAT**, confirming connectivity, doing the download, then switching back to **host-only** afterward. This ended up happening twice across the module — once for the initial `suricata` package install, once here — which is worth remembering as a recurring pattern rather than a one-off: any future step that needs something from the internet will hit the same wall while isolated, by design.

### Suricata rules — custom rule for port scans

**The custom rule itself:**
```
alert tcp any any -> $HOME_NET any (msg:"Possible TCP Port Scan Detected"; flags:S; threshold: type threshold, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:1000001; rev:1;)
```
Breaking down every piece:
- `alert` — the action Suricata takes when this rule matches (log it as an alert, vs. silently `pass` or `drop`).
- `tcp` — the protocol this rule inspects.
- `any any ->` — source IP `any`, source port `any`, `->` means "traffic going toward" (direction).
- `$HOME_NET any` — destination: `$HOME_NET` is a Suricata variable representing "the network(s) I'm protecting" (defined elsewhere in `suricata.yaml`, which in this setup resolves to the target's own network), destination port `any`.
- `(...)` — the rule's options, in order:
  - `msg:"..."` — the human-readable description that shows up in the alert log.
  - `flags:S` — only match packets with the **SYN** flag set (the first packet of a TCP handshake — "I'd like to connect") — this is exactly what a SYN/stealth scan sends repeatedly, without ever completing a real connection.
  - `threshold: type threshold, track by_src, count 10, seconds 60` — don't alert on every single matching packet; instead, only alert once a single source IP (`track by_src`) sends at least 10 matching packets (`count 10`) within a 60-second window (`seconds 60`). This is what turns "one SYN packet" (completely normal) into "10+ SYN packets from one place in a minute" (suspicious) — the actual logic that makes this a *scan* detector instead of a *connection* detector.
  - `classtype:attempted-recon` — a standard Suricata category label meaning "this looks like reconnaissance activity" (probing/mapping a target, not yet an active exploit).
  - `sid:1000001` — the rule's unique Signature ID. Numbers below 1,000,000 are reserved for official rule sets; 1,000,000+ is the conventional range for custom/local rules, specifically so they never collide with IDs from downloaded rulesets.
  - `rev:1` — revision number, for tracking changes to this exact rule over time (bump it if you edit the rule later).

**Where the file had to live:**
- Rule files referenced in `suricata.yaml`'s `rule-files:` list are resolved relative to Suricata's **default rule path**, which is `/var/lib/suricata/rules/` — this is where `suricata-update` places the compiled, ready-to-load ruleset.
- This is a different directory from `/etc/suricata/rules/`, which is where the *source/distribution* rule files live before processing. Easy to mix up since both sound like "the rules folder" — the practical distinction is `/etc/` generally holds source config, `/var/lib/` holds the built/active data a program actually reads from at runtime.
- **What actually went wrong:** `local.rules` was first created at `/etc/suricata/rules/local.rules` (the natural-feeling place, next to Suricata's other config). But testing the config (`suricata -T`) failed with `No rule files match the pattern /var/lib/suricata/rules/local.rules` — proof the file existed, just in the wrong directory for how `rule-files:` resolves paths. Fixed with a plain copy:

```bash
sudo cp /etc/suricata/rules/local.rules /var/lib/suricata/rules/local.rules
```
- `cp source destination` — copies a file. No flags needed here since it's a single, small text file. (A symlink, `ln -s`, would've been an alternative — keeping one "real" copy and a pointer to it in the second location — but a plain copy is simpler and fine for a file this small that doesn't change often.)
- The general lesson underneath this: when a tool says "no files match this pattern," the pattern itself (the full path) is telling you exactly where it's looking — worth reading literally rather than assuming the file being *somewhere* is good enough.

```bash
sudo sed -i '2153a\  - local.rules' /etc/suricata/suricata.yaml
```
- `2153a\...` — `sed`'s "append" command: insert the given text as a new line immediately **after** line 2153 in the file. Useful when you know the exact line number (from a prior `grep -n`) and want a precise, scriptable insertion instead of manually editing in a text editor.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```
- `-T` — "test mode": validates the config and all referenced rule files for syntax errors, then exits, without actually starting Suricata as a running service. The safe way to catch a typo before restarting something that's supposed to stay running continuously.
- `-c /path` — explicitly points at which config file to validate (in case there's ever more than one on a system).

### Checking logs and verifying

```bash
sudo journalctl -u suricata -n 50 --no-pager
```
- `journalctl` — reads the systemd journal (the centralized log system most modern Linux services write to).
- `-u suricata` — filter to just logs from the `suricata` service/unit.
- `-n 50` — show the last 50 lines only.
- `--no-pager` — print directly to the terminal instead of opening an interactive scrollable viewer (which can be awkward to copy text out of).

```bash
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json
```
- `grep` — searches text for lines matching a pattern.
- `'"event_type":"alert"'` — Suricata's `eve.json` log file holds many kinds of events (DNS queries, flow summaries, alerts, etc.) as one JSON object per line; this filters down to only the lines that are actual *alerts* (something a rule matched), ignoring routine traffic logging.
- `/var/log/suricata/eve.json` — Suricata's structured event log, in JSON-lines format (one JSON object per line) — built specifically to be machine-parseable, unlike the more human-readable `fast.log`.

### Wireshark capture filter

**First attempt — caught the wrong traffic:**
```
ip.addr == 192.168.233.128 && tcp.flags.syn == 1
```
- `ip.addr == ...` matches a packet if *either* its source or destination is that address — it doesn't specify direction. Combined with the target's own background DNS retry traffic also happening to use SYN-like repeated attempts during the capture window, this filter pulled in over 2,000 results that were mostly the target repeatedly failing to reach a DNS server — not the scan at all. The giveaway on review: the Source column showed the *target's* IP, not Kali's, meaning traffic was flowing the wrong direction for this to be Kali scanning the target.

**Corrected filter — isolates just the actual scan:**
```
ip.src == 192.168.233.129 && ip.dst == 192.168.233.128 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```
- `ip.src == ...` / `ip.dst == ...` — unlike `ip.addr`, these specify an exact direction: source must be Kali, destination must be the target. This is the key fix — it rules out any traffic going the other way, like the target's own DNS lookups.
- `tcp.flags.syn == 1` — only show packets with the SYN flag set (handshake-opening packets).
- `tcp.flags.ack == 0` — exclude packets that *also* have the ACK flag set — this is what separates "a fresh connection attempt" (SYN only) from "part of an already-established connection" (SYN-ACK, which has both flags).
- `&&` — logical AND; all conditions must be true for a packet to show.
- Lesson embedded here: `==` on an address field can silently mean "either side," not "this specific side" — worth checking which variant (`ip.addr` vs. `ip.src`/`ip.dst`) actually matches the intent before trusting a filtered result.

### Suricata detection-pipeline shape

Worth having written down as a mental model: Suricata reads raw packets off a network interface → checks them against **loaded rules** (which is just a big list of pattern/threshold conditions like the one above) → for anything that matches, writes a structured entry to `eve.json`. No rules loaded = packets still get *seen*, but nothing ever gets logged as an alert, since there's nothing to compare against. That's the core reason the scan went undetected for as long as it did — the pipeline worked the whole time, it just had nothing to check traffic against until a relevant rule existed.

---

*Will keep extending this through Module 2 (Hydra brute-force, auth.log analysis) and beyond — same format: command/line, then what each piece does.*
