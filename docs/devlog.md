# Detection Lab — Devlog

Running log of what got built, what broke, and what I learned along the way. Kept in sequence, module by module, so it doubles as source material for write-ups and LinkedIn posts later.

---

## Module 1: Lab Environment Setup & Verification

**Goal:** Stand up an isolated target VM and attacker VM, get SSH and Suricata running on the target, and prove the whole pipeline actually captures and detects activity before building anything that depends on it.

### Sequence of what happened

**1. Started clean instead of reusing an old VM**
Had an existing `ubuntu-wazuh` VM lying around, but decided against reusing it. Any pre-existing SIEM tooling on there would've generated background noise I couldn't fully account for, and the whole point of this lab is being able to explain *every* log line. Built a fresh Ubuntu Server 24.04 VM instead — lighter, no GUI overhead, nothing running that I didn't put there myself.

**2. SSH was installed but not running**
Enabled OpenSSH during the Ubuntu install, but a first check showed the service as inactive. Turned out it was installed correctly, just never started or enabled for boot. One command (`systemctl enable --now ssh`) fixed both at once. Small thing, but a good reminder to actually verify a service is live, not just assume the install flag did its job.

**3. Suricata installed but failed to start — wrong network interface**
Installed Suricata, and it immediately crash-looped on startup. The logs pointed at the issue directly: it was trying to listen on an interface called `eth0`, which doesn't exist on this machine (Ubuntu now names interfaces things like `ens33`). Suricata's default config ships assuming the old naming convention. Updated both its config files to point at the correct interface name, and it came up clean.

**4. Isolating the target lost its network entirely**
Switched the target's network adapter from NAT (needed for installs) over to host-only, which is the actual isolation the lab requires. The interface came back up with no IPv4 address at all. Two issues stacked here: Ubuntu 24.04 doesn't ship the tool I expected (`dhclient`) anymore — it uses `netplan` instead — and even after switching tools, it took confirming that VMware's host-only network actually had DHCP turned on before the target could pull a fresh address. Got there by checking VMware's network settings directly rather than guessing.

**5. Built the Kali attacker VM**
Grabbed the official pre-built Kali VMware image rather than installing from ISO — faster, and it's the standard approach. Hit one throwaway snag: a stalled download that showed 100% complete in the browser but wouldn't finalize. A pause/resume cycle and a redownload sorted it. Set Kali to the same host-only network as the target, changed the default credentials, and confirmed it could reach the target.

**6. Decoy accounts, with a paste mishap**
Added several decoy user accounts to the target so `auth.log` would have realistic multi-user noise instead of just one obvious account. A multi-line command got pasted into the terminal one line at a time, which caused a few of the loop's own keywords to get created as literal usernames by mistake. Easy to spot (accounts named things like "for" and "in" stand out) and easy to clean up with `userdel`.

**7. Built the password wordlist**
Put together a ~50-entry wordlist for the brute-force work in Module 2, with the real account password buried mid-list rather than at the top or bottom — the goal being that the next module's tooling has to actually search for it.

**8. First scan + Wireshark capture — wrong traffic at first**
Ran an Nmap SYN scan from Kali against the target while capturing in Wireshark. First attempt at filtering the capture down actually isolated the *target's own background DNS traffic* instead of the scan — same subnet, so it was easy to grab the wrong direction of traffic at a glance. Tightened the filter to specifically match traffic sourced from Kali, destined for the target, which isolated the real scan cleanly.

**9. Suricata saw the scan but didn't flag it — no detection rules installed**
Checked Suricata's alert log after the scan: nothing. Turned out a fresh Suricata install ships with zero actual detection rules — just protocol parsers. Pulled in the Emerging Threats Open ruleset (the standard free baseline, ~53,000 signatures) via `suricata-update`, which needed a brief, temporary switch back to NAT for internet access before isolating the target again.

**10. Still no alert on the scan — no built-in rule for generic port scans**
Even with ~53,000 rules loaded, the scan still didn't trigger anything. Tried to turn on a built-in "scan" rule category — but that meant creating a small config file to tell the rule-updater which categories to enable, and the step that actually creates that file got skipped the first time around. The updater ran fine, just silently had nothing new to turn on, which looked like a dead end until double-checking confirmed the config file flat-out didn't exist yet. Created it properly on the second pass.

**11. Confirmed the real issue — no generic scan rule exists in the public ruleset at all**
Even once the config file existed, re-running the rule update still showed zero newly-enabled rules. Rather than guess, searched the actual loaded ruleset directly for anything mentioning scanning or Nmap. Found matches, but every one of them turned out to be a rule for a *specific product exploit* that happened to reference Nmap as a tool — not a generic "someone is scanning me" detection. Confirmed what this pointed to: public rulesets like this one intentionally leave bare port-scan detection out by default, since it's considered too common and noisy to alert on without tuning for a specific environment.

**12. Wrote a custom detection rule — then hit a file-path mismatch**
With no existing rule to rely on, wrote a small one from scratch: flag any source sending 10+ connection-opening packets to the target within 60 seconds. Pulling in that rule's source also meant going back online briefly a second time (host-only has no internet, and downloading the rule-source list needed it) — the same NAT-then-host-only dance as before, just for a different reason this time. Once the rule itself was written, testing the config turned up one more snag: the rule file had been placed in the directory that holds Suricata's *source* config, but the setting that loads custom rule files actually looks in a separate directory where Suricata keeps its *active*, already-processed ruleset. A straightforward copy to the right location fixed it.

**13. Re-ran the scan — clean detection**
With the custom rule active, re-ran the same scan. Suricata alerted correctly, tagged with the right source and destination, lining up with the Wireshark capture. One side note worth keeping: the rule also picks up the target's normal background DNS retry traffic, since that traffic technically matches the same "lots of connections quickly" pattern. Not a bug — just a reminder that a simple threshold rule can't fully distinguish "scan" from "any bursty traffic," and that's worth being upfront about rather than treating the rule as airtight.

---

## Running list of lessons learned

- Verifying a service is actually *running*, not just installed, is its own step — don't assume a checkbox during setup did its job.
- Default configs often assume older system conventions (e.g. `eth0`) that modern systems have moved past (e.g. `ens33`) — when a service won't start, checking whether a config value matches what's actually on the system is a fast first move.
- Switching a VM's network mode means it may need to request a new address on the new network — that's not always automatic, and the tool expected for doing so can vary by OS version.
- Pasting multi-line commands one line at a time can cause partial/garbled execution — worth checking results rather than assuming a block executed as one unit.
- A fresh IDS install doesn't come pre-armed with detection logic — rules have to be sourced and loaded deliberately, and even a large general ruleset may skip "obvious" detections like basic port scanning because they're considered too noisy by default.
- A detection rule that works doesn't mean it's precise — testing it against real traffic surfaced that it also flags legitimate background noise, which is useful to know and disclose rather than something to quietly ignore.
- When a change "does nothing" with no error message, it's worth confirming the setup step for it actually completed, rather than assuming the mechanism itself is broken — in this case a config file was just never created, not misconfigured.
- Isolating a machine from the internet and needing to briefly reconnect it for an update is a normal, recurring part of the workflow in a lab like this, not a one-time setup step — worth planning for rather than treating each instance as a surprise.

---

*Log will continue through Module 2 (brute-force detection) and beyond.*
