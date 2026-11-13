Window start (target): 2026-10-28T14:51:19+00:00
## Benign baseline
start   : 2026-10-28T18:14:17+00:00
end     : 2026-10-28T19:18:25+00:00
result  : 5x interactive login+sudo check, 1-2 fat-finger failed logins (typo'd username),
          12x scripted successful login loop (150s interval, ~30min) via nohup — engineered
          FP candidate per spec

RUN A1 — nmap SYN scan
command : nmap -sS -p 1-1000 192.168.233.129
start   : 2026-10-28T19:18:25+00:00
end     : 2026-10-28T19:23:55+00:00
result  : only port 22/tcp (ssh) open, scan completed in ~5s, zero auth.log lines
          (noise-discipline control — confirmed clean)

RUN A2 — hydra brute force
command : hydra -l rohan -P passwords.txt ssh://192.168.233.129 -t 4
start   : 2026-10-28T19:26:20+00:00
end     : 2026-10-28T19:27:52+00:00
result  : success — password found in 49 attempts (full list exhausted essentially
          immediately, 4 parallel tasks), 1m32s wall time
          TARGET PASSWORD CHANGED after run — new password set below

RUN A3 — hydra password spray
command : hydra -L users.txt -p 'Spring2026!' ssh://192.168.233.129 -t 4
start   : 2026-10-28T19:32:34+00:00
end     : 2026-10-28T19:33:51+00:00
result  : 0/8 valid passwords found (expected) — 8 usernames x 1 password = 8 failed
          auth attempts from one source IP, 1m17s wall time
note    : "smoro" in users.txt was a typo (account created as "smore") — produced one
          extra "invalid user" failure line in A3, left as-is, harmless to detection logic

RUN A4 — hydra low-and-slow
command : while read pw; do hydra -l rohan -p "$pw" ssh://192.168.233.129 -t 1; sleep 270; done < tiny.txt
start   : 2026-10-28T19:43:36+00:00
end     : 2026-10-29T01:58:49+00:00
result  : 10/10 attempts completed, 0 valid password found, 9 usernames x 1 attempt
          each spaced ~270s apart as designed, EXCEPT attempt #10 — laptop/Kali VM
          suspended (closed laptop for work) between attempts #9 and #10, pausing the
          `sleep 270` mid-countdown; on resume, attempt #10 fired immediately rather
          than after the intended ~270s gap. Actual window ended up ~6h15m instead of
          the intended ~45min.
note    : labels.json A4 window set to the REAL observed start/end above, not the
          originally intended 45-min target. Window is still valid for low-and-slow
          detection (same attempt count, even more time-spread than planned) but the
          extra spread was caused by an uncontrolled environment variable (VM suspend),
          not deliberate test design — flagged here for honesty, see writeup methodology
          notes.
