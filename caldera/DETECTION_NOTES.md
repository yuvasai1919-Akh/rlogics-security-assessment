# Detection ideas for the benign operation (fill in with what you actually observe)

| Behaviour | Where it shows up | Example detection logic (pseudo) | Expected noise |
|-----------|-------------------|----------------------------------|----------------|
| Discovery burst: `whoami`, `uname`/`hostname`, `ps` within 60 s from the same parent | Process creation logs (auditd/Sysmon/EDR) | `>=3 distinct discovery binaries` with the **same parent PID** inside 60 s, parent not in an admin-tool allow-list | Admins, config management, monitoring agents -> allow-list by parent and user |
| Binary executed from a writable temp path | Process creation + file create | image path under `/tmp`, `/dev/shm`, user home AND file created < 5 min earlier | Installers, CI runners |
| Regular HTTP POST beaconing to an internal host:8888 | Network flow / proxy | low-variance interval, small bodies, same destination, non-standard port | Health checks, telemetry agents |
| Agent -> shell -> utility lineage | Process tree | grandparent is an unknown long-running process with network connections | Legit orchestrators |

Record for each: **fired / did not fire / fired late**, time-to-detect, and the change you would make.
Remember that single discovery commands are normal; the signal is the *sequence and context*.
