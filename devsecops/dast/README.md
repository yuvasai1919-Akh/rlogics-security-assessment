# DAST - OWASP ZAP

## Safety rule (say this in the interview)
Active DAST sends attack payloads (injection strings, fuzzing, forced browsing). Against a system you
do not own or are not authorised to test, that is an attack: it can break the target, trigger
incident response, and be unlawful. Therefore:
- Baseline/passive scans only by default; **active scans only against systems you own or have written
  authorisation to test**, in an agreed window, ideally a non-production clone.
- Scope-lock the target (this lab uses a private Docker network and a localhost-only port).
- Never put production credentials in a scan context; use dedicated test accounts.

## Lab usage
The pipeline starts the app container on a private Docker network and runs:
```bash
docker run --rm --network lab-net -v "$OUT:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://lab-app:8000 -J zap-baseline.json -r zap-baseline.html
```
Exit codes: `0` no issues, `1` failures, `2` warnings, `3` error.

## Optional stretch: active scan against the lab app (authorised - it is yours)
```bash
docker run --rm --network lab-net -v "$OUT:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t http://lab-app:8000 -J zap-full.json -r zap-full.html -m 5
```
Expect it to find the SQL injection in `/user?name=` on the vulnerable build and not on the
remediated build - a good before/after.

## What baseline typically reports on this app (verify against your own report)
Missing security headers (CSP, X-Content-Type-Options, X-Frame-Options), information disclosure via
Server header, cache-control issues. The remediated app adds headers via `after_request`.
Baseline will **not** reliably find SQLi - that is the point to make about passive vs active, and
about why SAST and DAST complement each other.
