# scan_gate.py - Trivy JSON policy gate (Exercise 3, option A)

## Purpose
Trivy's built-in `--exit-code/--severity` is blunt: it cannot distinguish "critical with a fix
available" from "critical nobody can fix yet", cannot carry approved exceptions with expiry, and
produces nothing a developer can read quickly. This utility turns a Trivy JSON report into a
decision (BLOCK / WARN / EXCEPTED), a Markdown summary, an optional CSV, and an exit code.

## Inputs
| Flag | Meaning |
|------|---------|
| `--trivy FILE` (required) | Trivy JSON (`trivy fs|image --format json`) |
| `--fail-on SEV` | Minimum severity that blocks (default `CRITICAL`) |
| `--only-fixable` / `--no-only-fixable` | Block only vulnerabilities with a fixed version (default on) |
| `--fail-on-secrets` / `--no-fail-on-secrets` | Any secret blocks (default on) |
| `--exceptions FILE` | JSON list of time-boxed exceptions (id, reason, approved_by, expires) |
| `--markdown FILE`, `--csv FILE` | Extra outputs; Markdown is always printed to stdout |
| `--today YYYY-MM-DD` | Override date (tests/reproducibility) |

## Outputs and exit codes
`0` policy satisfied - `1` policy violated - `2` input error (unreadable/malformed/non-Trivy input,
invalid exceptions file). Malformed input **fails closed**: a broken scanner must not look like a
clean scan.

## Example
```bash
python3 scripts/scan_gate.py --trivy scripts/samples/trivy_critical_fixable.json; echo "exit=$?"   # 1
python3 scripts/scan_gate.py --trivy scripts/samples/trivy_critical_fixable.json \
        --exceptions scripts/samples/exceptions.json; echo "exit=$?"                                 # 0 (excepted)
python3 scripts/scan_gate.py --trivy scripts/samples/malformed.json; echo "exit=$?"                  # 2
```

## Tests
`make test-gate` (stdlib `unittest`, no dependencies). Covers the failure case (critical with fix),
the edge cases (unfixed critical, expired exception, invalid exception, malformed JSON, missing file,
non-Trivy JSON) and the "secret value is never printed" property.

## Assumptions
- Trivy schema version 2 (`Results[].Vulnerabilities|Secrets|Misconfigurations`).
- Severity is Trivy's own; exposure/KEV/EPSS context is *not* in the report, so it is not modelled.
- Exceptions match on finding ID only (not per-package/per-target).

## Design decision I would change for a production service
Today the policy is a handful of CLI flags and exceptions match only by ID. In production I would:
load policy from a **versioned policy repository** (so hundreds of repos inherit it and cannot loosen
it), scope exceptions by ID **+ component + repository/image**, enrich findings with exposure and
KEV/EPSS data, and emit decisions as a signed attestation that admission control can check, rather
than only an exit code. I would also replace this script with OPA/Rego or Kyverno-style policy so the
same engine decides in CI and at admission.

## Limitations (be honest about these in the interview)
No cross-scan baselining/trending, no per-repo ownership routing, no VEX ingestion, Markdown only
(no SARIF output), and `--only-fixable` treats "fix exists" as sufficient even if the fix is a major
version bump that needs engineering work.
