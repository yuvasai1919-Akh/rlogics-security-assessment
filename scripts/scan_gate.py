#!/usr/bin/env python3
"""scan_gate.py - policy gate over Trivy JSON output (Exercise 3, option A).

Reads a Trivy JSON report, applies a configurable policy, writes a Markdown summary and optional
CSV, and exits non-zero when the policy is violated.

Exit codes:
    0  policy satisfied (WARN findings may still exist)
    1  policy violated (at least one BLOCK finding)
    2  input/usage error (unreadable file, not Trivy JSON, bad exceptions file)

Design notes:
  * Secrets are never echoed (Trivy's "Match" field is deliberately not read).
  * Exceptions must carry id, reason, approved_by and an expiry; expired ones are ignored and
    reported, so a forgotten exception cannot silently disable the gate forever.
  * Fail closed on unreadable/malformed input: a broken scanner must not look like a clean scan.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

EXIT_OK, EXIT_POLICY_FAIL, EXIT_INPUT_ERROR = 0, 1, 2
REQUIRED_EXCEPTION_FIELDS = ("id", "reason", "approved_by", "expires")


class InputError(Exception):
    """Raised for problems with the inputs (not with the findings)."""


# --------------------------------------------------------------------------- loading
def load_json(path: str) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from exc


def load_trivy(path: str) -> dict:
    data = load_json(path)
    # Trivy omits "Results" entirely on a clean scan but still emits SchemaVersion.
    if not isinstance(data, dict) or ("Results" not in data and "SchemaVersion" not in data):
        raise InputError(f"{path} does not look like Trivy JSON (no 'Results' or 'SchemaVersion')")
    return data


def parse_date(value: str, what: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise InputError(f"{what}: '{value}' is not a YYYY-MM-DD date") from exc


def load_exceptions(path: str | None, today: dt.date) -> tuple[dict[str, dict], list[dict]]:
    """Return (active exceptions by id, expired exceptions)."""
    if not path:
        return {}, []
    raw = load_json(path)
    if not isinstance(raw, list):
        raise InputError(f"{path}: exceptions file must be a JSON list")
    active: dict[str, dict] = {}
    expired: list[dict] = []
    for i, exc in enumerate(raw):
        if not isinstance(exc, dict):
            raise InputError(f"{path}: entry {i} is not an object")
        missing = [f for f in REQUIRED_EXCEPTION_FIELDS if not exc.get(f)]
        if missing:
            # An exception without an owner/reason/expiry is a suppression, not an exception.
            raise InputError(f"{path}: entry {i} missing required field(s): {', '.join(missing)}")
        if parse_date(exc["expires"], f"{path} entry {i}") < today:
            expired.append(exc)
        else:
            active[exc["id"]] = exc
    return active, expired


# --------------------------------------------------------------------------- normalising
def norm_sev(value: Any) -> str:
    sev = str(value or "UNKNOWN").upper()
    return sev if sev in RANK else "UNKNOWN"


def extract_findings(report: dict) -> list[dict]:
    findings: list[dict] = []
    for res in report.get("Results") or []:
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities") or []:
            findings.append({
                "kind": "vulnerability", "id": v.get("VulnerabilityID", "?"), "target": target,
                "package": v.get("PkgName", ""), "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion") or "", "severity": norm_sev(v.get("Severity")),
                "title": (v.get("Title") or "")[:120],
            })
        for s in res.get("Secrets") or []:
            findings.append({  # note: s["Match"] intentionally NOT copied
                "kind": "secret", "id": s.get("RuleID", "?"), "target": target,
                "package": "", "installed": "", "fixed": "n/a",
                "severity": norm_sev(s.get("Severity")), "title": (s.get("Title") or "")[:120],
            })
        for m in res.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            findings.append({
                "kind": "misconfig", "id": m.get("ID") or m.get("AVDID", "?"), "target": target,
                "package": "", "installed": "", "fixed": "n/a",
                "severity": norm_sev(m.get("Severity")), "title": (m.get("Title") or "")[:120],
            })
    return findings


# --------------------------------------------------------------------------- policy
def decide(f: dict, fail_on: str, only_fixable: bool, fail_on_secrets: bool,
           exceptions: dict[str, dict]) -> tuple[str, str]:
    """Return (decision, reason). decision in BLOCK | WARN | EXCEPTED."""
    meets_threshold = RANK[f["severity"]] >= RANK[fail_on]
    if f["kind"] == "secret":
        blocks = fail_on_secrets  # any secret blocks regardless of severity
        reason = "secret detected (blocks regardless of severity)"
    elif f["kind"] == "vulnerability":
        has_fix = bool(f["fixed"])
        blocks = meets_threshold and (has_fix or not only_fixable)
        if meets_threshold and not has_fix and only_fixable:
            reason = f"{f['severity']} with no fix available -> needs mitigation/exception, tracked as WARN"
        else:
            reason = f"{f['severity']}{' with fix ' + f['fixed'] if has_fix else ''}"
    else:  # misconfig
        blocks = meets_threshold
        reason = f"{f['severity']} misconfiguration"

    if not blocks:
        return "WARN", reason
    # Secrets are never excepted: rotate, do not waive.
    if f["kind"] != "secret" and f["id"] in exceptions:
        return "EXCEPTED", f"approved by {exceptions[f['id']]['approved_by']} until {exceptions[f['id']]['expires']}"
    return "BLOCK", reason


# --------------------------------------------------------------------------- reporting
def render_markdown(source: str, rows: list[dict], expired: list[dict], verdict: str,
                    cfg: dict, max_rows: int) -> str:
    by_dec = Counter(r["decision"] for r in rows)
    by_sev = Counter(r["severity"] for r in rows)
    lines = [
        f"# Scan gate result: **{verdict}**", "",
        f"- Source: `{source}`",
        f"- Policy: fail on >= `{cfg['fail_on']}`, only-fixable=`{cfg['only_fixable']}`, "
        f"secrets block=`{cfg['fail_on_secrets']}`, today=`{cfg['today']}`",
        f"- Findings: {len(rows)} (BLOCK {by_dec['BLOCK']}, EXCEPTED {by_dec['EXCEPTED']}, WARN {by_dec['WARN']})", "",
        "| Severity | Count |", "|---|---|",
    ]
    lines += [f"| {s} | {by_sev[s]} |" for s in reversed(SEVERITIES) if by_sev[s]]
    # WARN is listed too: e.g. an unfixed CRITICAL must stay visible and owned, never silently counted.
    for label in ("BLOCK", "EXCEPTED", "WARN"):
        subset = [r for r in rows if r["decision"] == label]
        if subset:
            lines += ["", f"## {label}", "", "| ID | Sev | Package | Installed | Fixed | Target | Reason |",
                      "|---|---|---|---|---|---|---|"]
            for r in sorted(subset, key=lambda x: -RANK[x["severity"]])[:max_rows]:
                lines.append(f"| {r['id']} | {r['severity']} | {r['package']} | {r['installed']} | "
                             f"{r['fixed'] or '-'} | {r['target']} | {r['reason']} |")
            if len(subset) > max_rows:
                lines.append(f"\n_...{len(subset) - max_rows} more in the CSV._")
    if expired:
        lines += ["", "## Expired exceptions (ignored - finding is enforced again)", ""]
        lines += [f"- {e['id']} expired {e['expires']} (approved by {e['approved_by']})" for e in expired]
    return "\n".join(lines) + "\n"


def write_csv(path: str, rows: list[dict]) -> None:
    fields = ["decision", "kind", "id", "severity", "package", "installed", "fixed", "target", "reason", "title"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Policy gate over Trivy JSON output.")
    p.add_argument("--trivy", required=True, help="Trivy JSON report (trivy ... --format json)")
    p.add_argument("--fail-on", default="CRITICAL", type=str.upper, choices=SEVERITIES[1:],
                   help="minimum severity that blocks (default CRITICAL)")
    p.add_argument("--only-fixable", action=argparse.BooleanOptionalAction, default=True,
                   help="only block vulnerabilities that have a fixed version (default on)")
    p.add_argument("--fail-on-secrets", action=argparse.BooleanOptionalAction, default=True,
                   help="any detected secret blocks (default on)")
    p.add_argument("--exceptions", help="JSON list of time-boxed exceptions")
    p.add_argument("--markdown", help="write Markdown summary here (always printed to stdout too)")
    p.add_argument("--csv", help="write all findings with decisions to CSV")
    p.add_argument("--max-rows", type=int, default=25, help="max rows per table in Markdown")
    p.add_argument("--today", help="override today's date (YYYY-MM-DD); for tests/reproducibility")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        today = parse_date(args.today, "--today") if args.today else dt.date.today()
        report = load_trivy(args.trivy)
        exceptions, expired = load_exceptions(args.exceptions, today)
    except InputError as exc:
        print(f"scan_gate: input error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    rows = []
    for f in extract_findings(report):
        decision, reason = decide(f, args.fail_on, args.only_fixable, args.fail_on_secrets, exceptions)
        rows.append({**f, "decision": decision, "reason": reason})

    verdict = "FAIL" if any(r["decision"] == "BLOCK" for r in rows) else "PASS"
    cfg = {"fail_on": args.fail_on, "only_fixable": args.only_fixable,
           "fail_on_secrets": args.fail_on_secrets, "today": today.isoformat()}
    md = render_markdown(args.trivy, rows, expired, verdict, cfg, args.max_rows)
    print(md)
    try:
        if args.markdown:
            Path(args.markdown).write_text(md, encoding="utf-8")
        if args.csv:
            write_csv(args.csv, rows)
    except OSError as exc:
        print(f"scan_gate: cannot write output: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    return EXIT_POLICY_FAIL if verdict == "FAIL" else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
