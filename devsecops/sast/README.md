# SAST - Semgrep Community Edition

```bash
# Registry rules + local custom rules, telemetry off, fail (exit 1) on ERROR-severity findings
docker run --rm -v "$PWD:/repo" -w /repo semgrep/semgrep \
  semgrep scan --config p/python --config devsecops/sast/rules --metrics=off \
  --severity ERROR --error \
  --sarif-output evidence/semgrep.sarif --json-output evidence/semgrep.json \
  devsecops/app-or-lab-target
```

## The one result to explain in the interview

**SQL injection in `/user`** (`app.py`):
```python
query = "SELECT id, name, email FROM users WHERE name = '%s'" % name   # tainted input in SQL
```
- *Why it matters:* attacker-controlled `name` changes the query (`' OR '1'='1`) -> data disclosure.
  Exploitability is high and needs no authentication on this endpoint.
- *Responsible fix:* parameterised query - `db.execute("... WHERE name = ?", (name,))`. Fix the root
  cause; do not "sanitise" with a blocklist.
- *When suppression is legitimate:* a true false positive (e.g. the "SQL" is a constant built from a
  fixed allow-list of column names). Suppress on that line only, with a reason and a ticket:
  `# nosemgrep: lab-sql-built-from-string -- column from fixed enum, see SEC-123`.
  CODEOWNERS should require security review of any new `nosemgrep` comment.

## Notes
- `--config auto` is convenient but sends metrics/config discovery; this setup uses explicit packs
  and `--metrics=off`. Say why in the interview (data minimisation, reproducibility).
- Registry rule IDs change over time; the custom rules in `rules/` keep the lab deterministic.
- Semgrep CE is single-file/limited cross-file dataflow. A mature setup adds scheduled full scans,
  rule tuning per repo, and triage metrics.
