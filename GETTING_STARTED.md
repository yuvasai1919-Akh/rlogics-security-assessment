# GETTING STARTED - Your execution plan

Target: ~6-8 focused hours for the core, +2-4 hours optional stretch. Do the exercises in this
order. Quality of reasoning beats volume of screenshots.

## 0. One-time setup (30-45 min)

**Use WSL2 (Windows) or a normal Linux/macOS shell.** The scripts are bash and mount the Docker
socket; Git Bash path conversion will fight you.

Install: Docker Desktop (or Rancher Desktop), `git`, `python3` (3.9+), `kubectl`, `kind`, `jq`, `curl`.

```bash
cd rlogics-security-assessment
make preflight          # checks every tool and prints versions
git init && git add -A && git commit -m "Initial assessment scaffold"
# create a PRIVATE GitHub repo, push, and share with the interview team when ready
```

Pull images once so later steps are quick:
```bash
docker pull semgrep/semgrep
docker pull aquasec/trivy:latest
docker pull ghcr.io/zaproxy/zaproxy:stable
docker pull openbao/openbao:latest
docker pull postgres:16-alpine
docker pull registry:2
docker pull ghcr.io/sigstore/cosign/cosign:v2.4.1
```

## Time plan

| Block | Exercise | Time | Done when |
|-------|----------|------|-----------|
| 1 | Ex 1 - DevSecOps pipeline | 2 h | You have Semgrep, Trivy, SBOM, ZAP, Cosign outputs for vulnerable AND remediated app |
| 2 | Ex 2 - OpenBao PKI + DB creds | 1.5 h | Cert inspected; dynamic DB user created, used, expired/revoked |
| 3 | Ex 5 - Kubernetes | 1.5-2 h | Hardened pod running; Kyverno denies bad pod; scanner output saved |
| 4 | Ex 3 - Script | 45 min | Tests pass, you can explain every function |
| 5 | Ex 6 - Architecture doc | 1 h | Edit `architecture/ARCHITECTURE.md`, export to PDF/Docx |
| 6 | Ex 4 + Ex 7 - Caldera / AI research | 1.5 h | Notes reviewed and in your own words; optional live run |
| 7 | Interview prep | 1 h | `docs/INTERVIEW_PREP.md` questions answered aloud |

## Exercise 1 - DevSecOps (`devsecops/`)

```bash
make plant-secret        # generates a SYNTHETIC secret file at runtime (gitignored)
make pipeline-vuln       # runs everything against the intentionally vulnerable app
make pipeline-fixed      # runs everything against the remediated app
```
Outputs land in `evidence/runs/<timestamp>-<mode>/`. Look at:
- `semgrep.sarif` / `semgrep.json` - pick ONE result, explain and fix it (see `FINDINGS_BEFORE_AFTER.md`).
- `trivy-fs.json`, `trivy-image.json` + `gate-*.md` - the gate summary.
- `sbom.cdx.json` (CycloneDX) and `sbom.spdx.json`.
- `zap-baseline.html` / `.json`.
- `cosign-verify.txt` and `cosign-tamper-test.txt`.

**Compare the two runs** (vulnerable vs remediated): that is your before/after evidence.
Run only on the lab app on localhost. Never point ZAP at anything you do not own.

## Exercise 2 - OpenBao (`openbao/`)

```bash
make openbao-up          # OpenBao dev mode + disposable PostgreSQL (localhost only)
make openbao-pki         # PKI engine, role, issue and inspect a short-lived cert
make openbao-db          # DB engine, dynamic creds, lease, use, revoke
make openbao-down
```
Read `openbao/CONCEPTS.md` (Part A answers) and `openbao/PRODUCTION_DESIGN.md` (Part B/C production
delta + the four production-thinking questions). Dev mode is **lab only**: in-memory, auto-unsealed,
no TLS, fixed root token.

## Exercise 5 - Kubernetes (`kubernetes/`)

```bash
make k8s-up              # kind cluster (record version/runtime/limitations)
make k8s-kyverno         # installs Kyverno via Helm
make k8s-policies        # applies the Kyverno policies
make k8s-deploy          # hardened workload (NEVER the unsafe review input)
make k8s-demo            # allow/deny demo using server-side dry-run
make k8s-scan            # Trivy config scan of unsafe vs hardened (static only)
make k8s-down
```
Read `kubernetes/REVIEW_NOTES.md`. The unsafe YAML in `review-input/` must never be applied.
`k8s-demo` refuses to run if the Kyverno policy is not installed.

## Exercise 3 - Script (`scripts/`)

```bash
make test-gate           # unit tests
python3 scripts/scan_gate.py --help
python3 scripts/scan_gate.py --trivy scripts/samples/trivy_critical_fixable.json
echo $?                  # 1 = policy fail
```

## Exercise 4, 6, 7 - Documents

These are research/design deliverables. **Rewrite them in your own words** and add what you actually
ran. The interviewers will probe the reasoning, not the formatting.
- `caldera/CALDERA_RESEARCH.md`
- `architecture/ARCHITECTURE.md` (convert to PDF; keep to 2-4 pages)
- `ai-security/TOOL_COMPARISON.md`, `ai-security/FIVE_TESTS.md`

## What you must do yourself (this is the assessment)

1. Actually run the labs and replace the reference outputs with your own.
2. Update the "Known limitations" table honestly. A clear "could not do X because Y, next step Z" is
   explicitly rewarded.
3. Verify tool flags/versions against current docs (the notes say where versions may have moved).
4. Fill in the separate RLogics response template using the answers in this repo as drafts.
5. Disclose AI assistance (template provided).
