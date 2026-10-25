# Decision table: BLOCK / WARN / REQUIRE EXCEPTION

**Principles.** (1) Block on things that are both *high-impact and actionable*; a gate nobody can
satisfy trains people to bypass it. (2) Context changes severity: internet exposure, known
exploitation, data sensitivity and whether a fix exists. (3) Everything that is not a block is still
*recorded and owned* (WARN has an SLA). (4) Exceptions are time-boxed, approved by the right owner,
and visible. (5) Fail **closed** on integrity controls (signatures, policy engine errors) and fail
**open-with-alert** only on developer-feedback stages.

| # | Finding / condition | PR stage | Build/release stage | Deploy (admission) | Exception path |
|---|---------------------|----------|---------------------|--------------------|----------------|
| 1 | **Secret**, high-confidence pattern (token, private key) in code, history or image | BLOCK | BLOCK | BLOCK | None. Rotate/revoke immediately; incident if it was pushed |
| 2 | Secret-like, low confidence (entropy, test fixture) | WARN + triage | WARN | n/a | Path allow-list reviewed by security |
| 3 | **Critical CVE, fix available** | WARN (annotate) | **BLOCK** | BLOCK if image already deployed-eligible | Exception: service owner + security, <=30 days, compensating control, ticket |
| 4 | Critical CVE, **no fix** | WARN | **REQUIRE EXCEPTION** (blocks until one exists) | Allowed only with valid exception | Mitigation (WAF/config/network) or VEX "not affected"; review every 30 days |
| 5 | High CVE, fix available, **internet-facing** service | WARN | **BLOCK** | BLOCK | Exception <=30 days |
| 6 | High CVE, fix available, internal service | WARN | WARN + SLA 30 days | allow | Not required unless SLA breached |
| 7 | High CVE, no fix | WARN | WARN + track | allow | Re-review when fix ships |
| 8 | Medium / Low CVE | WARN | WARN (SLA 90 days / backlog) | allow | Not required |
| 9 | **Known exploited (CISA KEV) or high EPSS**, any severity >= Medium | BLOCK | BLOCK | BLOCK | Security lead only; emergency patch path |
| 10 | SAST: high-confidence injection/deserialisation/command execution in **new/changed code** | **BLOCK** | BLOCK | n/a | Suppress on the line with reason + ticket (CODEOWNERS review) if a proven false positive |
| 11 | SAST: lower-confidence or style/hardening rules | WARN | WARN | n/a | Tune rule centrally |
| 12 | Misconfig: privileged container, hostPath, hostNetwork, root in prod namespace | BLOCK | BLOCK | **BLOCK** (admission) | Platform + security, break-glass only with incident ticket |
| 13 | Misconfig: missing limits/probes, `latest` tag in dev | WARN | WARN | WARN dev / BLOCK prod | Not required in dev |
| 14 | **Signature missing/invalid, wrong signer identity, digest mismatch** | n/a | BLOCK (do not publish) | **BLOCK** | None except break-glass with incident ticket |
| 15 | SBOM or provenance attestation missing | WARN | WARN dev / **BLOCK** prod promotion | BLOCK prod | Platform lead, <=7 days |
| 16 | Image from non-approved registry/base image | WARN | BLOCK prod | BLOCK | Platform review to add to allow-list |
| 17 | DAST: high-risk, high-confidence alert (e.g. SQLi, auth bypass) | n/a | **BLOCK release** | n/a | Fix or documented exception with owner sign-off |
| 18 | DAST: medium/low alerts (missing headers, info leakage) | n/a | WARN + SLA | n/a | Not required |
| 19 | License violation (e.g. copyleft in a proprietary product) | WARN | **REQUIRE EXCEPTION** | n/a | Legal approval |
| 20 | **Scanner error / timeout / stale vulnerability DB** | WARN + alert (do not block devs on tool outage) | **FAIL CLOSED** | fail closed on policy-engine error | Platform on-call can re-run; no silent skip |

## Context modifiers (how the same CVE moves in the table)
- Internet-facing or handles regulated data: promote one level (High -> treat like Critical).
- Not reachable / vulnerable code path not executed (VEX): demote with a recorded justification.
- Fix exists but breaks the build: that is a *scheduling* problem, not a reason to ignore it - use an
  exception with a date.
- Dev/sandbox namespaces: relax WARN thresholds, never relax integrity (signature/secret) rules.

## Who can approve what
| Decision | Approver |
|----------|----------|
| Suppress a single SAST false positive | Code owner + security review of the diff |
| Time-boxed vulnerability exception (<=30 days) | Service owner + security |
| Exception on a Critical / internet-facing, or >30 days | Security lead + business risk owner |
| Break-glass at admission | Incident commander; auto-expires; post-incident review |
| Change to the policy itself | Policy repo PR: security + platform, versioned and tested |

## Where policy lives
In a **central, versioned policy repository** (policy-as-code: OPA/Rego, Kyverno, Semgrep rule packs,
gate config), consumed by every pipeline through a shared template. Individual repos may tighten but
never loosen policy. At scale this is what makes hundreds of repositories tractable: one change,
tested once, rolled out via the template, with per-repo exceptions in the central register.
