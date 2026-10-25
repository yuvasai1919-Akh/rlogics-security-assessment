# Interview prep - show & tell (about 75 minutes)

Questions below come from the brief's discussion prompts. Answer them aloud, in your own words, with
a concrete example from your lab. "I would verify that" and "I did not complete X because Y" are good answers.

## Approach (10 min)
- How did you plan the six-to-eight hours? What did you deliberately **not** do and why?
- What was your riskiest assumption, and how did you test it?
- Where did AI help, and what did you have to correct? (see `docs/AI_DISCLOSURE.md`)

## DevSecOps (15 min) - demo `make pipeline-vuln` then `make pipeline-fixed`
- SAST vs SCA vs container scanning vs DAST: what each sees, what each misses.
- Walk one finding end to end: detection -> triage -> fix -> verification.
- Why is signing an image not proof it is secure? What does admission add?
- Where does vulnerability policy live; who can approve an exception; what makes an exception legitimate?
- 1 repo -> 500 repos: reusable workflows, central policy repo, exception register, ownership routing,
  scan-time budgets, metrics, noisy-rule handling, scheduled org-wide re-scans.
- Defend one row of `devsecops/policy/DECISION_TABLE.md` to an unhappy developer.

## OpenBao / PKI (10 min) - demo `make openbao-up openbao-pki openbao-db`
- Root vs intermediate vs leaf; why root offline; what CRL/OCSP do and where they fail.
- Authentication vs authorisation in OpenBao.
- What exactly happens at lease expiry/revocation in PostgreSQL?
- OpenBao down for two hours: what breaks first and what do the TTLs buy you?
- How does one app avoid minting certificates for another?

## Kubernetes + architecture (15 min)
- Rank the unsafe manifest's issues; which are blockers? Why is `hostPath: /` + `privileged` so bad?
- Does your local CNI enforce NetworkPolicy? How do you know? (`make k8s-netpol`)
- Show a Kyverno deny and an allow. What happens to a bad **Deployment** (vs a bad Pod)?
- Kyverno ClusterPolicy removal: what did you check and what changed in the new policy kinds?
- Draw the architecture; mark preventive / detective / corrective; walk the three compromise cases.

## Scripting + Caldera (10 min)
- Run `scan_gate.py` on the fixable-critical sample, the exception sample, and the malformed file.
- Why does malformed input exit 2 instead of passing? What would you change in a service?
- Caldera: relationships between abilities, adversaries, operations, planners, facts; your three
  abilities, ATT&CK IDs and expected telemetry; isolation and cleanup.

## AI security (10 min)
- OWASP LLM 2026 vs 2025 differences; two agentic risks; one ATLAS technique.
- Why Promptfoo + garak and not PyRIT first? What data leaves the machine, and how do you stop it?
- Pick one of the five tests and explain the evidence and the mitigation.

## Reflection (5 min)
- What failed? What would you improve with more time/production context? What do you want to learn next?

## Optional - Microsoft internal posture (short)
Entra ID (conditional access, MFA/phishing-resistant, PIM for admin roles, device compliance
signals), Intune (device compliance and configuration baselines, app protection), Defender
(endpoint/identity/cloud-apps detections, attack surface reduction, vulnerability management),
Purview (classification, DLP, retention, insider-risk, audit). Tie them together: identity + device
compliance gates access; Defender provides detections; Purview governs data; evidence flows to the
same audit store.
