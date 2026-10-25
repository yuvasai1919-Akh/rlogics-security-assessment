# Draft answers for the RLogics candidate response template

The real template is a separate document you were given. Copy from here, but **edit every answer to
reflect what you actually did**. Items marked [YOU] need your own facts.

| Template item | Draft answer |
|---------------|--------------|
| Repository link | [YOU] private GitHub URL; confirm the interview team has access |
| Architecture document | `architecture/ARCHITECTURE.md` (export to PDF: see GETTING_STARTED) |
| AI assistance disclosure | See `docs/AI_DISCLOSURE.md` - drafted with Claude; list what you changed [YOU] |
| Time spent | [YOU] honest hours per exercise |
| Environment | [YOU] OS, Docker/Rancher version, Kubernetes version, CNI, Kyverno version |
| Exercise 1 - completed | [YOU] Semgrep / Trivy / SBOM / ZAP / Cosign / pipeline: done or not, and why |
| Exercise 2 - completed | [YOU] PKI issuance; DB dynamic credential lease and expiry |
| Exercise 3 - completed | Option A `scripts/scan_gate.py`, 13 unit tests, demo-ready |
| Exercise 4 - completed | Research and operation plan complete; live execution [YOU: yes/no and why] |
| Exercise 5 - completed | [YOU] hardened deployed; Kyverno deny/allow; scanner output; NetworkPolicy enforcement result; kube-bench decision |
| Exercise 6 - completed | Architecture document with diagram, compromise analysis, 90-day phasing |
| Exercise 7 - completed | Tool comparison (Promptfoo, garak, PyRIT), five tests; optional safe run [YOU: yes/no] |
| Interview-only demos | Pipeline run, OpenBao labs, Kubernetes + Kyverno, scan_gate.py, Caldera plan/UI if run |
| Not completed + why + next step | Copy your edited "Known limitations" table from the root README |
| What I would do differently in production | Keyless signing + admission verification of attestations, durable HA OpenBao with HSM/KMS auto-unseal and offline root, central policy repo + exception register, authenticated active DAST in staging, runtime detection, regional evidence stores |
| Secrets check | I confirmed the repo contains no real credentials; lab values are synthetic and labelled |
