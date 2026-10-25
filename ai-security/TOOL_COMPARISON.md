# Exercise 7 - AI security threat research and tool selection

*Draft. Facts below were checked against primary/secondary sources in Oct 2026 where marked;
tool capabilities move quickly, so re-verify before the interview.*

## 1. Threat frameworks used

**OWASP Top 10 for LLM Applications - 2026 edition** (note the renumbering vs the 2025 list; verified
against two independent write-ups, confirm on genai.owasp.org):
LLM01 Prompt Injection - LLM02 Sensitive Information Disclosure - **LLM03 Excessive Agency** (up from 2025's
LLM06) - LLM04 Supply Chain - LLM05 Data and Model Poisoning - **LLM06 Unbounded Consumption** (incl.
denial-of-wallet) - LLM07 Misinformation - **LLM08 Hidden Context Exposure** (renamed/broadened from System
Prompt Leakage) - LLM09 Vector and Embedding Weaknesses - LLM10 Improper Output Handling.

**OWASP Top 10 for Agentic Applications** (ASI01-ASI10, as mapped on promptfoo's docs): ASI01 Agent Goal
Hijack - ASI02 Tool Misuse and Exploitation - ASI03 Identity and Privilege Abuse - ASI04 Agentic Supply
Chain Vulnerabilities - ASI05 Unexpected Code Execution - ASI06 Memory and Context Poisoning - ASI07 Insecure
Inter-Agent Communication - ASI08 Cascading Failures - ASI09 Human-Agent Trust Exploitation - ASI10 Rogue Agents.

**MITRE ATLAS** techniques used in the tests (IDs from a secondary source - verify on atlas.mitre.org):
AML.T0051 LLM Prompt Injection (.000 direct, .001 indirect) - AML.T0054 LLM Jailbreak - AML.T0057 LLM Data
Leakage - AML.T0053 LLM Plugin Compromise. RAG/vector poisoning and memory poisoning have
corresponding techniques in current ATLAS releases; look up the exact IDs rather than quoting from memory.

## 2. Tools compared

| Dimension | **Promptfoo** | **garak** (NVIDIA) | **PyRIT** (Microsoft) |
|-----------|--------------|--------------------|-----------------------|
| What it is | Eval + red-team framework driven by a YAML config; plugins generate adversarial cases per risk, strategies (jailbreak, crescendo...) mutate them, graders score responses | "LLM vulnerability scanner": a large library of **probes** (attack prompts) + **detectors** run against a model/endpoint, like nmap for LLMs | Python framework for building red-team campaigns: **targets, converters, scorers, attacks, memory, scenarios**; CLI scanner/shell, GUI (CoPyRIT) and Python API |
| Threat coverage | App-level: prompt injection (direct/indirect), PII/data leakage, excessive agency, tool/MCP abuse, RBAC/BOLA/BFLA, SQL/shell injection, memory poisoning, hallucination; **built-in mappings to OWASP LLM and OWASP Agentic (`owasp:agentic:asi01..10`)** | Model-level: prompt injection (promptinject, encoding), jailbreaks (dan), training-data replay (leakreplay), XSS/data-exfil via markdown (xss), malware generation, package hallucination, toxicity, glitch tokens. Weak on *your app's* tools, RAG and authorisation logic | Broad and flexible: content harms, data leakage scenarios, multi-turn attacks (Crescendo, TAP, Skeleton Key); you can script agent/RAG-specific campaigns, but you build more yourself |
| Deployment model | Local CLI/Node; targets run locally. **Without your own provider key, test generation/grading uses Promptfoo-hosted inference and sends app purpose, plugin config, prompts and responses to `api.promptfoo.app`.** Set `PROMPTFOO_DISABLE_REMOTE_GENERATION=true` and a local/own `redteam.provider` to keep data in-house; `PROMPTFOO_DISABLE_TELEMETRY=1` for telemetry. (These switches are not network isolation.) | Local Python CLI (3.11+). Fully local possible with HF pipeline models or GGUF via llama.cpp; many generators call remote APIs and need keys. Attack prompts are mostly **static probe sets** (no remote attacker LLM needed except for adaptive probes such as `atkgen`) | Local Python. Needs an **attacker/scorer LLM** for adaptive and LLM-scored attacks - can be a local model or an approved endpoint; memory in SQLite (or Azure SQL) stays with you |
| Integration / CI | Strong: YAML config, CLI exit codes, JSON/HTML output, comparison across runs, designed for CI | Good: CLI; per-run **JSONL report + hit log + log file**; easy to schedule; baselining by comparing hit rates per probe | Moderate: scriptable and has a scanner CLI, but you assemble pipelines/reporting; results in the memory DB |
| Target support | HTTP endpoints, custom providers, major hosted models, local models (e.g. Ollama), agents/RAG via HTTP or custom provider | HF, OpenAI-compatible, Replicate, Cohere, Groq, NIM, Bedrock, litellm, GGUF, **generic REST generator (YAML)** | OpenAI/Azure/Anthropic/Google/HF, custom HTTP/WebSocket targets, web apps via Playwright |
| Operational fit | Lowest learning curve for platform engineers; actively developed. Check current ownership/licence/roadmap and telemetry defaults before adopting | Mature, well-known, Apache-2.0; latest release seen on PyPI: **0.17.1 (Oct 16 2026)**. Less app-aware | Microsoft-backed, MIT-style open source, powerful; highest skill requirement; APIs/terminology change between releases (now "attacks") |
| Uncontrolled-attack-tool risk | Scope-lock targets, no destructive tools in the test agent, test accounts only | Same; it only sends prompts, but a pointed-at-production run can still cause cost/abuse | Same, plus multi-turn automated attacks need rate/spend caps |

## 3. Recommendation: **Promptfoo + garak** (PyRIT as a later specialist tool)

- **Promptfoo = application/agent regression tests in CI.** It tests *our* RAG + agent behaviour
  (leakage across users, tool abuse, goal hijack via retrieved docs), maps directly to OWASP
  LLM/Agentic IDs, runs per pull request or nightly, and results can be diffed over time. Run it with
  local or approved providers and remote generation disabled so internal prompts and documents do
  not leave the environment.
- **garak = model/provider baseline and release gate.** When a model, system prompt template, guardrail
  or provider changes, garak's broad probe library gives a cheap, reproducible
  "did the base behaviour regress?" measurement that works against a local model, with JSONL/hit logs
  that are easy to retain as evidence.
- **PyRIT later:** when the team has a security engineer who wants bespoke multi-turn or agentic
  campaigns (Crescendo/TAP) or custom scorers. Valuable, but a poor first choice for a platform team
  that needs repeatable CI checks.

**Harness guardrails:** run against test deployments with synthetic data and test identities only;
allow-list target URLs in config; spend/rate caps on any attacker LLM; no production credentials or
tools reachable from the target agent; results stored without live secrets/PII; the config and the
probe/plugin set are version-controlled and reviewed like code.

## 4. Making it repeatable instead of a one-off pen test
1. **Threat model once, test continuously:** each identified risk maps to a test in version control
   (`FIVE_TESTS.md` pattern), tagged with OWASP/ATLAS IDs.
2. **Triggers:** every PR touching prompts/tools/retrieval config (fast subset), nightly (full
   suite), and on model/provider/guardrail changes (garak + Promptfoo full).
3. **Baselines and budgets:** store attack-success rate per test; fail the release when a
   high-impact test regresses or exceeds an agreed threshold; track trends, not just pass/fail.
4. **Evidence:** keep run configs, versions, model IDs, results and approvals by release - supports
   ISO/IEC 42001 and SOC 2 style assurance.
5. **Human layer:** periodic manual red-team/pen test for novel attack paths, feeding new automated
   tests back into the suite. Findings go through the same triage/SLA/exception process as code vulns.
6. **Fix loop:** mitigations are architectural first (least privilege tools, per-user retrieval
   authorisation, output handling, human approval for risky actions); prompt hardening is a
   secondary, fragile layer.
