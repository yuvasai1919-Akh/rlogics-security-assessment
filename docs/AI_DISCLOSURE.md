# AI Assistance Disclosure

AI tools were used as a supporting resource for technical research, drafting, and troubleshooting during this assessment. I executed the lab exercises, reviewed the outputs, investigated issues, and documented the results and limitations of the work performed.

| Area | AI assisted? | How | Implementation and validation |
|------|--------------|-----|-------------------------------|
| Repository scaffold, scripts and manifests | Yes | Research, initial drafts, and troubleshooting | Ran the lab commands, reviewed results, and corrected Cosign flags for the local HTTP registry |
| Technical explanations and architecture | Yes | Drafting and refinement | Reviewed the implementation scope and aligned documented claims with observed results |
| Evidence collection and reporting | Yes | Execution guidance and help interpreting outputs | Captured lab outputs and documented the results from my runs |

## Implementation refinements and validation

- Updated Cosign registry flags to support signing and verification against the local HTTP registry.
- Executed vulnerable and remediated pipeline scenarios and recorded their outcomes.
- Tested the scan gate using sample Trivy reports; all 13 unit tests passed.
- Ran OpenBao PKI and dynamic database credential exercises, including certificate and credential lifecycle checks.
- Validated Kubernetes Kyverno admission controls and NetworkPolicy connectivity in a local kind cluster.
- Implemented and ran a deterministic local AI-security harness covering five checks. These were simulated checks, not live LLM red-team tests.

## Scope and remaining validation

- Caldera research and the benign operation plan were completed; live operation and endpoint telemetry were not executed.
- Promptfoo, garak, and PyRIT were not run against a live AI target.
- `kube-bench` and a CIS node benchmark were not run.
- Active ZAP scanning was not performed; the passive baseline scan passed.
- Production deployment, multi-region resilience, and production-cluster network enforcement were not validated.
- Repository-wide secret scanning remains to be completed and reviewed before the repository is shared.

## References

Project documentation and relevant technical documentation informed the implementation and testing. Supporting evidence is recorded in the repository's exercise notes and captured outputs.
