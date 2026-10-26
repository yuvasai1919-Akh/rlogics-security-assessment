# Remediated DevSecOps Pipeline — Evidence Summary

**Date:** 2026-10-26
**Result:** PASSED
**Run evidence directory:** `evidence/runs/20261026T121125Z-remediated`

## Pipeline Results

| Stage | Result |
|---|---|
| SAST (Semgrep) | PASS |
| SCA, secrets and filesystem misconfiguration checks | PASS |
| Build image | PASS |
| Image scan and security gate | PASS |
| SBOM generation (CycloneDX and SPDX) | PASS |
| DAST baseline (ZAP) | PASS |
| Sign and verify (Cosign) | PASS |

## Notes

- The raw run artifacts remain under `evidence/runs/`, which is excluded by `.gitignore`.
- Cosign verification was performed with transparency-log upload disabled. This demonstrates the lab's signing and verification workflow, but does not establish transparency-log inclusion.
- This summary records the observed pipeline results; it does not replace the underlying test artifacts.
