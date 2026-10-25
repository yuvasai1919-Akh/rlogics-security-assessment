# Trivy - dependency, secret, misconfiguration, image scan and SBOM

Commands (the pipeline wraps these; shown here so you can run them by hand):

```bash
# Source filesystem: vulnerabilities (SCA), secrets and misconfigurations. Machine + human output.
trivy fs --scanners vuln,secret,misconfig --format json  --output trivy-fs.json  devsecops/app-or-lab-target
trivy fs --scanners vuln,secret,misconfig --format table devsecops/app-or-lab-target

# Image
trivy image --format json --output trivy-image.json lab-app:vulnerable

# SBOM (CycloneDX and SPDX)
trivy image --format cyclonedx --output sbom.cdx.json  lab-app:vulnerable
trivy image --format spdx-json --output sbom.spdx.json lab-app:vulnerable
```

## Reading the output
- **Vulnerabilities**: package, installed vs fixed version, severity. "FixedVersion empty" = no fix
  available yet (matters for the gate: you cannot patch your way out, so you need mitigation or an
  exception rather than a blocking build that nobody can fix).
- **Secrets**: rule ID + file + line. Trivy shows a redacted match. Treat any real hit as compromised
  and rotate - removing it from Git history is not enough.
- **Misconfig** (Dockerfile): e.g. image runs as root, no HEALTHCHECK.

## SBOM: where it lives
Generate at build, store alongside the image **by digest**, and attach it as a signed attestation
(`cosign attest --type cyclonedx`) so consumers can verify the SBOM belongs to that exact image and
was produced by the trusted pipeline. A copy goes to the evidence store for audit; a dependency
inventory service (e.g. Dependency-Track) ingests it so new CVEs can be matched to deployed
artifacts without rebuilding.

## Policy gate
Raw Trivy `--exit-code` is blunt. `scripts/scan_gate.py` adds fix-availability, exposure-aware
thresholds, secret handling and expiring exceptions on top of the JSON (Exercise 3 ties into 1).

## Exceptions
`exceptions.example.json` shows the shape of a time-boxed exception (consumed by `scan_gate.py --exceptions`). Keep the real register in the
policy repo, reviewed by security, not scattered in individual repositories.
