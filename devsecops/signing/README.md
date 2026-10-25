# Artifact signing - Sigstore Cosign

## What the lab shows
1. Push the image to a local registry and resolve its **digest**.
2. Sign the digest with a local key pair (`cosign sign --key`), no transparency log (lab only).
3. `cosign verify` succeeds for the signed digest.
4. A tampered image (different digest, never signed) **fails** verification.
5. The SBOM is attached as a signed CycloneDX **attestation**.

Run: `make pipeline-fixed` (the signing step is part of it) or call
`bash devsecops/signing/cosign_lab.sh remediated evidence/signing` after building `lab-app:remediated`.

## Why signing != secure (interview prompt)
A signature proves **who** produced the artifact and that it has **not changed since** signing. It says
nothing about whether the artifact is vulnerable or malicious. A pipeline will happily sign an image
full of critical CVEs. Security comes from *what you require before signing* (scans, policy gates,
review) plus *what you verify at admission* (signature + identity + attestations). Scanned, signed and
approved are separate states; approval should be an attestation produced by policy evaluation.

## Production admission flow
```
CI (GitHub Actions, OIDC token) -> build -> scan -> SBOM -> push by digest
   -> cosign sign (keyless: Fulcio cert bound to workflow identity, entry in Rekor)
   -> cosign attest (SBOM, scan result, SLSA provenance)
Registry (immutable tags, push only by pipeline identity)
Kubernetes admission (Kyverno verifyImages):
   - signature valid, issuer = GitHub OIDC, subject = org/repo/.github/workflows/release.yml@refs/heads/main
   - required attestations present (SBOM, vuln-scan with no unmitigated criticals, provenance)
   - image referenced by digest (mutateDigest), registry on allow-list
   - failure -> deny, log decision to evidence store
```
Compromise scenarios (key, CI identity, registry) are covered in `architecture/ARCHITECTURE.md`.
A sample Kyverno `verifyImages` policy is in `kubernetes/policies/verify-image-signature.yaml`.
