#!/usr/bin/env bash
# Cosign lab: sign an image in a LOCAL registry with a LOCAL key pair, verify it, then prove that
# a tampered image fails verification. Usage: cosign_lab.sh <mode> <evidence-dir-relative-to-repo>
#
# Local-lab simplification: key-based signing, no transparency log (--tlog-upload=false).
# Production: keyless (OIDC identity of the CI workload -> Fulcio cert -> Rekor log) and Kyverno
# verifying issuer + subject at admission. See architecture/ARCHITECTURE.md.
#
# NOTE: cosign flags changed between v2 and v3. This script pins a v2 image via COSIGN_IMG; if you
# use a newer cosign, check `cosign sign --help` and adjust the tlog/registry flags.
set -uo pipefail

MODE="${1:-vulnerable}"
OUT_REL="${2:-evidence/signing}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/$OUT_REL"; mkdir -p "$OUT"
KEYS="$ROOT/devsecops/signing/keys"; mkdir -p "$KEYS"

COSIGN_IMG="${COSIGN_IMG:-ghcr.io/sigstore/cosign/cosign:v2.4.1}"
NET="lab-net"
REG_CT="lab-registry"
LOCAL_REF="localhost:5001/lab-app:${MODE}"      # as seen from the host (docker push)
NET_REF_BASE="${REG_CT}:5000/lab-app"           # as seen from containers on lab-net

# Synthetic lab passphrase - NOT a secret. Real keys would live in KMS/HSM, never in a repo.
export COSIGN_PASSWORD="lab-only-not-a-secret"

cosign_c() {
  docker run --rm --network "$NET" -e COSIGN_PASSWORD \
    -v "$KEYS:/keys" -v "$OUT:/out" "$COSIGN_IMG" "$@"
}

docker network create "$NET" >/dev/null 2>&1 || true

# Local registry on the lab network, published on localhost only
if ! docker ps --format '{{.Names}}' | grep -qx "$REG_CT"; then
  docker rm -f "$REG_CT" >/dev/null 2>&1 || true
  docker run -d --name "$REG_CT" --network "$NET" -p 127.0.0.1:5001:5000 registry:2 >/dev/null || exit 1
  sleep 2
fi

# Key pair (private key is gitignored; public key may be committed / given to Kyverno)
if [ ! -f "$KEYS/cosign.key" ]; then
  docker run --rm -e COSIGN_PASSWORD -v "$KEYS:/keys" -w /keys "$COSIGN_IMG" generate-key-pair || exit 1
fi

# Push and resolve the immutable digest. Sign DIGESTS, not tags: tags are mutable pointers.
docker tag "lab-app:${MODE}" "$LOCAL_REF" && docker push "$LOCAL_REF" >/dev/null || exit 1
DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$LOCAL_REF" | sed 's/.*@//')"
[ -n "$DIGEST" ] || { echo "could not resolve digest"; exit 1; }
REF="${NET_REF_BASE}@${DIGEST}"
echo "Signing $REF"

cosign_c sign --yes --key /keys/cosign.key --tlog-upload=false --allow-insecure-registry --allow-http-registry "$REF" || exit 1

echo; echo "--- verify (expected: success) ---"
cosign_c verify --key /keys/cosign.pub --insecure-ignore-tlog=true --allow-insecure-registry --allow-http-registry "$REF" \
  | tee "$OUT/cosign-verify.txt"
VERIFY_RC=${PIPESTATUS[0]}

# Attach the SBOM as a signed attestation if the pipeline produced one
if [ -f "$OUT/sbom.cdx.json" ]; then
  echo; echo "--- attest SBOM (CycloneDX) ---"
  cosign_c attest --yes --key /keys/cosign.key --tlog-upload=false --allow-insecure-registry --allow-http-registry \
    --type cyclonedx --predicate /out/sbom.cdx.json "$REF" || true
fi

# Negative test: a different image pushed under another tag has a different digest and no signature
echo; echo "--- tamper test (expected: verification FAILS) ---"
printf 'FROM lab-app:%s\nLABEL tampered="true"\n' "$MODE" | docker build -q -t "localhost:5001/lab-app:tampered" - >/dev/null \
  && docker push "localhost:5001/lab-app:tampered" >/dev/null
TAMPER_DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' localhost:5001/lab-app:tampered | sed 's/.*@//')"
cosign_c verify --key /keys/cosign.pub --insecure-ignore-tlog=true --allow-insecure-registry --allow-http-registry \
  "${NET_REF_BASE}@${TAMPER_DIGEST}" 2>&1 | tee "$OUT/cosign-tamper-test.txt"
TAMPER_RC=${PIPESTATUS[0]}

echo
if [ "$VERIFY_RC" -eq 0 ] && [ "$TAMPER_RC" -ne 0 ]; then
  echo "Cosign lab OK: signed image verifies, tampered image is rejected."
  exit 0
fi
echo "Cosign lab FAILED (verify rc=$VERIFY_RC, tamper rc=$TAMPER_RC)"
exit 1
