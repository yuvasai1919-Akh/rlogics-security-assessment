#!/usr/bin/env bash
# Static posture scans of the unsafe review input (never deployed) and the hardened manifests.
# Trivy runs as a container; Kubescape is used too if it is installed locally.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_REL="evidence/k8s"; mkdir -p "$ROOT/$OUT_REL"
TRIVY_IMG="${TRIVY_IMG:-aquasec/trivy:latest}"

trivy_c() { docker run --rm -v "$ROOT:/repo" -w /repo -v lab-trivy-cache:/root/.cache/ "$TRIVY_IMG" "$@"; }

echo "=== Trivy config scan: UNSAFE review input (static only) ==="
trivy_c config --format json  --output "$OUT_REL/trivy-k8s-unsafe.json"  kubernetes/review-input
trivy_c config --format table --severity CRITICAL,HIGH,MEDIUM kubernetes/review-input | tee "$ROOT/$OUT_REL/trivy-k8s-unsafe.txt"

echo; echo "=== Trivy config scan: HARDENED manifests ==="
trivy_c config --format json  --output "$OUT_REL/trivy-k8s-hardened.json" kubernetes/hardened
trivy_c config --format table --severity CRITICAL,HIGH,MEDIUM kubernetes/hardened | tee "$ROOT/$OUT_REL/trivy-k8s-hardened.txt"

if command -v kubescape >/dev/null; then
  echo; echo "=== Kubescape (NSA framework): unsafe vs hardened ==="
  kubescape scan framework nsa "$ROOT/kubernetes/review-input" --format json --output "$ROOT/$OUT_REL/kubescape-unsafe.json" || true
  kubescape scan framework nsa "$ROOT/kubernetes/hardened"     --format json --output "$ROOT/$OUT_REL/kubescape-hardened.json" || true
else
  echo; echo "(kubescape not installed - optional. Install per its docs and re-run for a second opinion.)"
fi
echo; echo "Evidence in $OUT_REL. Compare unsafe vs hardened and explain any remaining findings."
