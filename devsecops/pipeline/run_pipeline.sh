#!/usr/bin/env bash
# Local DevSecOps pipeline. Usage: run_pipeline.sh [vulnerable|remediated]
#
# Behaviour: run EVERY stage, record pass/fail, then exit non-zero if any gate failed.
# Rationale: one run should give developers the complete picture instead of stopping at the first
# failure. In CI the same stages are separate jobs so they run in parallel and report independently.
#
# Tools run as containers so nothing needs installing and versions are explicit.
# SAFETY: the target is the local lab app only, published on 127.0.0.1. Never point ZAP elsewhere.
set -uo pipefail

MODE="${1:-vulnerable}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$MODE" in
  vulnerable) SRC_REL="devsecops/app-or-lab-target" ;;
  remediated) SRC_REL="devsecops/remediated" ;;
  *) echo "usage: $0 [vulnerable|remediated]"; exit 2 ;;
esac

# Pin these in production (by digest). :latest is acceptable only for a throwaway lab.
SEMGREP_IMG="${SEMGREP_IMG:-semgrep/semgrep:latest}"
TRIVY_IMG="${TRIVY_IMG:-aquasec/trivy:latest}"
ZAP_IMG="${ZAP_IMG:-ghcr.io/zaproxy/zaproxy:stable}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_REL="evidence/runs/${STAMP}-${MODE}"
OUT="$ROOT/$OUT_REL"
mkdir -p "$OUT"
chmod 777 "$OUT"   # ZAP runs as a non-root user inside its container and writes reports here

IMG="lab-app:${MODE}"
NET="lab-net"
APP_CT="lab-app"
FAIL=0
SUMMARY=()

stage() {  # stage <name> <command...>
  local name="$1"; shift
  echo; echo "=== [${name}] ==="
  if "$@"; then
    SUMMARY+=("PASS  ${name}")
  else
    local rc=$?
    SUMMARY+=("FAIL  ${name} (exit ${rc})")
    FAIL=1
  fi
}

trivy_c() {  # trivy in a container, repo mounted at /repo, docker socket for image scans
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$ROOT:/repo" -w /repo \
    -v lab-trivy-cache:/root/.cache/ \
    "$TRIVY_IMG" "$@"
}

# ---------------------------------------------------------------- 1. SAST
sast() {
  docker run --rm -v "$ROOT:/repo" -w /repo "$SEMGREP_IMG" \
    semgrep scan --config p/python --config devsecops/sast/rules --metrics=off \
    --severity ERROR --error \
    --sarif-output "$OUT_REL/semgrep.sarif" --json-output "$OUT_REL/semgrep.json" \
    "$SRC_REL" | tee "$OUT/semgrep.txt"
  return "${PIPESTATUS[0]}"
}

# ---------------------------------------------------------------- 2. Source SCA + secrets + misconfig
trivy_fs() {
  trivy_c fs --scanners vuln,secret,misconfig --format json --output "$OUT_REL/trivy-fs.json" "$SRC_REL" || return $?
  trivy_c fs --scanners vuln,secret,misconfig --format table --output "$OUT_REL/trivy-fs.txt" "$SRC_REL" || return $?
  python3 "$ROOT/scripts/scan_gate.py" --trivy "$OUT/trivy-fs.json" \
      --fail-on HIGH --only-fixable --markdown "$OUT/gate-fs.md" --csv "$OUT/gate-fs.csv"
}

# ---------------------------------------------------------------- 3. Build + image scan
build() { DOCKER_CONFIG="$(mktemp -d)" docker build -t "$IMG" "$ROOT/$SRC_REL"; }

trivy_image() {
  trivy_c image --format json --output "$OUT_REL/trivy-image.json" "$IMG" || return $?
  python3 "$ROOT/scripts/scan_gate.py" --trivy "$OUT/trivy-image.json" \
      --fail-on HIGH --only-fixable --markdown "$OUT/gate-image.md" --csv "$OUT/gate-image.csv"
}

# ---------------------------------------------------------------- 4. SBOM
sbom() {
  trivy_c image --format cyclonedx --output "$OUT_REL/sbom.cdx.json" "$IMG" || return $?
  trivy_c image --format spdx-json --output "$OUT_REL/sbom.spdx.json" "$IMG"
}

# ---------------------------------------------------------------- 5. DAST (baseline = passive)
dast() {
  docker network create "$NET" >/dev/null 2>&1 || true
  docker rm -f "$APP_CT" >/dev/null 2>&1 || true
  # Published to localhost ONLY. The vulnerable app must never be reachable from the LAN.
  docker run -d --name "$APP_CT" --network "$NET" -p 127.0.0.1:8000:8000 "$IMG" >/dev/null || return 1
  for _ in $(seq 1 30); do
    curl -fs http://127.0.0.1:8000/health >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fs http://127.0.0.1:8000/health >/dev/null 2>&1 || { echo "app did not become healthy"; docker logs "$APP_CT" | tail -n 20; return 1; }

  # Baseline scan = spider + passive rules only. No attack payloads are sent.
  # Exit codes: 0 clean, 1 failures, 2 warnings, 3 error. We treat 0 and 2 as "ran OK" here and let
  # the report speak; a stricter pipeline would parse the JSON and gate on specific alerts.
  docker run --rm --network "$NET" -v "$OUT:/zap/wrk:rw" "$ZAP_IMG" \
    zap-baseline.py -t "http://${APP_CT}:8000" -J zap-baseline.json -r zap-baseline.html
  local rc=$?
  docker rm -f "$APP_CT" >/dev/null 2>&1 || true
  [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ] || return "$rc"
}

# ---------------------------------------------------------------- 6. Sign + verify
sign() { DOCKER_CONFIG="$(mktemp -d)" bash "$ROOT/devsecops/signing/cosign_lab.sh" "$MODE" "$OUT_REL"; }

stage "SAST (Semgrep)"            sast
stage "SCA+secrets+misconfig fs"  trivy_fs
stage "Build image"               build
stage "Image scan + gate"         trivy_image
stage "SBOM (CycloneDX+SPDX)"     sbom
stage "DAST baseline (ZAP)"       dast
stage "Sign + verify (Cosign)"    sign

echo; echo "================ PIPELINE SUMMARY (${MODE}) ================"
printf '%s\n' "${SUMMARY[@]}" | tee "$OUT/summary.txt"
echo "Evidence: $OUT_REL"
if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: BLOCKED (at least one gate failed)"; exit 1
fi
echo "RESULT: PASSED"
