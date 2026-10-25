#!/usr/bin/env bash
# Shared helpers for the OpenBao labs. Sourced, not executed.
# All values below are synthetic LAB values. Dev mode only.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BAO_CT="${BAO_CT:-lab-openbao}"
export BAO_ADDR_IN_CT="http://127.0.0.1:8200"
ROOT_TOKEN="lab-root-token-not-a-secret"

# bao_as <token> <args...> : run the bao CLI inside the container with a specific token
bao_as() {
  local token="$1"; shift
  docker exec -e BAO_ADDR="$BAO_ADDR_IN_CT" -e BAO_TOKEN="$token" "$BAO_CT" bao "$@"
}
bao() { bao_as "$ROOT_TOKEN" "$@"; }

require_lab() {
  command -v jq >/dev/null || { echo "jq is required"; exit 1; }
  docker ps --format '{{.Names}}' | grep -qx "$BAO_CT" \
    || { echo "OpenBao container '$BAO_CT' not running. Run: make openbao-up"; exit 1; }
  # wait for readiness
  for _ in $(seq 1 30); do
    bao status >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "OpenBao did not become ready"; exit 1
}

# x509 inspection: host openssl if present, else a throwaway container
inspect_cert() {
  local file="$1"
  if command -v openssl >/dev/null; then
    openssl x509 -in "$file" -noout -subject -issuer -serial -dates -ext subjectAltName,keyUsage,extendedKeyUsage
  else
    docker run --rm -i alpine/openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName,keyUsage,extendedKeyUsage < "$file"
  fi
}

banner() { printf '\n=== %s ===\n' "$*"; }
