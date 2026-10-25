#!/usr/bin/env bash
# Checks that the lab tooling is present. Read-only; changes nothing.
set -u
ok=0; missing=0
check() {
  local bin="$1" ver_cmd="$2" required="${3:-yes}"
  if command -v "$bin" >/dev/null 2>&1; then
    printf '  [ok]      %-10s %s\n' "$bin" "$(eval "$ver_cmd" 2>&1 | head -n1)"
    ok=$((ok+1))
  else
    printf '  [missing] %-10s (%s)\n' "$bin" "$required"
    [ "$required" = "yes" ] && missing=$((missing+1))
  fi
}
echo "Core tools"
check docker  "docker --version"
check git     "git --version"
check python3 "python3 --version"
check curl    "curl --version"
check jq      "jq --version"
echo "Kubernetes tools (Exercise 5)"
check kubectl "kubectl version --client"
check kind    "kind version"
check helm    "helm version --short" optional
echo "Optional local CLIs (the pipeline uses containers instead)"
check semgrep "semgrep --version" optional
check trivy   "trivy --version"   optional
check cosign  "cosign version"    optional
check kyverno "kyverno version"   optional

echo
if docker info >/dev/null 2>&1; then
  echo "Docker daemon: reachable"
else
  echo "Docker daemon: NOT reachable - start Docker/Rancher Desktop"; missing=$((missing+1))
fi
echo
[ "$missing" -eq 0 ] && echo "Preflight OK" || { echo "Preflight: $missing required item(s) missing"; exit 1; }
