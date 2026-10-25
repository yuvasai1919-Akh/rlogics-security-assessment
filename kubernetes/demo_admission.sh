#!/usr/bin/env bash
# Allow/deny demonstration of the Kyverno invariants.
# SAFETY: every object is submitted with --dry-run=server, so NOTHING is persisted, even if the
# policy were missing. The script still refuses to run unless the policies are installed, so an
# "allow" never gets mistaken for proof when enforcement is absent.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/kubernetes/policies/tests"
OUT="$ROOT/evidence/k8s"; mkdir -p "$OUT"
exec > >(tee "$OUT/admission-demo.txt") 2>&1

# Current Kyverno uses ValidatingPolicy (policies.kyverno.io); <= 1.19 may still use ClusterPolicy.
for p in disallow-privileged-containers require-run-as-nonroot; do
  kubectl get validatingpolicies.policies.kyverno.io "$p" >/dev/null 2>&1 \
    || kubectl get clusterpolicy "$p" >/dev/null 2>&1 \
    || { echo "Policy '$p' is not installed. Run: make k8s-kyverno k8s-policies"; exit 1; }
done
kubectl create namespace policy-demo --dry-run=client -o yaml | kubectl apply -f - >/dev/null

PASS=0; FAILN=0
expect() {  # expect <deny|allow> <label> <manifest>
  local want="$1" label="$2" file="$3" out rc
  out="$(kubectl apply --dry-run=server -f "$file" 2>&1)"; rc=$?
  echo "--- $label (expect: $want) ---"; echo "$out"
  if [ "$want" = "deny" ] && [ $rc -ne 0 ]; then echo "=> DENIED as expected"; PASS=$((PASS+1))
  elif [ "$want" = "allow" ] && [ $rc -eq 0 ]; then echo "=> ADMITTED as expected"; PASS=$((PASS+1))
  else echo "=> UNEXPECTED RESULT (rc=$rc)"; FAILN=$((FAILN+1)); fi
  echo
}

expect deny  "privileged container"      "$T/bad-pod-privileged.yaml"
expect deny  "runs as root"              "$T/bad-pod-root.yaml"
expect allow "compliant hardened pod"    "$T/good-pod.yaml"

# Defence in depth: the namespace-level Pod Security Admission (restricted) also rejects the
# privileged pod WITHOUT Kyverno. (Only if the hardened namespace exists.)
if kubectl get ns assessment >/dev/null 2>&1; then
  tmp="$(mktemp)"; sed 's/namespace: policy-demo/namespace: assessment/' "$T/bad-pod-privileged.yaml" > "$tmp"
  expect deny "privileged pod in PSA-restricted namespace 'assessment' (built-in layer)" "$tmp"
  rm -f "$tmp"
fi

echo "Summary: $PASS expected, $FAILN unexpected"
[ "$FAILN" -eq 0 ]
