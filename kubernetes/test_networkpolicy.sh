#!/usr/bin/env bash
# Tests whether NetworkPolicy is actually ENFORCED by the local cluster's CNI.
#   allowed client (label access=assessment-web)  -> expect RESULT=ALLOWED
#   denied client  (no label)                     -> expect RESULT=BLOCKED
# If the denied client reports ALLOWED, your CNI does not enforce NetworkPolicy: the YAML is correct
# but provides NO protection. Record that as a limitation (and use kind-config-calico.yaml to fix it).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=assessment
OUT="$ROOT/evidence/k8s"; mkdir -p "$OUT"
exec > >(tee "$OUT/networkpolicy-test.txt") 2>&1

kubectl -n "$NS" get deploy assessment-web >/dev/null 2>&1 || { echo "Deploy first: make k8s-deploy"; exit 1; }
kubectl -n "$NS" rollout status deploy/assessment-web --timeout=120s || exit 1

WEB_IP="$(kubectl -n "$NS" get pod -l app=assessment-web -o jsonpath='{.items[0].status.podIP}')"
echo "web pod IP: $WEB_IP"
kubectl apply -f "$ROOT/kubernetes/hardened/tests/np-test-egress.yaml" >/dev/null

run_client() {  # run_client <manifest> <podname>
  sed "s/WEB_IP/${WEB_IP}/" "$1" | kubectl apply -f - >/dev/null
  for _ in $(seq 1 30); do
    phase="$(kubectl -n "$NS" get pod "$2" -o jsonpath='{.status.phase}' 2>/dev/null)"
    [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ] && break
    sleep 2
  done
  kubectl -n "$NS" logs "$2" 2>&1 | tail -n 3
  kubectl -n "$NS" delete pod "$2" --wait=false >/dev/null
}

echo; echo "--- client WITH label access=assessment-web ---"
run_client "$ROOT/kubernetes/hardened/tests/client-allowed.yaml" np-client-allowed
echo; echo "--- client WITHOUT the label ---"
run_client "$ROOT/kubernetes/hardened/tests/client-denied.yaml" np-client-denied

kubectl delete -f "$ROOT/kubernetes/hardened/tests/np-test-egress.yaml" >/dev/null
echo; echo "Expected: first RESULT=ALLOWED, second RESULT=BLOCKED."
