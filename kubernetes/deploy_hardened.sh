#!/usr/bin/env bash
# Deploys ONLY the hardened manifests. The unsafe review input is never applied by this repo.
# Optional: PIN_DIGEST=1 resolves the image digest and substitutes it before applying.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
H="$ROOT/kubernetes/hardened"
IMG_TAG="nginxinc/nginx-unprivileged:1.27-alpine"

kubectl config current-context
echo "Applying to the context above. Expected: a local lab cluster (kind-rlogics-lab, docker-desktop, rancher-desktop)."
case "$(kubectl config current-context)" in
  kind-*|docker-desktop|rancher-desktop|minikube) ;;
  *) echo "Refusing: current context does not look like a local lab cluster."; exit 1 ;;
esac

kubectl apply -f "$H/00-namespace.yaml"

# Synthetic lab secret, created at deploy time so it never lives in Git.
kubectl -n assessment create secret generic assessment-web-demo \
  --from-literal=DEMO_PASSWORD="assessment-only-not-a-real-secret" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "$H/10-rbac.yaml" -f "$H/20-quota-limits.yaml" -f "$H/40-service.yaml" -f "$H/50-networkpolicy.yaml"

if [ "${PIN_DIGEST:-0}" = "1" ]; then
  docker pull "$IMG_TAG" >/dev/null
  DIGEST_REF="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMG_TAG")"
  echo "Pinning image to $DIGEST_REF"
  sed "s|image: ${IMG_TAG}|image: ${DIGEST_REF}|" "$H/30-deployment.yaml" | kubectl apply -f -
else
  kubectl apply -f "$H/30-deployment.yaml"
fi

kubectl -n assessment rollout status deploy/assessment-web --timeout=180s
kubectl -n assessment get pods,svc,networkpolicy -o wide
