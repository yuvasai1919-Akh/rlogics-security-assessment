.PHONY: help preflight plant-secret pipeline-vuln pipeline-fixed test-gate \
        openbao-up openbao-pki openbao-db openbao-down \
        k8s-up k8s-kyverno k8s-policies k8s-policies-legacy k8s-deploy k8s-demo k8s-netpol k8s-scan k8s-down clean

SHELL := /bin/bash

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*' Makefile | grep -v '^\.PHONY' | cut -d: -f1 | sort

preflight:
	@bash scripts/preflight.sh

plant-secret:
	@bash scripts/plant_demo_secret.sh

pipeline-vuln: plant-secret
	@bash devsecops/pipeline/run_pipeline.sh vulnerable

pipeline-fixed:
	@bash devsecops/pipeline/run_pipeline.sh remediated

test-gate:
	@python3 -m unittest discover -s scripts/tests -v

# ---- Exercise 2 -------------------------------------------------------------
openbao-up:
	docker compose -f openbao/docker-compose.yml up -d
	@echo "OpenBao (dev mode, LAB ONLY): http://127.0.0.1:8200"

openbao-pki:
	@bash openbao/pki/pki_lab.sh

openbao-db:
	@bash openbao/database-secrets/db_lab.sh

openbao-down:
	docker compose -f openbao/docker-compose.yml down -v

# ---- Exercise 5 -------------------------------------------------------------
k8s-up:
	kind create cluster --name rlogics-lab --config kubernetes/kind-config.yaml
	kubectl version
	kubectl get nodes -o wide

k8s-kyverno:
	helm repo add kyverno https://kyverno.github.io/kyverno/
	helm repo update
	helm install kyverno kyverno/kyverno -n kyverno --create-namespace
	kubectl -n kyverno rollout status deploy --timeout=180s || true

k8s-policies:
	@echo "Applying CEL-based ValidatingPolicy files (non-recursive: examples/, legacy/, tests/ are NOT applied)"
	kubectl apply -f kubernetes/policies/

k8s-policies-legacy:
	@echo "Only for Kyverno <= 1.19 (ClusterPolicy is removed in 1.20)"
	kubectl apply -f kubernetes/policies/legacy/clusterpolicy-disallow-privileged.yaml -f kubernetes/policies/legacy/clusterpolicy-require-run-as-nonroot.yaml

k8s-deploy:
	@bash kubernetes/deploy_hardened.sh

k8s-demo:
	@bash kubernetes/demo_admission.sh

k8s-netpol:
	@bash kubernetes/test_networkpolicy.sh

k8s-scan:
	@bash kubernetes/scan_manifests.sh

k8s-down:
	kind delete cluster --name rlogics-lab

clean:
	rm -rf evidence/runs devsecops/signing/keys/cosign.key
