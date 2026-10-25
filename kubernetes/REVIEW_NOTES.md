# Exercise 5 - Review notes (draft; verify against your own scan output)

## 1. Review of the unsafe baseline - ranked by risk

| Rank | Issue | Why it matters | Verdict |
|------|-------|----------------|---------|
| 1 | `privileged: true` | Disables most container isolation: all capabilities, access to host devices, can load kernel modules / mount host filesystems. A container compromise becomes a node compromise. | **Deployment blocker** |
| 2 | `hostPath: /` mounted at `/host` (read/write) | Entire node filesystem exposed: kubelet credentials and kubeconfigs, other pods' secrets and volumes, container runtime socket, `/etc/shadow`. Alone it is enough to take over the node; with #1 it is trivial. | **Deployment blocker** |
| 3 | `hostNetwork: true` | Pod shares the node's network namespace: reach node-local services (kubelet, metadata endpoints, localhost-bound admin ports), sniff traffic, bypass NetworkPolicy semantics, port conflicts. | **Deployment blocker** for general workloads |
| 4 | `runAsUser: 0` | Root inside the container amplifies #1-#3 and many kernel/runtime escape bugs. | **Blocker** in production namespaces |
| 5 | `image: nginx:latest` | Mutable, unpredictable, unreviewed content; defeats provenance and reproducibility, makes rollbacks and incident scoping hard. | **Blocker** for prod via policy (pin tag + digest, signed) |
| 6 | Secret in plaintext `env` value | Lands in Git, `kubectl describe`, process environment, crash dumps. (Here the value is synthetic.) | **Blocker** if real; use a secret store, mount as file |
| 7 | `serviceAccountName: default` + token auto-mounted | Shared identity with a token the app does not need; stolen token = API access. | Hardening (blocker where RBAC on default SA is permissive) |
| 8 | No `securityContext` hardening: no `allowPrivilegeEscalation: false`, no dropped capabilities, no seccomp, writable root FS | Larger attack surface after compromise. | Hardening |
| 9 | No resource requests/limits | Noisy-neighbour/DoS, node pressure, unfair scheduling. | Hardening (blocker under quota policies) |
| 10 | No namespace specified (lands in `default`), no NetworkPolicy | No isolation or blast-radius control. | Hardening |
| 11 | No probes, single replica, no PDB | Availability, not confidentiality. | Hardening |

## 2. What changed in the hardened version (`hardened/`)
Dedicated namespace with PSA `restricted`; dedicated ServiceAccount with token automount disabled;
RBAC limited to a named ConfigMap `get` (pattern example); ResourceQuota + LimitRange; non-root
(`nginx-unprivileged`, UID 101); `allowPrivilegeEscalation: false`; all capabilities dropped;
`seccompProfile: RuntimeDefault`; read-only root filesystem with small `emptyDir` mounts for the
paths nginx must write; requests/limits; probes; 2 replicas + PDB; secret mounted as a read-only
file; no host namespaces or hostPath; image pinned by tag with a **digest-pinning option**
(`PIN_DIGEST=1`); default-deny NetworkPolicy plus a narrow allow rule.

## 3. NetworkPolicy and local limitations
- Policy: default deny (ingress+egress); only pods labelled `access=assessment-web` may reach port 8080; no egress for the web pods (static content needs none).
- **Enforcement depends on the CNI.** NetworkPolicy objects are accepted by the API server regardless, but only a policy-aware CNI enforces them. Docker Desktop's/Rancher Desktop's built-in Kubernetes and kind's default CNI may not (or may not by default). `test_networkpolicy.sh` proves it empirically: if the unlabelled client gets through, enforcement is absent and the policy is decorative. Use `kind-config-calico.yaml` (or Cilium) for a faithful test.
- Record your Kubernetes version, runtime and what you observed in `evidence/k8s/environment.txt`.

## 4. Scanners
- **Trivy config** and optionally **Kubescape** run statically against `review-input/` (never deployed) and `hardened/` (`make k8s-scan`).
- Expect the unsafe file to produce many HIGH/CRITICAL-class results (privileged, host network, hostPath, root, latest tag, missing limits, no seccomp, ...). Check your own output for the exact IDs.
- Expect the hardened set to be much cleaner. **Explain the remainder** rather than hiding it - e.g. image tag pinning (tag vs digest), a ConfigMap-reading Role that is a pattern example, or checks that ask for a service mesh/other platform controls. Interpreting residual findings is the skill being assessed.

## 5. kube-bench
kube-bench checks a node and control plane against the **CIS Kubernetes Benchmark** by inspecting
kubelet/API-server/etcd flags, file permissions and config paths on the host. It is run as a Job with
host access (hostPID, host path mounts), or directly on nodes.
- **On Docker/Rancher Desktop and kind it is of limited meaning:** the "node" is a VM or a container, file paths and process layouts differ from a real kubeadm node, the control plane is managed by the tool, and many checks are N/A or false findings. Running it is still a fine learning exercise in a *disposable kind cluster*; record what it said and why it is not authoritative.
- **Where it belongs:** real cluster nodes (kubeadm/self-managed), using the benchmark variant matching the distribution (managed services such as EKS/GKE/AKS have their own variants), scheduled (e.g. weekly) with results shipped to the evidence store, and after upgrades/node image changes.
- The kube-bench Job needs privileged host access by design - another reason not to run it casually on a machine that matters.

## 6. Kyverno
- **Policy API note (checked Oct 2026):** Kyverno deprecated `ClusterPolicy` in 1.17 and plans to remove it in v1.20 (scheduled around Oct/Nov 2026). The policies here use the replacement CEL-based `ValidatingPolicy` / `ImageValidatingPolicy` (`policies.kyverno.io/v1`). Legacy `ClusterPolicy` versions are in `policies/legacy/` for Kyverno <= 1.19. Record which Kyverno version you installed.
- `policies/disallow-privileged.yaml` and `policies/require-run-as-nonroot.yaml` (Deny; system namespaces excluded so cluster components are not bricked). **These were written from the docs and not run against a live cluster when this repo was generated** - expect to fix field names with `kubectl explain` if your version differs, and say so honestly.
- `make k8s-demo` proves deny/allow with **server-side dry-run** (nothing is persisted) and also shows the built-in PSA layer rejecting the same privileged pod.
- `policies/examples/verify-image-signature.yaml` shows Cosign verification at admission (`ImageValidatingPolicy`).
- Because the policies match `Pod`, a bad Deployment is accepted by the API but its Pods are rejected (ReplicaSet events show why). Kyverno's `spec.autogen.podControllers` can generate controller-level rules to reject earlier - a good "what I'd improve" point.

### Cosign verification at admission with Kyverno (explanation)
An `ImageValidatingPolicy` (formerly `verifyImages` inside a ClusterPolicy) matches pod images by
reference (`matchImageReferences`) and verifies each one against the configured Cosign attestor - a
public key (lab) or a **keyless identity** (OIDC issuer + subject, backed by a Fulcio certificate and
the Rekor log, production) - and can additionally require signed **attestations** (SBOM, vuln scan,
provenance). `validationConfigurations.mutateDigest` rewrites the tag to the verified digest so what was
verified is exactly what runs; `verifyDigest`/`required` reject unsigned or tag-only references;
`failurePolicy: Fail` means a webhook outage blocks rather than allows. Start in Audit to measure, then Enforce, with
exceptions for system namespaces and a documented break-glass.

## 7. Which controls belong where
- **CI (shift-left, fast feedback):** manifest/IaC scanning (Trivy config/Kubescape), Kyverno CLI tests of policies against rendered manifests, image build/scan/SBOM/signing, secret scanning. Catches mistakes cheaply, but can be bypassed - it is advice, not enforcement.
- **Admission control (the enforcement point):** PSA `restricted`, Kyverno/ValidatingAdmissionPolicy invariants (no privileged, non-root, no hostPath/hostNetwork, resource limits, allowed registries), and Cosign signature/attestation verification by digest. This is where a bypassed CI is caught, because nothing reaches the cluster without passing.
- **Continuous runtime assurance:** posture and drift re-evaluation (Kubescape/Trivy operator, Kyverno background scans/reports), kube-bench on real nodes, runtime detection (Falco/Tetragon-style syscall/behaviour monitoring), NetworkPolicy flow monitoring, scheduled re-scans of running images for new CVEs, audit-log collection, and evidence export. These catch change after deployment (new CVEs, manual `kubectl edit`, compromised workloads).
