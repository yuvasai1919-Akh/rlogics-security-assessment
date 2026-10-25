# OpenBao: production design delta and production-thinking questions

Verify feature specifics (HA modes, replication, managed keys/HSM options, OCSP) against the docs of
the OpenBao version you would deploy; the project evolves quickly.

## What the lab does vs what production needs
| Area | Lab (this repo) | Production |
|------|-----------------|-----------|
| Mode | `-dev`: in-memory, auto-unsealed, root token fixed | Real server config, **auto-unseal** (cloud KMS/HSM/transit), no standing root token (generate-root only for break-glass) |
| Storage | In memory (gone on restart) | **Integrated Raft**, 3 or 5 nodes across failure domains, encrypted volumes, tested **snapshots** + off-site backup, restore drills |
| Transport | HTTP | **TLS everywhere** (listener TLS, mTLS to clients where practical, `verify-full` to DB) |
| CA hierarchy | Root + intermediate both online in one instance | **Root offline** (or a separate, tightly controlled OpenBao/HSM) signs intermediates; online intermediate(s) per environment/tenant; consider separate issuing CAs per trust domain |
| CA key protection | In memory | Non-exportable keys; HSM/KMS-backed where supported; documented key ceremony, split custody, offline encrypted backups |
| AuthN | Root token / hand-made tokens | Workload identity: Kubernetes auth or JWT/OIDC with projected service account tokens; humans via OIDC SSO + MFA |
| AuthZ | One demo policy | Least-privilege policies per app/env, templated on identity metadata (namespace/service account); policy changes via PR + review |
| Audit | None | **Audit devices enabled and mandatory** (OpenBao blocks requests if no audit device can write); ship to immutable store/SIEM; alert on `sys/` changes, root-token use, failed auth spikes |
| DB mgmt account | Static lab password | Dedicated least-privilege account; **rotate-root** so no human knows it; DB over TLS; network-restricted |
| Operations | Manual | IaC for mounts/roles/policies, monitoring (seal status, lease counts, latency, cert expiries), upgrade and DR runbooks |

## Production-thinking questions

### How would Kubernetes workloads authenticate to OpenBao?
Use platform identity, not a shared token. Options: the **Kubernetes auth method** (the workload
presents its service account JWT; OpenBao validates it through the API server's TokenReview) or the
**JWT/OIDC method** validating *projected, audience-bound, short-lived* service account tokens
(avoids giving OpenBao broad API-server access). Each auth *role* binds to a specific service account
name **and** namespace, maps to a narrow policy, and issues a short-TTL token (minutes) with a low
`max_ttl`. Delivery: a sidecar/agent, CSI provider or operator that authenticates and renews on the
pod's behalf so app code never handles the OpenBao token. Avoid static root/long-lived tokens, avoid
sharing one role across namespaces, and avoid mounting the default service account token where not
needed.

### What happens if OpenBao is unavailable?
Decide per credential type, deliberately:
- **Existing leases/certs keep working until expiry** (the DB and the TLS peer do not call OpenBao on each use). So TTL is your outage budget: pick TTLs that outlast a realistic incident (e.g. DB creds 1-4h renewed at ~50%, leaf certs 24h rotated at ~1/3 of lifetime) while keeping compromise windows acceptable.
- **New issuance fails -> fail closed.** A pod that cannot obtain credentials should not start with a hard-coded fallback ("fail open" to a static password defeats the design). Readiness probes should reflect "no valid credential".
- Apps must **retry with backoff and jitter**, renew early, and keep running with current credentials; cache in memory only.
- **HA:** multi-node Raft across zones, auto-unseal so a restart does not need humans, load-balanced health-checked endpoints, tested backup/restore, alerting on seal/leader loss. Rehearse "OpenBao is down for 2 hours" as a game day.

### How should CA keys be protected?
Root offline (air-gapped or HSM-resident), used only to sign/renew intermediates in a scripted,
witnessed ceremony with M-of-N custody and recorded evidence. Intermediate keys generated *inside*
the secrets platform as non-exportable (`internal`) or HSM/KMS-backed managed keys, with strict
policy on `pki*/root/*`, `config/*`, key import/export paths and `sys/` operations. Encrypted offline
backups with split custody, tested restores, planned rotation (overlapping intermediates so trust
rolls over without outage), full audit logging, and an incident playbook for "intermediate
compromised" (revoke, rotate, re-issue, communicate).

### How do you prevent one app minting certs for another app?
Layered controls: (1) **one role per app** with `allowed_domains`/`allowed_uri_sans` limited to that
app's names, `allow_any_name=false`, `allow_subdomains=false` unless required, `enforce_hostnames`,
no wildcards, tight `max_ttl`; (2) **policy** granting each identity only `pki*/issue/<its-role>` and
never `sign`, `sign-verbatim`, `issue` on other roles or `root/*`; (3) **identity binding**: the auth
role ties a Kubernetes namespace+service account to that policy, so a pod cannot borrow another app's
rights; (4) **separate mounts/intermediates** per environment or trust domain so prod and dev cannot
cross-issue; (5) **detective**: audit-log alerting on issuance for unexpected names and certificate
transparency-style inventory of issued serials. The lab demonstrates (1) and (2): the wrong-name and
wrong-role requests in `pki_lab.sh` steps 8 and 9 are rejected.

## Database dynamic credentials in production
- Workload gets credentials at start (and re-requests when the lease cannot be renewed), usually through an agent/operator that also reloads the connection pool.
- One role per app and privilege level (read-only vs read-write), `default_ttl` small, `max_ttl` bounded, revocation statements that terminate sessions and drop the role.
- Mgmt account: dedicated, least-privilege, **rotated by OpenBao**, TLS to DB, connection allow-listed to OpenBao.
- Watch connection and role churn; some databases need tuning (role creation cost, pooler compatibility).
