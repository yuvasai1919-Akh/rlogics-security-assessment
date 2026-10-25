# Exercise 2 Part A - Concepts (draft; rewrite in your own words)

## PKI building blocks
| Term | What it is |
|------|-----------|
| **Root CA** | Self-signed trust anchor. Clients trust it directly. Its private key signs intermediates only. |
| **Intermediate CA** | CA certificate signed by the root. Issues leaf certificates day to day, so the root stays protected and a compromised intermediate can be revoked and replaced without replacing the root trust anchor everywhere. |
| **Leaf (end-entity) certificate** | The certificate a workload/server presents. Binds a public key to names (SANs) and usage (server/client auth). Cannot sign other certificates. |
| **Private key** | The secret half of the key pair. Possession proves identity. Should be generated where it will be used and never leave. |
| **CSR** | Certificate Signing Request: the public key + requested names, signed with the private key to prove possession. The CA decides what to actually issue. |
| **Certificate chain** | leaf -> intermediate(s) -> root. Clients validate each signature up to a trusted root and check names, validity and usage along the way. |
| **CRL / OCSP** | Revocation signals. CRL is a signed list of revoked serials; OCSP answers "is serial X revoked?" per certificate. Both depend on availability and client behaviour (many clients soft-fail). |
| **TTL** | Validity window. The shorter it is, the smaller the exposure after key theft, and the less you depend on revocation actually working. |

## Why the production root is protected and used mostly to sign intermediates
The root key is the ultimate trust anchor: anyone holding it can mint a certificate for any name that
all your clients will accept, and re-establishing trust means redistributing a new root everywhere.
So it is generated and kept offline (air-gapped host or HSM), used rarely in a documented ceremony
with split custody (M-of-N), and its only routine job is signing intermediate CA certificates. Online
intermediates (in OpenBao) take the risk of day-to-day issuance; compromise there is contained by
revoking one intermediate.

## Short-lived certificates / DB credentials: advantages vs trade-offs
**Advantages:** a stolen credential is useful for minutes/hours, not months; revocation matters less;
rotation is the normal path rather than a rare, risky event; per-workload unique credentials give
attributable audit trails (you can tell *which* instance did a query); no shared long-lived password
to leak in repos, tickets and chat.

**Trade-offs:** the issuer (OpenBao) becomes a critical dependency -> HA, monitoring and a plan for
outage; workloads must handle renewal/re-request correctly (connection pools, TLS reload without
restart); clock skew and TTL tuning problems; more load on the issuer and the database (role churn);
debugging is harder because credentials disappear; and you still need an authentication path for the
workload to get its first credential (the "secret zero" problem, solved with platform identity).

## Authentication vs authorisation in a secrets platform
**Authentication** answers "who is this caller?" (e.g. a Kubernetes service account JWT validated
against the API server, an OIDC token from the CI system). It yields a token with an identity and a
TTL. **Authorisation** answers "what may this identity do?" - policies attached to the token or the
auth role determine which paths it may read, which roles it may use to generate credentials, and with
what constraints. Being authenticated does not entitle you to any secret. A workload may be perfectly
authenticated and still be denied `database/creds/payments-rw` because its policy does not allow it.

## Why hard-coded database passwords are weaker
They are long-lived, shared across instances and environments, copied into repos/images/CI variables,
rarely rotated (rotation requires coordinated redeploys), impossible to attribute to one workload,
and remain valid after the leak is discovered until someone manually changes them. Dynamic
credentials flip each of those properties: unique, short-lived, auto-revoked, audited per lease.
