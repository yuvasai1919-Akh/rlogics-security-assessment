#!/usr/bin/env bash
# OpenBao PKI lab: root CA -> intermediate CA -> role -> short-lived leaf cert -> inspect,
# then prove that one app cannot mint certificates for another app.
# LAB ONLY (dev mode). Output evidence: evidence/openbao/pki-<timestamp>/
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../_common.sh"
require_lab

OUT="$ROOT/evidence/openbao/pki-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
exec > >(tee "$OUT/transcript.txt") 2>&1

banner "1. Root CA (mount: pki). In production the root is OFFLINE; here it is in-memory dev mode."
bao secrets enable -path=pki pki >/dev/null
bao secrets tune -max-lease-ttl=87600h pki >/dev/null
bao write -field=certificate pki/root/generate/internal \
  common_name="RLogics Lab Root CA (synthetic)" issuer_name="lab-root" ttl=87600h > "$OUT/root-ca.crt"
echo "root CA written to $OUT/root-ca.crt"

banner "2. Intermediate CA (mount: pki_int), signed by the root"
bao secrets enable -path=pki_int pki >/dev/null
bao secrets tune -max-lease-ttl=43800h pki_int >/dev/null
CSR="$(bao write -format=json pki_int/intermediate/generate/internal \
  common_name="RLogics Lab Intermediate CA (synthetic)" issuer_name="lab-intermediate" | jq -r '.data.csr')"
INT_CERT="$(bao write -format=json pki/root/sign-intermediate csr="$CSR" format=pem_bundle ttl=43800h | jq -r '.data.certificate')"
bao write pki_int/intermediate/set-signed certificate="$INT_CERT" >/dev/null
echo "$INT_CERT" > "$OUT/intermediate-ca.crt"

# CRL / issuing certificate URLs embedded in issued certs (lab address)
bao write pki_int/config/urls \
  issuing_certificates="http://127.0.0.1:8200/v1/pki_int/ca" \
  crl_distribution_points="http://127.0.0.1:8200/v1/pki_int/crl" >/dev/null

banner "3. Roles: one per app, constrained to that app's own name (no allow_any_name, no wildcards)"
for app in app-a app-b; do
  bao write "pki_int/roles/$app" \
    allowed_domains="${app}.svc.lab.internal" allow_bare_domains=true allow_subdomains=false \
    enforce_hostnames=true allow_any_name=false allow_ip_sans=false \
    server_flag=true client_flag=false key_type=ec key_bits=256 \
    ttl=15m max_ttl=1h >/dev/null
done
bao read pki_int/roles/app-a

banner "4. Policy + token scoped to ONE role path (stands in for workload identity)"
cat <<'HCL' | docker exec -i -e BAO_ADDR="$BAO_ADDR_IN_CT" -e BAO_TOKEN="$ROOT_TOKEN" "$BAO_CT" bao policy write app-a-issue - >/dev/null
path "pki_int/issue/app-a" { capabilities = ["create", "update"] }
HCL
APP_A_TOKEN="$(bao token create -policy=app-a-issue -ttl=15m -field=token)"

banner "5. Issue a short-lived cert for app-a using app-a's token"
bao_as "$APP_A_TOKEN" write -format=json pki_int/issue/app-a \
  common_name="app-a.svc.lab.internal" ttl=15m > "$OUT/issue-response.json"
# The private key is deliberately NOT written to disk in this demo.
jq -r '.data.certificate' "$OUT/issue-response.json" > "$OUT/leaf.crt"
SERIAL="$(jq -r '.data.serial_number' "$OUT/issue-response.json")"
echo "serial: $SERIAL   lease: $(jq -r '.lease_duration' "$OUT/issue-response.json")s"

banner "6. Inspect subject / SAN / issuer / validity (expect ~15 minutes, issuer = intermediate)"
inspect_cert "$OUT/leaf.crt" | tee "$OUT/leaf-inspection.txt"

banner "7. Verify chain: leaf -> intermediate -> root"
if command -v openssl >/dev/null; then
  openssl verify -CAfile "$OUT/root-ca.crt" -untrusted "$OUT/intermediate-ca.crt" "$OUT/leaf.crt" | tee "$OUT/chain-verify.txt"
else
  echo "(host openssl not found - skipping chain verification)"
fi

banner "8. NEGATIVE: app-a token asks for app-b's name through app-a's role (expect role-constraint error)"
bao_as "$APP_A_TOKEN" write pki_int/issue/app-a common_name="app-b.svc.lab.internal" 2>&1 | tee "$OUT/negative-wrong-name.txt" || true

banner "9. NEGATIVE: app-a token tries app-b's role path (expect permission denied)"
bao_as "$APP_A_TOKEN" write pki_int/issue/app-b common_name="app-b.svc.lab.internal" 2>&1 | tee "$OUT/negative-wrong-role.txt" || true

banner "10. Revocation and CRL (short TTLs reduce reliance on this, they do not remove it)"
bao write pki_int/revoke serial_number="$SERIAL" | tee "$OUT/revoke.txt"
curl -fs http://127.0.0.1:8200/v1/pki_int/crl/pem -o "$OUT/crl.pem" && echo "CRL fetched: $OUT/crl.pem" || echo "CRL fetch failed (non-fatal)"

banner "Done"
echo "Evidence directory: ${OUT#$ROOT/}"
echo "Next: read openbao/PRODUCTION_DESIGN.md and be ready to explain the delta."
