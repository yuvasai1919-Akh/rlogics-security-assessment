#!/usr/bin/env bash
# OpenBao database secrets engine lab (PostgreSQL). LAB ONLY (dev mode, synthetic passwords).
# Shows: mgmt connection -> role -> dynamic credential + lease -> permitted use -> denied use
#        -> renew -> revoke -> natural expiry.
# Evidence: evidence/openbao/db-<timestamp>/
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../_common.sh"
require_lab

OUT="$ROOT/evidence/openbao/db-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
exec > >(tee "$OUT/transcript.txt") 2>&1
PG_CT="lab-postgres"

# psql inside the postgres container. -h 127.0.0.1 forces password auth (the unix socket is 'trust').
psql_as() {  # psql_as <user> <password> <sql>
  docker exec -e PGPASSWORD="$2" "$PG_CT" psql -h 127.0.0.1 -U "$1" -d labdb -tA -c "$3"
}

banner "Wait for PostgreSQL"
for _ in $(seq 1 30); do
  docker exec "$PG_CT" pg_isready -U lab_admin -d labdb >/dev/null 2>&1 && break
  sleep 1
done

banner "1. Enable the database engine and configure the connection with the DEDICATED mgmt account"
bao secrets enable database >/dev/null
bao write database/config/lab-postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles="app-readonly,app-short" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/labdb?sslmode=disable" \
  username="bao_mgmt" password="lab-mgmt-password-not-a-secret" >/dev/null
echo "configured (sslmode=disable is a LAB shortcut; production requires verify-full TLS)"

if [ "${ROTATE_ROOT:-0}" = "1" ]; then
  banner "1b. Rotate the mgmt password so ONLY OpenBao knows it (re-run 'make openbao-down openbao-up' afterwards)"
  bao write -force database/rotate-root/lab-postgres
fi

banner "2. Define roles that generate TIME-LIMITED, read-only credentials"
CREATE_SQL="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; GRANT USAGE ON SCHEMA public TO \"{{name}}\";"
bao write database/roles/app-readonly db_name=lab-postgres creation_statements="$CREATE_SQL" default_ttl=5m max_ttl=15m >/dev/null
bao write database/roles/app-short    db_name=lab-postgres creation_statements="$CREATE_SQL" default_ttl=20s max_ttl=1m  >/dev/null
bao read database/roles/app-readonly

banner "3. Request a dynamic credential (observe username, lease_id, lease_duration)"
bao read -format=json database/creds/app-readonly > "$OUT/cred-1.json"
USER1="$(jq -r '.data.username' "$OUT/cred-1.json")"
PASS1="$(jq -r '.data.password' "$OUT/cred-1.json")"
LEASE1="$(jq -r '.lease_id' "$OUT/cred-1.json")"
echo "username      : $USER1"
echo "lease_id      : $LEASE1"
echo "lease_duration: $(jq -r '.lease_duration' "$OUT/cred-1.json")s"
# The password is shown to you only in the JSON on disk of YOUR lab; it is not echoed and is synthetic.
rm -f "$OUT/cred-1.json"   # do not keep even synthetic passwords in evidence

banner "4. PERMITTED action: SELECT with the dynamic credential"
psql_as "$USER1" "$PASS1" "SELECT count(*) AS orders_visible FROM orders;" | tee "$OUT/permitted-select.txt"

banner "5. DENIED action: INSERT (role was granted SELECT only)"
psql_as "$USER1" "$PASS1" "INSERT INTO orders (customer, amount) VALUES ('x', 1);" 2>&1 | tee "$OUT/denied-insert.txt" || true

banner "6. Lease inspection and renewal"
bao lease lookup "$LEASE1" | tee "$OUT/lease-lookup.txt"
bao lease renew -increment=600 "$LEASE1" | tee "$OUT/lease-renew.txt" || true

banner "7. Explicit revocation: credential stops working immediately"
bao lease revoke "$LEASE1"
sleep 1
psql_as "$USER1" "$PASS1" "SELECT 1;" 2>&1 | tee "$OUT/after-revoke.txt" || echo "(login rejected as expected)"

banner "8. Natural expiry: 20-second credential, poll until login fails"
bao read -format=json database/creds/app-short > "$OUT/cred-2.json"
USER2="$(jq -r '.data.username' "$OUT/cred-2.json")"
PASS2="$(jq -r '.data.password' "$OUT/cred-2.json")"
rm -f "$OUT/cred-2.json"
echo "issued $USER2 with a 20s TTL"
psql_as "$USER2" "$PASS2" "SELECT 'works while the lease is valid';" | tee "$OUT/short-valid.txt"
EXPIRED=0
for i in $(seq 1 24); do   # up to ~2 minutes
  sleep 5
  if ! psql_as "$USER2" "$PASS2" "SELECT 1;" >/dev/null 2>&1; then
    echo "credential rejected after ~$((i*5))s - lease expired and role was dropped"
    EXPIRED=1; break
  fi
done
echo "expired_naturally=$EXPIRED" | tee "$OUT/short-expiry.txt"

banner "9. Roles still present in PostgreSQL (should not contain the dynamic users anymore)"
psql_as lab_admin "lab-admin-password-not-a-secret" "SELECT rolname FROM pg_roles WHERE rolname LIKE 'v-%';" | tee "$OUT/remaining-dynamic-roles.txt" || true

banner "Done"
echo "Evidence directory: ${OUT#$ROOT/}"
