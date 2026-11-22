#!/bin/sh
# One-shot, before visado starts: waits for Keycloak to serve the lab realm,
# then writes the realm's signing keys (a JWKS) to /out/jwks.json, which
# visado reads through [[oauth_issuers]] jwks_file. Keycloak's JWKS also
# lists its encryption key; only keys with use "sig" are kept.
set -eu

certs=http://keycloak:8080/realms/lab/protocol/openid-connect/certs

# Keycloak takes a while to build and import the realm on first start.
for i in $(seq 600); do
  if wget -q -O /tmp/certs.json "$certs" 2>/tmp/err; then
    break
  fi
  [ "$i" = 600 ] && { cat /tmp/err >&2; exit 1; }
  sleep 1
done

jq -e '{keys: [.keys[] | select(.use == "sig")]} | select(.keys | length > 0)' \
  /tmp/certs.json > /out/jwks.json.tmp
mv /out/jwks.json.tmp /out/jwks.json
jq -r '.keys[] | "trusting Keycloak key \(.kid) (\(.alg))"' /out/jwks.json
