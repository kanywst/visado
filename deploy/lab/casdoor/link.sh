#!/bin/sh
# One-shot: links bob in Keycloak's lab realm to bob in Casdoor, so that
# Keycloak's JWT authorization grant finds the user an ID-JAG names. Casdoor
# gives each user a random ID when it imports them, so the link can only be
# made once both are up: bob's Casdoor ID is the sub of an ID token from a
# password login, and Keycloak's admin API adds it as a federated identity.
set -eu

casdoor=http://casdoor:8000
keycloak=http://keycloak:8080

retry() {
  for i in $(seq 600); do
    if "$@" 2>/tmp/err; then return 0; fi
    [ "$i" = 600 ] && { cat /tmp/err >&2; exit 1; }
    sleep 1
  done
}

# base64url payload of a JWT, as JSON.
payload() {
  cut -d. -f2 | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | base64 -d
}

retry wget -q -O /tmp/login.json \
  --post-data 'grant_type=password&client_id=agent-a&client_secret=agent-a-casdoor-secret&username=bob&password=bob-lab-password&scope=openid' \
  "$casdoor/api/login/oauth/access_token"
casdoor_id=$(jq -er .id_token /tmp/login.json | payload | jq -er .sub)

retry wget -q -O /tmp/admin.json \
  --post-data "grant_type=password&client_id=admin-cli&username=admin&password=$KEYCLOAK_ADMIN_PASSWORD" \
  "$keycloak/realms/master/protocol/openid-connect/token"
auth="Authorization: Bearer $(jq -er .access_token /tmp/admin.json)"

# The realm import finishes before the admin API answers for it.
retry wget -q -O /tmp/users.json --header "$auth" "$keycloak/admin/realms/lab/users?username=bob&exact=true"
user=$(jq -er '.[0].id' /tmp/users.json)

wget -q -O /tmp/links.json --header "$auth" "$keycloak/admin/realms/lab/users/$user/federated-identity"
linked=$(jq -r '.[] | select(.identityProvider == "casdoor") | .userId' /tmp/links.json)
if [ "$linked" = "$casdoor_id" ]; then
  echo "bob is already linked to Casdoor user $casdoor_id"
  exit 0
elif [ -n "$linked" ]; then
  # Casdoor was recreated and gave bob a new ID; Keycloak still has the old one.
  echo "bob is linked to Casdoor user $linked, not $casdoor_id: recreate keycloak and casdoor together" >&2
  exit 1
fi
wget -q -O /dev/null --header "$auth" --header 'Content-Type: application/json' \
  --post-data "{\"identityProvider\":\"casdoor\",\"userId\":\"$casdoor_id\",\"userName\":\"bob\"}" \
  "$keycloak/admin/realms/lab/users/$user/federated-identity/casdoor"
echo "linked Keycloak user bob to Casdoor user $casdoor_id"
