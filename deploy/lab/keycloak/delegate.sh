#!/bin/sh
# One-shot: lets agent-a act for any user of the lab realm (RFC 8693
# delegation, Keycloak's preview token-exchange-delegation). Keycloak only
# puts may_act in a user's token when the actor holds the `delegate` scope
# on Users through fine-grained admin permissions (FGAP V2), and a realm
# import cannot create those, so the admin API does it once the realm is up.
set -eu

keycloak=http://keycloak:8080
admin=$keycloak/admin/realms/lab

retry() {
  for i in $(seq 600); do
    if "$@" 2>/tmp/err; then return 0; fi
    [ "$i" = 600 ] && { cat /tmp/err >&2; exit 1; }
    sleep 1
  done
}

retry wget -q -O /tmp/admin.json \
  --post-data "grant_type=password&client_id=admin-cli&username=admin&password=$KEYCLOAK_ADMIN_PASSWORD" \
  "$keycloak/realms/master/protocol/openid-connect/token"
auth="Authorization: Bearer $(jq -er .access_token /tmp/admin.json)"

# The realm import finishes before the admin API answers for it.
retry wget -q -O /tmp/perms.json --header "$auth" "$admin/clients?clientId=admin-permissions"
perms=$admin/clients/$(jq -er '.[0].id' /tmp/perms.json)/authz/resource-server
wget -q -O /tmp/agent.json --header "$auth" "$admin/clients?clientId=agent-a"
agent=$(jq -er '.[0].id' /tmp/agent.json)

wget -q -O /tmp/existing.json --header "$auth" "$perms/permission/scope?name=agent-a+delegate"
if jq -e 'map(select(.name == "agent-a delegate")) | length > 0' /tmp/existing.json >/dev/null; then
  echo "agent-a already holds delegate on Users"
  exit 0
fi

post() {
  wget -q -O /dev/null --header "$auth" --header 'Content-Type: application/json' --post-data "$2" "$perms/$1"
}
post policy/client "{\"name\":\"agent-a\",\"logic\":\"POSITIVE\",\"clients\":[\"$agent\"]}"
post permission/scope '{"name":"agent-a delegate","resourceType":"Users","scopes":["delegate"],"policies":["agent-a"]}'
echo "agent-a may act for every user of the lab realm"
