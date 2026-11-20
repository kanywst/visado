#!/bin/sh
# One-shot: registers the lab workloads with the SPIRE server, leaves a join
# token and the X.509 trust bundle for the agent in /run/spire/shared, and
# writes the bundles visado trusts for mTLS and JWT-SVIDs to /out.
set -eu

server() { spire-server "$@" -socketPath /run/spire/server/api.sock; }
td=spiffe://td.example
node=$td/lab-node

until server healthcheck >/dev/null 2>&1; do sleep 1; done

server bundle show > /run/spire/shared/bundle.pem
# visado's [mtls] CA and [jwt_svid] bundle. The SPIFFE format carries the
# `use` of each key; the Workload API's JWT bundle leaves it out.
cp /run/spire/shared/bundle.pem /out/x509-bundle.pem
server bundle show -format spiffe > /out/spiffe-bundle.json
if [ ! -s /run/spire/shared/join-token ]; then
  server token generate -spiffeID "$node" -ttl 3600 -output json \
    | jq -r .value > /run/spire/shared/join-token
fi

# Each lab workload is a Unix user in the agent container. The gateway's
# X.509-SVID is Envoy's server certificate on the mTLS listener, so it also
# names the host clients connect to.
for workload in agent-a agent-b agent-z gateway; do
  uid=$(id -u "$workload")
  if server entry show -spiffeID "$td/$workload" -output json | jq -e '.entries | length > 0' >/dev/null; then
    continue
  fi
  dns=""
  [ "$workload" = gateway ] && dns="-dns tools.td.example"
  # shellcheck disable=SC2086
  server entry create -parentID "$node" -spiffeID "$td/$workload" -selector "unix:uid:$uid" $dns
done
