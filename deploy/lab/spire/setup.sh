#!/bin/sh
# One-shot: registers the lab workloads with the SPIRE server and leaves a
# join token and the X.509 trust bundle for the agent in /run/spire/shared.
set -eu

server() { spire-server "$@" -socketPath /run/spire/server/api.sock; }
td=spiffe://td.example
node=$td/lab-node

until server healthcheck >/dev/null 2>&1; do sleep 1; done

server bundle show > /run/spire/shared/bundle.pem
if [ ! -s /run/spire/shared/join-token ]; then
  server token generate -spiffeID "$node" -ttl 3600 -output json \
    | jq -r .value > /run/spire/shared/join-token
fi

# Each lab workload is a Unix user in the agent container.
for workload in agent-a agent-b agent-z; do
  uid=$(id -u "$workload")
  if server entry show -spiffeID "$td/$workload" -output json | jq -e '.entries | length > 0' >/dev/null; then
    continue
  fi
  server entry create -parentID "$node" -spiffeID "$td/$workload" -selector "unix:uid:$uid"
done
