#!/bin/sh
# One-shot, before visado starts: fetches the td.example WIT bundle (a JWKS)
# from the SPIRE agent and writes it to /out/wit-bundle.json, which visado
# reads through [[wit_issuers]] jwks_file. Runs in the agent's PID namespace
# so the unix workload attestor can see it, as agent-a: the Workload API
# serves WIT bundles only to registered workloads.
set -eu

fetch="spire-agent api fetch wit -socketPath /run/spire/agent/api.sock -output json"

# The agent takes a few seconds after startup to receive its entries.
for i in $(seq 60); do
  if su agent-a -s /bin/sh -c "$fetch" > /tmp/wit.json 2>/tmp/err; then
    break
  fi
  [ "$i" = 60 ] && { cat /tmp/err >&2; exit 1; }
  sleep 1
done

# The CLI prints each bundle as a JSON string.
jq -e '[.[] | .bundles? // empty | .["spiffe://td.example"]][0] | fromjson | select(.keys | length > 0)' \
  /tmp/wit.json > /out/wit-bundle.json.tmp
mv /out/wit-bundle.json.tmp /out/wit-bundle.json
jq -r '.keys[].kid | "trusting SPIRE WIT key \(.)"' /out/wit-bundle.json
