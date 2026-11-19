#!/bin/sh
# One-shot, before visado starts: fetches the td.example WIT bundle (a JWKS)
# from the SPIRE agent and writes visado's configuration to /etc/visado, with
# one [[wit_issuers]] key file per bundle key. Runs in the agent's PID
# namespace so the unix workload attestor can see it, as agent-a: the
# Workload API serves WIT bundles only to registered workloads.
set -eu

out=/etc/visado
fetch="spire-agent api fetch wit -socketPath /run/spire/agent/api.sock -output json"

# The agent takes a few seconds after startup to receive its entries.
for i in $(seq 60); do
  if su agent-a -s /bin/sh -c "$fetch" > /tmp/wit.json 2>/tmp/err; then
    break
  fi
  [ "$i" = 60 ] && { cat /tmp/err >&2; exit 1; }
  sleep 1
done

rm -rf "$out/keys"
cp -r /lab/keys "$out/keys"
cp /lab/visado.toml "$out/visado.toml"

jwks=$(jq -er '.[] | .bundles? // empty | .["spiffe://td.example"]' /tmp/wit.json)
{
  echo
  echo "# Written by spire/wit-config.sh from the SPIRE WIT bundle."
  echo "[[wit_issuers]]"
  echo 'trust_domain = "td.example"'
  echo 'issuer = "https://spire.td.example"'
  echo "keys = ["
} >> "$out/visado.toml"
for kid in $(echo "$jwks" | jq -r '.keys[].kid'); do
  # SPIRE's bundle keys carry no "alg"; visado requires one.
  echo "$jwks" | jq -e --arg kid "$kid" \
    '.keys[] | select(.kid == $kid and .kty == "EC" and .crv == "P-256") | {alg: "ES256", kty, crv, x, y}' \
    > "$out/keys/spire-wit-$kid.jwk.json"
  echo "  { kid = \"$kid\", jwk_file = \"keys/spire-wit-$kid.jwk.json\" }," >> "$out/visado.toml"
  echo "trusting SPIRE WIT key $kid"
done
echo "]" >> "$out/visado.toml"
