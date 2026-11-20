#!/bin/sh
# One-shot, before Envoy starts: fetches the gateway's X.509-SVID, its key and
# the td.example X.509 bundle from the SPIRE agent and writes them to /out,
# where Envoy reads them for the mTLS listener: the SVID as its server
# certificate, the bundle to validate client certificates. Runs in the agent's
# PID namespace, as the gateway user, so the unix workload attestor can see it.
set -eu

fetch="spire-agent api fetch x509 -socketPath /run/spire/agent/api.sock -write /tmp/svid"

# The agent takes a few seconds after startup to receive its entries.
mkdir -p /tmp/svid
chown gateway /tmp/svid
for i in $(seq 60); do
  if su gateway -s /bin/sh -c "$fetch" >/dev/null 2>/tmp/err; then
    break
  fi
  [ "$i" = 60 ] && { cat /tmp/err >&2; exit 1; }
  sleep 1
done

cp /tmp/svid/svid.0.pem /out/svid.pem
cp /tmp/svid/bundle.0.pem /out/bundle.pem
# Envoy runs as uid 101. A lab key; a deployment would have Envoy fetch its
# SVID over SDS instead of reading a file.
install -m 0644 /tmp/svid/svid.0.key /out/svid.key
echo "wrote the gateway X.509-SVID for Envoy"
