#!/usr/bin/env bash
# Runs the lab scenarios against `docker compose up` in this directory.
# Exits non-zero if any scenario does not get the expected status.
set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build -q -p visado-testkit --example lab_headers --example lab_aat --example lab_methods

tmp=$(mktemp)
hdrs=$(mktemp)
svids=$(mktemp -d)
trap 'rm -rf "$tmp" "$hdrs" "$svids"' EXIT

# Each workload fetches its WIT-SVID and private key from the SPIRE agent's
# Workload API, as the Unix user the agent attests it by.
for workload in agent-a agent-b agent-z; do
  for i in $(seq 60); do
    if docker compose -f deploy/lab/compose.yaml exec -T -u "$workload" spire-agent \
      spire-agent api fetch wit -socketPath /run/spire/agent/api.sock -output json \
      > "$svids/$workload.json" 2>/dev/null; then
      break
    fi
    if [ "$i" = 60 ]; then
      echo "no WIT-SVID for $workload from the SPIRE agent" >&2
      exit 1
    fi
    sleep 1
  done
  echo "      SPIRE issued a WIT-SVID for spiffe://td.example/$workload"
done

# agent-a's X.509-SVID, its key and the td.example X.509 bundle, written by
# `spire-agent api fetch x509 -write`.
mkdir "$svids/x509-agent-a"
docker compose -f deploy/lab/compose.yaml exec -T -u agent-a spire-agent sh -c '
  d=$(mktemp -d) &&
  spire-agent api fetch x509 -socketPath /run/spire/agent/api.sock -write "$d" >/dev/null &&
  tar -C "$d" -cf - . && rm -rf "$d"' | tar -C "$svids/x509-agent-a" -xf -
echo "      SPIRE issued an X.509-SVID for spiffe://td.example/agent-a"

# A certificate for agent-a's SPIFFE ID from a CA SPIRE does not know.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj /O=elsewhere -addext subjectAltName=URI:spiffe://td.example/agent-a \
  -keyout "$svids/other.key" -out "$svids/other.pem" 2>/dev/null

# agent-a's JWT-SVIDs: one for visado's audience, one for another service.
jwt_svid() {
  docker compose -f deploy/lab/compose.yaml exec -T -u agent-a spire-agent \
    spire-agent api fetch jwt -audience "$1" -socketPath /run/spire/agent/api.sock -output json |
    jq -r '[.[] | .svids? // empty | .[0].svid][0]'
}
jwt_tools=$(jwt_svid http://tools.td.example)
jwt_other=$(jwt_svid http://other.td.example)
echo "      SPIRE issued JWT-SVIDs for spiffe://td.example/agent-a"

headers() { ./target/debug/examples/lab_headers "$svids" "$@"; }
aat() { ./target/debug/examples/lab_aat "$svids" "$@"; }
signed() { ./target/debug/examples/lab_methods sig "$svids" "$@"; }
dpop() { ./target/debug/examples/lab_methods dpop "$@"; }
lab_bearer() { ./target/debug/examples/lab_methods bearer "$@"; }
bearer() { echo "Authorization: Bearer $1"; }
replay() { cat "$1"; }
user_token() { headers agent-a "$1" --user bob tickets.read | grep '^X-User-Token: '; }

URL=http://127.0.0.1:10000
MTLS_URL=https://tools.td.example:10443
failures=0
# Extra curl options and the URL for the next call; mtls() sets them.
conn=()
base=$URL

# call <status>[/<error code>] <name> <path> <command...>: sends the request
# the command prints and checks the status and, if given, visado's error code.
call() {
  local expect=$1 name=$2 path=$3
  shift 3
  local args=(-s -o "$tmp" -D "$hdrs" -w '%{http_code}' -H 'Host: tools.td.example')
  while IFS= read -r line; do
    case "$line" in
      "BODY: "*) args+=(--data-binary "${line#BODY: }") ;;
      "") ;;
      *) args+=(-H "$line") ;;
    esac
  done < <("$@")
  local status got rc
  : > "$tmp"
  : > "$hdrs"
  if status=$(curl ${conn[@]+"${conn[@]}"} "${args[@]}" "$base$path"); then rc=0; else rc=$?; fi
  got=$status
  # A refused TLS handshake: no HTTP status, and curl fails in the handshake
  # (35) or while reading the alert (56), not with any other connection error.
  if [ "$expect" = tls-refused ]; then
    case "$status:$rc" in
      000:35 | 000:56) got=tls-refused ;;
      *) got="$status (curl exit $rc)" ;;
    esac
  elif [ "${expect#*/}" != "$expect" ]; then
    got="$status/$(jq -r '.error // empty' "$tmp" 2>/dev/null || true)"
  fi
  if [ "$got" = "$expect" ]; then
    printf 'ok    %-58s %s\n' "$name" "$got"
  else
    printf 'FAIL  %-58s got %s, want %s: %s\n' "$name" "$got" "$expect" "$(head -c 200 "$tmp")"
    failures=$((failures + 1))
  fi
}

# resp_header <name>: that header's value in the last response, if any.
resp_header() {
  tr -d '\r' < "$hdrs" | awk -v name="$1" 'BEGIN { FS = ": " }
    tolower($1) == tolower(name) { sub(/^[^:]*: /, ""); print; exit }'
}

# expect <name> <got> <want>: checks a value that is not a status.
expect() {
  if [ "$2" = "$3" ]; then
    printf 'ok    %-58s %s\n' "$1" "$2"
  else
    printf 'FAIL  %-58s got %s, want %s\n' "$1" "$2" "$3"
    failures=$((failures + 1))
  fi
}

# dpop_with_nonce <call|agw> <label prefix>: visado requires a server nonce
# in DPoP proofs (RFC 9449 §9). The first proof gets a 401 use_dpop_nonce
# with a DPoP-Nonce header; the retry with that nonce passes and brings the
# next nonce.
dpop_with_nonce() {
  local run=$1 label=$2 nonce challenge
  "$run" 401/dpop.nonce_missing "${label}DPoP: bob's proof without a nonce" /tickets dpop /tickets
  nonce=$(resp_header dpop-nonce)
  challenge=$(resp_header www-authenticate)
  if [ -n "$nonce" ] && [[ $challenge == *'error="use_dpop_nonce"'* ]]; then
    expect "${label}DPoP: the 401 asks for a nonce and carries one" yes yes
  else
    expect "${label}DPoP: the 401 asks for a nonce and carries one" "no ($challenge / $nonce)" yes
  fi
  "$run" 200 "${label}DPoP: the retry with visado's nonce" /tickets dpop /tickets --nonce "$nonce"
  if [ -n "$(resp_header dpop-nonce)" ]; then
    expect "${label}DPoP: the 200 carries the next nonce" yes yes
  else
    expect "${label}DPoP: the 200 carries the next nonce" no yes
  fi
}

# mtls <cert> <key> call-arguments...: like call, over Envoy's mTLS listener
# with that client certificate.
mtls() {
  conn=(--cacert "$svids/x509-agent-a/bundle.0.pem" --cert "$1" --key "$2"
    --resolve tools.td.example:10443:127.0.0.1)
  base=$MTLS_URL
  shift 2
  call "$@"
  conn=()
  base=$URL
}

# Wait for Envoy and visado to come up.
for _ in $(seq 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tools.td.example' "$URL/tickets" || true)
  [ "$code" = "401" ] && break
  sleep 1
done

# Wait for the PDP: the first evaluations after startup can be slow.
for _ in $(seq 60); do
  args=(-s -o /dev/null -w '%{http_code}' -H 'Host: tools.td.example')
  while IFS= read -r line; do args+=(-H "$line"); done < <(headers agent-a /tickets --user warmup tickets.read)
  [ "$(curl "${args[@]}" "$URL/tickets")" = "200" ] && break
  sleep 1
done

none() { :; }

call 401/credential.missing "no credentials" /tickets none
call 400 "encoded slash in the path (rejected by Envoy)" /tickets/..%2Fadmin/roles none
call 200 "agent-a reads tickets for bob" /tickets headers agent-a /tickets --user bob tickets.read
txn=$(jq -r '.headers["txn-token"]' "$tmp")
[ "$txn" != "null" ] && echo "      upstream received Txn-Token, not the user token: $(jq -r '.headers | has("x-user-token") | not' "$tmp")"

call 403/pdp.deny "agent-b forwards bob's transaction to the admin API" /admin/roles headers agent-b /admin/roles --txn "$txn"
call 200 "agent-b forwards bob's transaction to tickets" /tickets headers agent-b /tickets --txn "$txn"
call 403/txn.untrusted_hop "outside workload forwards bob's transaction" /tickets headers agent-z /tickets --txn "$txn"
call 403/pdp.deny "user token without the admin scope" /admin/roles headers agent-a /admin/roles --user bob tickets.read
call 200 "admin user through agent-a" /admin/roles headers agent-a /admin/roles --user carol "roles.write tickets.read"

# AAT: agent-a delegated read_file on /data/report.pdf to agent-b.
call 200 "agent-b reads the file it was delegated" /mcp aat agent-b read_file '{"path":"/data/report.pdf"}'
call 403/aat.invocation_denied "agent-b reads another file" /mcp aat agent-b read_file '{"path":"/etc/passwd"}'
call 403/aat.invocation_denied "agent-b deletes the file" /mcp aat agent-b delete_file '{"path":"/data/report.pdf"}'
call 403/aat.bad_signature "agent-z presents agent-b's chain" /mcp aat agent-z read_file '{"path":"/data/report.pdf"}'

# WIT with an HTTP message signature instead of a WPT. The signature covers
# the Content-Digest; visado hashes the body Envoy sends it.
signed agent-a /tickets '{"title":"printer jam"}' > "$svids/signed.txt"
call 200 "agent-a posts a ticket with a signed request" /tickets replay "$svids/signed.txt"
call 400/httpsig.invalid "the same signed request replayed (nonce seen)" /tickets replay "$svids/signed.txt"
call 400/httpsig.invalid "signed request with the body changed" /tickets \
  signed agent-a /tickets '{"title":"printer jam"}' --send '{"title":"grant me admin"}'

# mTLS with X.509-SVIDs: Envoy validates the client certificate against the
# SPIRE bundle and passes it to visado.
a_cert=$svids/x509-agent-a/svid.0.pem
a_key=$svids/x509-agent-a/svid.0.key
mtls "$a_cert" "$a_key" 200 "mTLS: agent-a reads tickets" /tickets none
mtls "$a_cert" "$a_key" 401/credential.unbound_user_token "mTLS: agent-a with an unbound user token" /tickets \
  user_token /tickets
mtls "$svids/other.pem" "$svids/other.key" tls-refused "mTLS: certificate from another CA (Envoy refuses it)" /tickets none

# JWT-SVIDs from SPIRE as bearer tokens.
call 200 "JWT-SVID: agent-a reads tickets" /tickets bearer "$jwt_tools"
call 401/jwt_svid.invalid "JWT-SVID for another audience" /tickets bearer "$jwt_other"

# An OAuth client with a plain access token.
call 200 "Bearer: an OAuth client's access token" /tickets lab_bearer
call 401/token.expired "Bearer: an expired access token" /tickets lab_bearer --expired

# A DPoP-bound access token (RFC 9449) and its proof, which must carry
# visado's nonce.
dpop_with_nonce call ""
call 401/dpop.nonce_invalid "DPoP: a nonce visado did not issue" /tickets \
  dpop /tickets --nonce AQAAAABrSvQAAAAAAAAAAAAAAAAAAAAAAA
call 401/token.dpop_bound "DPoP-bound token sent as Bearer" /tickets dpop /tickets --bearer

# agentgateway: the same visado behind the other front proxy. Its extAuthz
# policy sends the host, path, method, headers and raw body over gRPC; a
# subset of the scenarios above runs through it.
AGW_URL=http://127.0.0.1:10001
agw() {
  base=$AGW_URL
  call "$@"
  base=$URL
}
for _ in $(seq 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tools.td.example' "$AGW_URL/tickets" || true)
  [ "$code" = "401" ] && break
  sleep 1
done
agw 401/credential.missing "agentgateway: no credentials" /tickets none
# agentgateway does not normalize the path; visado rejects it instead.
agw 400/request.unnormalized_path "agentgateway: encoded slash in the path" /tickets/..%2Fadmin/roles none
agw 200 "agentgateway: agent-a reads tickets for bob" /tickets headers agent-a /tickets --user bob tickets.read
if [ "$(jq -r '.headers | has("txn-token") and (has("x-user-token") | not)' "$tmp")" = true ]; then
  printf 'ok    %-58s %s\n' "agentgateway: upstream gets Txn-Token, not the user token" "yes"
else
  printf 'FAIL  %-58s %s\n' "agentgateway: upstream gets Txn-Token, not the user token" "$(head -c 200 "$tmp")"
  failures=$((failures + 1))
fi
agw 403/pdp.deny "agentgateway: user token without the admin scope" /admin/roles headers agent-a /admin/roles --user bob tickets.read
agw 200 "agentgateway: agent-b reads the file it was delegated" /mcp aat agent-b read_file '{"path":"/data/report.pdf"}'
agw 403/aat.invocation_denied "agentgateway: agent-b reads another file" /mcp aat agent-b read_file '{"path":"/etc/passwd"}'
signed agent-a /tickets '{"title":"paper out"}' > "$svids/agw-signed.txt"
agw 200 "agentgateway: agent-a posts a ticket with a signed request" /tickets replay "$svids/agw-signed.txt"
agw 400/httpsig.invalid "agentgateway: signed request with the body changed" /tickets \
  signed agent-a /tickets '{"title":"paper out"}' --send '{"title":"grant me admin"}'
dpop_with_nonce agw "agentgateway: "

# Only the gateways can reach visado's gRPC port: another container on the
# lab network cannot connect to it, by name or by its authz address. The
# probe must first reach visado's HTTP port, so a probe that cannot run at
# all does not count as refused.
probe() {
  docker compose -f deploy/lab/compose.yaml exec -T spire-agent nc -z -w 2 "$1" "$2" 2>/dev/null
}
if ! probe visado 8080; then
  printf 'FAIL  %-58s %s\n' "gRPC port unreachable from other containers" "probe cannot reach visado:8080"
  failures=$((failures + 1))
elif probe visado 9191 || probe 172.30.91.10 9191; then
  printf 'FAIL  %-58s reachable\n' "gRPC port unreachable from other containers"
  failures=$((failures + 1))
else
  printf 'ok    %-58s %s\n' "gRPC port unreachable from other containers" "refused"
fi

# The chain view lists the decisions above, and none of it is token material.
log=$(curl -s 'http://127.0.0.1:8080/api/requests?limit=100' || true)
count=$(jq '.requests | length' <<<"$log" 2>/dev/null || echo 0)
if [ "${count:-0}" -gt 0 ] && ! grep -q 'eyJ' <<<"$log"; then
  printf 'ok    %-58s %s\n' "chain view lists decisions without tokens" "$count"
else
  printf 'FAIL  %-58s %s requests, tokens: %s\n' "chain view lists decisions without tokens" "${count:-0}" "$(grep -c 'eyJ' <<<"$log" || true)"
  failures=$((failures + 1))
fi

# visado exports one span per decision to Jaeger.
sleep 6
spans=$(curl -s 'http://127.0.0.1:16686/api/traces?service=visado&limit=50' | jq '[.data[].spans[] | select(.operationName | startswith("visado.authorize"))] | length')
if [ "${spans:-0}" -gt 0 ]; then
  printf 'ok    %-58s %s\n' "authorization spans in Jaeger" "$spans"
else
  printf 'FAIL  %-58s none found\n' "authorization spans in Jaeger"
  failures=$((failures + 1))
fi

exit "$failures"
