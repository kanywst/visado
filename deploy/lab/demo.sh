#!/usr/bin/env bash
# Runs the lab scenarios against `docker compose up` in this directory.
# Exits non-zero if any scenario does not get the expected status.
set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build -q -p visado-testkit --example lab_headers
headers() { ./target/debug/examples/lab_headers "$@"; }

URL=http://127.0.0.1:10000
failures=0

call() {
  local expect=$1 name=$2 path=$3
  shift 3
  local args=(-s -o "$tmp" -w '%{http_code}' -H 'Host: tools.td.example')
  while IFS= read -r line; do
    [ -n "$line" ] && args+=(-H "$line")
  done < <("$@")
  local status
  status=$(curl "${args[@]}" "$URL$path")
  if [ "$status" = "$expect" ]; then
    printf 'ok    %-58s %s\n' "$name" "$status"
  else
    printf 'FAIL  %-58s got %s, want %s: %s\n' "$name" "$status" "$expect" "$(head -c 200 "$tmp")"
    failures=$((failures + 1))
  fi
}

# Wait for Envoy and visado to come up.
for _ in $(seq 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tools.td.example' "$URL/tickets" || true)
  [ "$code" = "401" ] && break
  sleep 1
done

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

none() { :; }

call 401 "no credentials" /tickets none
call 400 "encoded slash in the path (rejected by Envoy)" /tickets/..%2Fadmin/roles none
call 200 "agent-a reads tickets for bob" /tickets headers agent-a /tickets --user bob tickets.read
txn=$(jq -r '.headers["txn-token"]' "$tmp")
[ "$txn" != "null" ] && echo "      upstream received Txn-Token, not the user token: $(jq -r '.headers | has("x-user-token") | not' "$tmp")"

call 403 "agent-b forwards bob's transaction to the admin API" /admin/roles headers agent-b /admin/roles --txn "$txn"
call 200 "agent-b forwards bob's transaction to tickets" /tickets headers agent-b /tickets --txn "$txn"
call 403 "outside workload forwards bob's transaction" /tickets headers agent-z /tickets --txn "$txn"
call 403 "user token without the admin scope" /admin/roles headers agent-a /admin/roles --user bob tickets.read
call 200 "admin user through agent-a" /admin/roles headers agent-a /admin/roles --user carol "roles.write tickets.read"

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
