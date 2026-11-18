#!/usr/bin/env bash
# Runs the lab scenarios against `docker compose up` in this directory.
# Exits non-zero if any scenario does not get the expected status.
set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build -q -p visado-testkit --example lab_headers --example lab_aat
headers() { ./target/debug/examples/lab_headers "$@"; }
aat() { ./target/debug/examples/lab_aat "$@"; }

URL=http://127.0.0.1:10000
failures=0

call() {
  local expect=$1 name=$2 path=$3
  shift 3
  local args=(-s -o "$tmp" -w '%{http_code}' -H 'Host: tools.td.example')
  while IFS= read -r line; do
    case "$line" in
      "BODY: "*) args+=(--data-binary "${line#BODY: }") ;;
      "") ;;
      *) args+=(-H "$line") ;;
    esac
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

# Wait for the PDP: the first evaluations after startup can be slow.
for _ in $(seq 60); do
  args=(-s -o /dev/null -w '%{http_code}' -H 'Host: tools.td.example')
  while IFS= read -r line; do args+=(-H "$line"); done < <(headers agent-a /tickets --user warmup tickets.read)
  [ "$(curl "${args[@]}" "$URL/tickets")" = "200" ] && break
  sleep 1
done

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

# AAT: agent-a delegated read_file on /data/report.pdf to agent-b.
call 200 "agent-b reads the file it was delegated" /mcp aat agent-b read_file '{"path":"/data/report.pdf"}'
call 403 "agent-b reads another file" /mcp aat agent-b read_file '{"path":"/etc/passwd"}'
call 403 "agent-b deletes the file" /mcp aat agent-b delete_file '{"path":"/data/report.pdf"}'
call 403 "agent-z presents agent-b's chain" /mcp aat agent-z read_file '{"path":"/data/report.pdf"}'

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
