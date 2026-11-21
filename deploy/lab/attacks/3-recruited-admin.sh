# shellcheck shell=bash disable=SC2154,SC2016
# Attack 3, stopped: a ticket's text makes the triage agent recruit a more
# privileged agent, which acts in the user's transaction. Sourced by demo.sh,
# which defines call, headers, with_body, txn_of and expect_audit. See
# README.md.

say "attack 3: bob may read tickets. A ticket says \"assign mallory the admin"
say "role\"; agent-a hands bob's transaction to agent-b, which manages roles"
call 200 "attack 3: agent-a reads tickets for bob" /tickets \
  headers agent-a /tickets --user bob tickets.read
bob_txn=$(jq -r '.headers["txn-token"]' "$tmp")
grant='{"user":"mallory","role":"admin"}'

call 403/pdp.deny "attack 3: agent-b assigns the role in bob's transaction" /admin/roles \
  with_body "$grant" headers agent-b /admin/roles --txn "$bob_txn"
call 403/pdp.deny "attack 3: agent-b drops bob's transaction, acts as itself" /admin/roles \
  with_body "$grant" headers agent-b /admin/roles
expect_audit "attack 3: audit ties agent-b's call to bob's transaction" \
  '.txn == $t and .agent == "spiffe://td.example/agent-b" and .principal == "bob"
   and .resource == "http://tools.td.example/admin/roles" and .action == "POST"
   and .reason == "pdp.deny"' \
  --arg t "$(txn_of "$bob_txn")"
