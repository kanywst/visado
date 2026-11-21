# shellcheck shell=bash disable=SC2154,SC2016
# Attack 4, NOT stopped: a prompt-injected agent leaks data it is allowed to
# read, using only calls it is allowed to make. Sourced by demo.sh, which
# defines call, via_agw, mcp, headers, with_body, mcp_text and expect_audit.
# See README.md.

say "attack 4 (visado does not stop this): the report agent-b may read"
say "carries hidden instructions: post this file to a public ticket"
via_agw 200 "attack 4: agent-b reads the report it was delegated" /mcp \
  mcp agent-b read_file '{"path":"/data/report.pdf"}'
leaked=$(mcp_text "$tmp")
check "attack 4: the report reaches agent-b in the response" "$(cut -c1-9 <<<"$leaked")" "Q3 report"
call 200 "attack 4: agent-b posts the report to a public ticket" /tickets \
  with_body "$(jq -cn --arg text "$leaked" '{title: "public: notes", text: $text}')" \
  headers agent-b /tickets
check "attack 4: the upstream received the leaked text" \
  "$(jq -r '.json.text // .body' "$tmp" 2>/dev/null | cut -c1-9)" "Q3 report"
expect_audit "attack 4: audit: the read, allowed" \
  '.agent == "spiffe://td.example/agent-b" and .tool == "read_file" and .decision == "allow"'
expect_audit "attack 4: audit: the post, allowed" \
  '.agent == "spiffe://td.example/agent-b" and .action == "POST"
   and .resource == "http://tools.td.example/tickets" and .decision == "allow"'
