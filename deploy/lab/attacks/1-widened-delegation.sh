# shellcheck shell=bash disable=SC2154,SC2016
# Attack 1, stopped: a prompt-injected agent widens the delegation it hands on.
# Sourced by demo.sh, which defines call, via_agw, mcp and expect_audit. See
# README.md.

say "attack 1: agent-a may only read the report; a poisoned prompt makes it"
say "delegate read_file on any path, and delete_file, to agent-b"
granted='{"read_file":{"path":{"constraint_type":"one_of","values":["/data/report.pdf"]}}}'
widened='{"read_file":{"path":{"constraint_type":"wildcard"}},"delete_file":{"path":{"constraint_type":"wildcard"}}}'

via_agw 200 "attack 1: control: agent-b reads the report" /mcp \
  mcp agent-b read_file '{"path":"/data/report.pdf"}' --root "$granted" --child "$granted"
via_agw 403/aat.not_attenuated "attack 1: widened chain: agent-b reads /etc/passwd" /mcp \
  mcp agent-b read_file '{"path":"/etc/passwd"}' --root "$granted" --child "$widened"
via_agw 403/aat.not_attenuated "attack 1: widened chain: agent-b deletes the report" /mcp \
  mcp agent-b delete_file '{"path":"/data/report.pdf"}' --root "$granted" --child "$widened"
expect_audit "attack 1: audit records the widened chain" \
  '.agent == "spiffe://td.example/agent-b" and .tool == "delete_file" and .reason == "aat.not_attenuated"'
check "attack 1: no delete_file reached the MCP server" "$(mcp_calls delete_file)" 0
