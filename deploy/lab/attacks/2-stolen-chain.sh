# shellcheck shell=bash disable=SC2154,SC2016
# Attack 2, stopped: another workload steals agent-b's delegated request and
# presents it. Sourced by demo.sh, which defines call, via_agw, mcp, headers
# and expect_audit. See README.md.

say "attack 2: agent-z, a workload on the same network, captures agent-b's"
say "requests (from a debug log, a proxy, a shared trace) and uses them"
mcp agent-b read_file '{"path":"/data/report.pdf"}' > "$svids/attack2-sent.txt"
mcp agent-b read_file '{"path":"/data/report.pdf"}' > "$svids/attack2-unsent.txt"

via_agw 200 "attack 2: agent-b sends its request" /mcp replay "$svids/attack2-sent.txt"
via_agw 401/wpt.replay "attack 2: agent-z replays it byte for byte" /mcp \
  replay "$svids/attack2-sent.txt"
# A request agent-b has not sent yet: agent-z keeps the chain and the proof
# of possession, and authenticates as itself.
{
  grep -v -e '^Workload-Identity-Token: ' -e '^Authorization: ' "$svids/attack2-unsent.txt"
  headers agent-z /mcp
} > "$svids/attack2-rewrapped.txt"
via_agw 403/chain.holder_mismatch "attack 2: agent-z presents the chain as itself" /mcp \
  replay "$svids/attack2-rewrapped.txt"
expect_audit "attack 2: audit names agent-z as the presenter" \
  '.agent == "spiffe://td.example/agent-z" and .tool == "read_file" and .reason == "chain.holder_mismatch"'
