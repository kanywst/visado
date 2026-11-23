#!/usr/bin/env bash
# WIMSE credential interop: visado (WIT, WPT, HTTP message signatures) against
# strideynet/wit-wpt-go, spiffe/go-spiffe exp/svid/witsvid, the Cofide HTTP
# signature PoC and the WIMSE WG example generator. See README.md.
#
# Needs cargo, go, git and jq; downloads Go modules and the WG repository.
set -euo pipefail

# Pinned commits. The Go drivers pin the first four in their go.mod.
WIT_WPT_GO=5cf9b7dec23606f5296e91ec1641ac28ae76f843
WIT_WPT_GO_OLD=e8fa34519d8d2dec9b81e0a9276a256672fe2979
GO_SPIFFE=b6b0441b2d05dab703ef859756ea534d8f50a515
COFIDE_POC=7984a60105002dc65b31e9cd08572cd5d10ed9d6
WG_REPO=https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol
WG_COMMIT=ae2acf10cc5523dbe66fc9369dac8c1fb8da1534

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
results="$here/results"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# wit-wpt-go@e8fa345 writes WPT exp as a local time string.
export TZ=UTC

pin() { # module dir, commit
  grep -q "${2:0:12}" "$here/go/$1/go.mod" || {
    echo "go/$1/go.mod does not pin ${2:0:12}" >&2
    exit 1
  }
}
pin witwpt "$WIT_WPT_GO"
pin witwpt-e8fa345 "$WIT_WPT_GO_OLD"
pin gospiffe "$GO_SPIFFE"
pin cofide "$COFIDE_POC"

(cd "$root" && cargo build -q --locked -p visado-interop)
wimse="$root/target/debug/wimse"
driver() { # module dir, args...
  local dir=$1
  shift
  (cd "$here/go/$dir" && go run . "$@")
}
mkdir -p "$results"

# visado's own cases at the fixed time, with visado's verdicts.
"$wimse" mint >"$results/visado-mint.json"

# Draft examples (draft-ietf-wimse-workload-creds-03, draft-ietf-wimse-wpt-02).
"$wimse" verify <"$here/vectors/draft-examples.json" >"$results/draft-examples-to-visado.json"

# The WG's example generator at its pinned commit.
git -C "$tmp" init -q wg
git -C "$tmp/wg" fetch -q --depth 1 "$WG_REPO" "$WG_COMMIT"
git -C "$tmp/wg" checkout -q FETCH_HEAD
(cd "$tmp/wg/examples" && go run .) >"$tmp/wg.txt"
key=$(sed -n '/^Signer public key: /,$p' "$tmp/wg.txt" | sed '1s/^Signer public key: //')
jq -n --arg wit "$(sed -n 's/^WIT: //p' "$tmp/wg.txt")" \
  --arg wpt "$(sed -n 's/^WPT: //p' "$tmp/wg.txt")" --argjson key "$key" '{
  now: 1745509980,
  issuers: [{ trust_domain: "example.com", jwks: { keys: [$key] } }],
  cases: [
    { id: "wg-examples/valid", expect: "accept", method: "POST",
      uri: "https://workload.example.com/path", wit: $wit, wpt: $wpt },
    { id: "wg-examples/other_target", expect: "reject", method: "POST",
      uri: "https://workload.example.com/other", wit: $wit, wpt: $wpt }
  ]}' | "$wimse" verify >"$results/wg-examples-to-visado.json"

# wit-wpt-go at HEAD: its WITs to visado (WPTs signed by visado, since its
# MintWPT fails), and visado's WIT+WPT cases to its ValidateWPT.
driver witwpt mint >"$tmp/witwpt.json"
"$wimse" verify <"$tmp/witwpt.json" >"$tmp/witwpt-verdicts.json"
jq --slurpfile mint "$tmp/witwpt.json" '{mint_wpt: $mint[0].mint_wpt} + .' \
  "$tmp/witwpt-verdicts.json" >"$results/wit-wpt-go-to-visado.json"
driver witwpt verify <"$results/visado-mint.json" >"$results/visado-to-wit-wpt-go.json"

# wit-wpt-go at e8fa345, where MintWPT still works.
driver witwpt-e8fa345 >"$tmp/witwpt-old.json"
"$wimse" verify <"$tmp/witwpt-old.json" >"$results/wit-wpt-go-e8fa345-to-visado.json"

# go-spiffe and the Cofide PoC check time against the wall clock.
"$wimse" mint --now "$(date +%s)" >"$tmp/mint-now.json"
driver gospiffe verify <"$tmp/mint-now.json" >"$results/visado-to-go-spiffe.json"
driver cofide verify <"$tmp/mint-now.json" >"$results/visado-to-cofide.json"
driver cofide sign <"$tmp/mint-now.json" >"$tmp/cofide.json"
"$wimse" verify <"$tmp/cofide.json" >"$results/cofide-to-visado.json"

# visado must agree with itself on every case.
if jq -e '[.suites[].cases[] | select(.visado.verdict != .expect)] | length > 0' \
  "$results/visado-mint.json" >/dev/null; then
  echo "visado disagrees with its own expected verdicts" >&2
  exit 1
fi

echo "file                                   checker              agree/total"
for f in "$results"/*.json; do
  jq -r --arg f "$(basename "$f")" '
    def row($k): [(.cases // [])[] | (if $k == "." then . else .[$k] end) | select(. != null)]
      | "\($f | .[0:38] | . + " " * (39 - length))\($k | . + " " * (21 - length))\(map(select(.agrees == true)) | length)/\(length)";
    if .suites then
      [.suites[].cases[] | .visado.verdict == .expect] as $v
      | "\($f | . + " " * (39 - length))visado (self)        \($v | map(select(.)) | length)/\($v | length)"
    elif $f == "visado-to-wit-wpt-go.json" then row("as_is"), row("own_format_wpt")
    elif $f == "visado-to-cofide.json" then row("poc_server"), row("httpsign_draft08")
    else row(".") end' "$f"
done
