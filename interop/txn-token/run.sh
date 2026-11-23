#!/usr/bin/env bash
# Transaction Token (draft-ietf-oauth-transaction-tokens-11) interop with
# authgent, atlas-go and kontxt. Writes interop/txn-token/results/.
# Needs git, python3 (3.11+), go and cargo, and network access to github.com,
# pypi.org and proxy.golang.org.
set -euo pipefail

AUTHGENT_COMMIT=8341cf932c9816dc666f2a6577b6776bd6f3b978 # authgent-server 0.3.4
ATLAS_GO=v0.27.0  # commit 794a21e55e40c4a89afef69d821b0334b52d552f, pinned in atlas-verify/go.mod
KONTXT=v0.0.2-0.20260611230541-d23ebb50121a # commit d23ebb50121a650af57c9e34e8227d54db324f9d, pinned in kontxt-driver/go.mod

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

grep -q "github.com/Atlas-Authorization/atlas-go $ATLAS_GO" "$here/atlas-verify/go.mod"
grep -q "github.com/aramase/kontxt $KONTXT" "$here/kontxt-driver/go.mod"

git clone -q --filter=blob:none https://github.com/authgent/authgent "$work/authgent"
git -C "$work/authgent" checkout -q "$AUTHGENT_COMMIT"
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q --disable-pip-version-check \
  -c "$here/authgent-constraints.txt" "$work/authgent/server"

go build -C "$here/atlas-verify" -o "$work/atlas-verify" .
go build -C "$here/kontxt-driver" -o "$work/kontxt-driver" .
cargo build -q --locked -p visado-interop --manifest-path "$root/Cargo.toml"
txn="$root/target/debug/txn"
atlas="$work/atlas-verify"
kontxt="$work/kontxt-driver"
summarize=(python3 -I "$here/summarize.py")
out="$here/results"
mkdir -p "$out"

# 1. visado -> atlas-go, at a fixed time. visado-minted.json is reproducible.
"$txn" mint > "$out/visado-minted.json"
"$txn" verify < "$out/visado-minted.json" > "$work/v-visado.json"
"$atlas" < "$out/visado-minted.json" > "$work/v-atlas.json"
"${summarize[@]}" "$out/visado-minted.json" visado="$work/v-visado.json" atlas-go="$work/v-atlas.json" \
  > "$out/visado-to-atlas-go.json"

# 2. visado -> kontxt. kontxt's verifier reads the wall clock, so mint at it.
"$txn" mint --now "$(date +%s)" > "$work/vw.json"
"$txn" verify < "$work/vw.json" > "$work/vw-visado.json"
"$kontxt" verify < "$work/vw.json" > "$work/vw-kontxt.json"
"${summarize[@]}" "$work/vw.json" visado="$work/vw-visado.json" kontxt="$work/vw-kontxt.json" \
  > "$out/visado-to-kontxt.json"

# 3. authgent -> visado, with atlas-go as a control.
(cd "$work" && "$work/venv/bin/python" -I "$here/authgent_mint.py" > "$work/a.json" 2> "$work/a.log")
"$txn" verify < "$work/a.json" > "$work/a-visado.json"
"$atlas" < "$work/a.json" > "$work/a-atlas.json"
"${summarize[@]}" "$work/a.json" visado="$work/a-visado.json" atlas-go="$work/a-atlas.json" \
  > "$out/authgent-to-visado.json"

# 4. kontxt -> visado, with kontxt's own verifier and atlas-go as controls.
"$kontxt" mint > "$work/k.json"
"$txn" verify < "$work/k.json" > "$work/k-visado.json"
"$kontxt" verify < "$work/k.json" > "$work/k-kontxt.json"
"$atlas" < "$work/k.json" > "$work/k-atlas.json"
"${summarize[@]}" "$work/k.json" visado="$work/k-visado.json" kontxt="$work/k-kontxt.json" \
  atlas-go="$work/k-atlas.json" > "$out/kontxt-to-visado.json"

python3 -I - "$out" <<'PY'
import json, pathlib, sys
for f in sorted(pathlib.Path(sys.argv[1]).glob("*-to-*.json")):
    d = json.loads(f.read_text())
    for name, s in d["summary"].items():
        print(f"{f.stem:22} {name:9} {s['as_expected']}/{s['cases'] - len(s['unspecified'])} as expected"
              f"  unexpected={s['unexpected']}  unspecified={s['unspecified']}")
PY
