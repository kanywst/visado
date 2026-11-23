#!/usr/bin/env bash
# asor-03 interop with attenu-io/attenu-guard. Writes interop/asor/results/.
# Needs python3 and cargo, and network access to pypi.org.
set -euo pipefail

ATTENU_GUARD=0.22.0
ATTENU_GUARD_SHA256=12f9edf606161f6bb1242f5a9abbdad48eb67818e26a2c10487199382365e717
CRYPTOGRAPHY=46.0.3

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 -m venv "$work/venv"
pip="$work/venv/bin/pip"
"$pip" install -q --disable-pip-version-check "cryptography==$CRYPTOGRAPHY"
"$pip" download -q --disable-pip-version-check --no-deps -d "$work/dl" "attenu-guard==$ATTENU_GUARD"
wheel="$work/dl/attenu_guard-$ATTENU_GUARD-py3-none-any.whl"
echo "$ATTENU_GUARD_SHA256  $wheel" | shasum -a 256 -c - >/dev/null
"$pip" install -q --disable-pip-version-check --no-deps "$wheel"
py=("$work/venv/bin/python" -I "$here/attenu_guard_interop.py")

cargo build -q --locked -p visado-interop --manifest-path "$root/Cargo.toml"
harness="$root/target/debug/visado-interop"
out="$here/results"
mkdir -p "$out"

# 1. Chains minted by attenu-guard, verified by visado (with DPoP where a case has a request).
"${py[@]}" mint > "$out/attenu-guard-minted.json"
"$harness" asor-verify < "$out/attenu-guard-minted.json" > "$work/visado-results.json"
"${py[@]}" compare "$out/attenu-guard-minted.json" "$work/visado-results.json" \
  > "$out/visado-on-attenu-guard-minted.json"

# 2. Chains minted by visado's fixtures, verified by attenu-guard.
"$harness" asor-mint > "$out/visado-minted.json"
"${py[@]}" verify "$out/visado-minted.json" > "$out/attenu-guard-on-visado-minted.json"

for f in visado-on-attenu-guard-minted attenu-guard-on-visado-minted; do
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); a=sum(r["agree"] for r in d["results"]); print(sys.argv[2] + ":", a, "of", d["cases"], "agree,", d["unexpected"], "unexpected")' \
    "$out/$f.json" "$f"
done
