#!/usr/bin/env bash
# AAT interop with tenuo-ai/tenuo. Writes interop/aat/results/.
# Needs git, python3 and cargo, and network access to github.com and pypi.org.
set -euo pipefail

TENUO_COMMIT=f1a6c22b3ef6de3d442eee4cbc1a9231fd65e7d4
CRYPTOGRAPHY=46.0.3

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone -q --filter=blob:none https://github.com/tenuo-ai/tenuo "$work/tenuo"
git -C "$work/tenuo" checkout -q "$TENUO_COMMIT"
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q --disable-pip-version-check "cryptography==$CRYPTOGRAPHY"

cargo build -q --locked -p visado-interop --manifest-path "$root/Cargo.toml"
harness="$root/target/debug/visado-interop"
out="$here/results"
mkdir -p "$out"

# 1. tenuo's published suite, verified by visado, scored by tenuo's script.
suite="$work/tenuo/tests/vectors/aat-jws-vectors.json"
"$harness" aat-suite "$suite" > "$out/visado-on-tenuo-suite.json"
(cd "$work/tenuo" && python3 ietf/vectors/compare_results.py "$out/visado-on-tenuo-suite.json" --steps) \
  | sed "s|$out/||" > "$out/visado-on-tenuo-suite.compare.txt"

# 2. Chains minted by visado's fixtures, verified by tenuo's Section 8 verifier.
"$harness" aat-mint > "$out/visado-minted.json"
"$work/venv/bin/python" -I "$here/tenuo_verify.py" "$work/tenuo" "$out/visado-minted.json" \
  > "$out/tenuo-on-visado-minted.json"

cat "$out/visado-on-tenuo-suite.compare.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("tenuo on visado-minted:", d["cases"] - d["differ"], "of", d["cases"], "agree")' \
  "$out/tenuo-on-visado-minted.json"
