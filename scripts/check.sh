#!/usr/bin/env bash
# The checks CI runs, in one command. Run before every commit.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked -q
cargo test --workspace --doc --locked -q
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked -q
cargo deny --log-level error check
npx --yes markdownlint-cli2 "**/*.md" >/dev/null
if command -v actionlint >/dev/null; then actionlint; fi
git diff --exit-code -- conformance/ >/dev/null
echo "all checks passed"
