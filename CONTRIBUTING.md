# Contributing

## Sign-off

Every commit needs a [Developer Certificate of Origin](https://developercertificate.org/) sign-off. `git commit -s` adds it. CI rejects pull requests with unsigned commits.

## Checks

CI runs these checks, and `scripts/check.sh` runs all of them locally. Run it before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
npx markdownlint-cli2 "**/*.md"
```

The parsers also have cargo-fuzz targets; `fuzz/README.md` shows how to seed and run them (`cargo +nightly fuzz run <target>`).

## Coding style

- Rust follows the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and the [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/), as `rustfmt` applies it with no configuration. `cargo fmt --check` enforces it in CI.
- Clippy runs with `all` and `pedantic` at `-D warnings` ([Cargo.toml](Cargo.toml) `[workspace.lints]`); `unsafe` code is forbidden. A lint is allowed only locally, with a comment saying why.
- Public items have doc comments (`missing_docs`), and `cargo doc` builds without warnings.
- Workflows pass `actionlint`, and Markdown passes `markdownlint-cli2` with [.markdownlint-cli2.jsonc](.markdownlint-cli2.jsonc).

## Tests

- New functionality comes with tests in the same pull request: unit tests next to the code, integration tests under the crate's `tests/`, and conformance vectors for spec behaviour.
- A bug fix comes with a regression test that fails without the fix.
- Line coverage of the workspace stays at 80% or more. The `test coverage` job in CI measures it with `cargo llvm-cov` and fails below that; run `cargo llvm-cov --workspace --summary-only` to see it locally.
- A change to the lab (`deploy/lab`) keeps `deploy/lab/demo.sh` passing against both PDPs.

## Guidelines

- One logical change per commit. Keep refactors apart from behaviour changes.
- Cite the draft section for spec-driven code, and update [SPEC-MAP.md](SPEC-MAP.md) when a pinned revision changes.
- Behaviour changes come with conformance vectors, negative cases included. Regenerate with `VISADO_REGENERATE=1 cargo test --workspace` and commit the result. See [conformance/README.md](conformance/README.md).
- Security checks fail closed and have negative tests.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
