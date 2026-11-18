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

## Guidelines

- One logical change per commit. Keep refactors apart from behaviour changes.
- Cite the draft section for spec-driven code, and update [SPEC-MAP.md](SPEC-MAP.md) when a pinned revision changes.
- Behaviour changes come with conformance vectors, negative cases included. Regenerate with `VISADO_REGENERATE=1 cargo test --workspace` and commit the result. See [conformance/README.md](conformance/README.md).
- Security checks fail closed and have negative tests.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
