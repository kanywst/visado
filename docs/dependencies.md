# Dependency policy

How visado chooses, pins and updates what it depends on.

## Choosing a dependency

- Prefer a crate that is maintained, widely used, and under a license in the `[licenses] allow` list of [deny.toml](../deny.toml) (Apache-2.0, MIT, BSD, ISC and a few permissive others).
- Crates come from crates.io only. `deny.toml` denies unknown registries and git sources.
- A dependency whose types appear in a public API is a semver commitment; see [RELEASING.md](../RELEASING.md).

## Pinning

- `Cargo.lock` is committed and CI builds with `--locked`.
- GitHub Actions are pinned by commit SHA, container base images by digest.
- The Rust toolchain follows `stable` ([rust-toolchain.toml](../rust-toolchain.toml)); the minimum supported version is `rust-version` in `Cargo.toml`.

## Updating

- Dependabot opens weekly pull requests for Cargo, GitHub Actions, the website's npm packages and Docker images ([.github/dependabot.yml](../.github/dependabot.yml)). Minor and patch Cargo updates are grouped.
- Every update goes through the same CI as any other change, including `cargo deny check` for advisories, yanked crates, licenses and sources.
- A RustSec advisory against a dependency is fixed by an update or, if none exists, recorded in `deny.toml` with the reason and the advisory ID.
- A release goes out at least every six weeks, even if it only carries dependency updates ([RELEASING.md](../RELEASING.md)).
