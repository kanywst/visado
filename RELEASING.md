# Releasing

## Versioning

All crates share the version in `[workspace.package]`. Before 1.0, a breaking change bumps the minor version and anything else the patch. Read the bump from the [Conventional Commits](https://www.conventionalcommits.org/) since the last tag: `fix:` and `feat:` are patches, and a breaking change (`!`) is a minor.

A dependency bump is breaking when that dependency's types appear in visado's public API. `wimsey-jose` keys appear in `visado-txn-token` and `visado-extauthz`, so a major `wimsey-jose` bump is a breaking release.

Cut a release at least every six weeks, even if it only carries dependency updates.

## Steps

1. Review what landed: `git log --oneline "$(git describe --tags --abbrev=0)"..HEAD`.
2. Set `[workspace.package] version` in `Cargo.toml`, and the `version` of every `visado-*` entry under `[workspace.dependencies]`.
3. Move the `[Unreleased]` entries in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD` and update the links at the bottom.
4. Run the checks:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --all-targets
   cargo deny check
   ```

5. Open a `chore(release): X.Y.Z` pull request and merge it once CI passes.
6. Tag the merge commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "visado X.Y.Z"
   git push origin vX.Y.Z
   ```

## What the tag triggers

`.github/workflows/release.yml`:

| Job | Does |
| --- | --- |
| `guard` | Stops unless the tag, the `visado` package version and a `## [X.Y.Z]` changelog section agree |
| `build` | Builds `visado` for x86-64 and arm64 Linux and macOS |
| `publish` | SPDX SBOM, `SHA256SUMS`, a cosign keyless bundle per asset, SLSA build provenance (also attached as `visado-vX.Y.Z-provenance.intoto.jsonl`), then the GitHub release |
| `crates-io` | Publishes the crates, only when the repository variable `PUBLISH_CRATES` is `true` and `CARGO_REGISTRY_TOKEN` is set |

To retry a release whose `publish` job failed: `gh workflow run release.yml -f tag=vX.Y.Z`. Every step is idempotent. A dispatched run signs under the branch it ran from, and the release notes name that identity.
