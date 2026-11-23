# Governance

visado is a vendor-neutral open source project. This document stays short while the project is young.

## Roles

- Contributors open issues and pull requests.
- Maintainers review and merge, triage issues and cut releases. They are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Responsibilities

Every maintainer shares these. While there is one maintainer, that maintainer holds all of them.

| Responsibility | What it involves |
| --- | --- |
| Review | Review pull requests against [CONTRIBUTING.md](CONTRIBUTING.md); nothing merges with CI red |
| Triage | Label new issues and answer them within 14 days |
| Releases | Cut a release at least every six weeks, as in [RELEASING.md](RELEASING.md) |
| Security response | Handle private vulnerability reports within the times in [SECURITY.md](SECURITY.md) |
| Spec tracking | Move the pinned revisions in [SPEC-MAP.md](SPEC-MAP.md) when a draft the project implements changes |
| Dependencies | Merge or answer Dependabot pull requests, as in [docs/dependencies.md](docs/dependencies.md) |

## Continuity

The project keeps going if any one person stops. Every maintainer has admin access to the repository and is a required reviewer on the `crates-io` release environment. Releases are signed keyless in CI, so there is no private signing key to hand over. The crates.io crates list every maintainer as an owner.

With one maintainer this is not yet met. Adding a second maintainer, from another organization, is the first goal in [MAINTAINERS.md](MAINTAINERS.md).

## Decisions

- Routine changes are approved by maintainer review of a pull request.
- Significant changes (a pinned draft revision, a new crate, a change to scope or governance) are proposed in an issue or pull request and decided by maintainer consensus.
- The project wants maintainers from more than one organization.

## Adding maintainers

A maintainer can nominate a contributor with a sustained record of good contributions. Maintainer consensus confirms the nomination.

## Changing this document

Use the significant-change process above.
