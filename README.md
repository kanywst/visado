<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/lockup-dark.svg">
  <img alt="visado" src="docs/assets/lockup-light.svg" height="56">
</picture>

[![ci](https://github.com/kanywst/visado/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/visado/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kanywst/visado/badge)](https://scorecard.dev/viewer/?uri=github.com/kanywst/visado)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16930/badge)](https://www.bestpractices.dev/projects/16930)
[![crates.io](https://img.shields.io/crates/v/visado.svg)](https://crates.io/crates/visado)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

visado is an ext_authz service for AI agent traffic that runs behind Envoy, Istio or agentgateway. For each request it verifies the caller's workload credential and the delegation chain behind the request, asks an [AuthZEN](https://openid.net/specs/authorization-api-1_0.html) policy decision point, and passes the verified chain downstream as an [OAuth Transaction Token](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/).

> [!IMPORTANT]
> visado is pre-alpha and implements Internet-Drafts that are still changing. AAT, asor and RFC 8693 `act` are the delegation-chain formats so far. See the [roadmap](ROADMAP.md).

## How it fits

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/flow-dark.svg">
  <img alt="Agent A calls through Envoy; Envoy asks visado over ext_authz; visado asks the PDP over AuthZEN and the request reaches agent B with a Transaction Token" src="docs/assets/flow-light.svg">
</picture>

It follows the composition in [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/). It does not issue identities, log users in, evaluate policy or route traffic; see [docs/scope.md](docs/scope.md).

## Components

| Component | Spec | Status |
| --- | --- | --- |
| [`visado-txn-token`](crates/txn-token) | draft-ietf-oauth-transaction-tokens-11 | alpha: mint, verify, replace, request parsing, conformance vectors |
| [`visado-credentials`](crates/credentials) | WIMSE WIT with WPT or HTTP signatures (draft-ietf-wimse-http-signature-08) and mTLS via [wimsey](https://github.com/kanywst/wimsey), SPIFFE JWT-SVIDs, OAuth access tokens (bearer or DPoP, RFC 9449) | alpha |
| [`visado-authzen`](crates/authzen) | AuthZEN 1.0 | alpha: evaluation and discovery; batch and search not used |
| [`visado-extauthz`](crates/extauthz) | Envoy ext_authz v3 | alpha |
| [`visado`](crates/server) | | alpha: server binary |
| [`visado-chain`](crates/chain) | | alpha: normalized chain model and decoder trait |
| [`visado-chain-aat`](crates/chain-aat) | draft-niyikiza-oauth-attenuating-agent-tokens-02 | alpha: §8 verification, 229/229 published vectors, enforced by the gate |
| [`visado-chain-asor`](crates/chain-asor) | draft-asor-wimse-agent-delegation-chain-03 | alpha: §6 verification with DPoP and Token Status Lists, 36/36 published vectors, enforced by the gate |
| [`visado-chain-act`](crates/chain-act) | RFC 8693 `act` claim | alpha: the current actor bound to the caller, prior actors kept out of the PDP, enforced by the gate |
| Chain view, OpenTelemetry | | alpha: `visado.authorize` spans over OTLP; an opt-in page of recent decisions and their chains at `/chain` ([design](docs/design.md#chain-view)) |

## Install

```bash
cargo install visado
```

Signed binaries for Linux and macOS (x86-64 and arm64), with an SPDX SBOM and SLSA provenance, are on the [releases page](https://github.com/kanywst/visado/releases). The library crates are on [crates.io](https://crates.io/search?q=visado).

## Try it

```bash
git clone https://github.com/kanywst/visado
cd visado
cargo test --workspace
cargo run -p visado -- deploy/local/visado.toml
```

To see it behind Envoy with a real PDP, run the [lab](deploy/lab/): `docker compose up -d --build && ./demo.sh` in `deploy/lab`. The Transaction Token conformance vectors in [conformance/](conformance/) can be used to test other implementations; the AAT vectors there are a copy of the suite from [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo), and the asor vectors a copy of the set from [attenu-io/attenu-guard](https://github.com/attenu-io/attenu-guard).

## Documentation

- [docs/scope.md](docs/scope.md): what visado covers and what it leaves to other projects
- [docs/design.md](docs/design.md): request pipeline and plugin interfaces
- [SPEC-MAP.md](SPEC-MAP.md): pinned draft revisions and known divergences
- [docs/research/](docs/research/): background research

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off. visado follows the [CNCF Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
