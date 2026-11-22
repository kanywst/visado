# Interop harnesses

Runs of visado against independent implementations of the specs it implements. The results are in [docs/interop.md](../docs/interop.md).

| Directory | Spec | Other implementations |
| --- | --- | --- |
| [aat/](aat/) | draft-niyikiza-oauth-attenuating-agent-tokens-02 | tenuo-ai/tenuo (vector suite and its Section 8 verifier) |
| [asor/](asor/) | draft-asor-wimse-agent-delegation-chain-03 | attenu-io/attenu-guard 0.22.0 |
| [txn-token/](txn-token/) | draft-ietf-oauth-transaction-tokens-11 | authgent, atlas-go, kontxt |
| [wimse/](wimse/) | WIMSE workload-creds-03, wpt-02, http-signature-08 | wit-wpt-go, go-spiffe witsvid, Cofide PoC, the WG example generator |

[harness/](harness/) is the visado side: the `visado-interop`, `txn` and `wimse` binaries read and write JSON so a script in another language can drive them. Each directory's `run.sh` pins the other implementation (commit, version or wheel hash), builds the harness, runs both directions where the other side can mint and verify, and rewrites `results/`. The scripts need network access to GitHub and the package registries, so CI does not run them; CI builds and lints the harness with the rest of the workspace.
