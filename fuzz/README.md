# Fuzzing

Everything visado decides on arrives as bytes from somebody else: Transaction Tokens, token requests, AAT chains and PoP JWTs, WIMSE and OAuth credentials, and the PDP's response. All of it is parsed before it is trusted, so a panic there is a denial of service reachable by anyone who can reach the port.

The targets run under [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html), which needs a nightly toolchain for libFuzzer's instrumentation. The workspace itself stays on stable; this directory is excluded from it.

## Targets

| Target | What it feeds |
| --- | --- |
| `txn_token_verify` | `visado_txn_token::verify` on the input as a token, with the conformance keys and validation |
| `txn_token_request` | `TokenRequest::from_form`, one `name=value` pair per line |
| `aat_verify` | `Verifier::verify`: a `,`-separated chain, the PoP JWT, the tool and the arguments JSON, one per line, against the conformance anchors |
| `aat_decode` | `ChainDecoder::decode` on a `,`-separated chain |
| `authzen_response` | `visado_authzen::parse_response` on the input as a response body |
| `credentials_authenticate` | `Authenticator::authenticate` with the `workload-identity-token`, `authorization`, `x-user-token` and `dpop` values, one per line (empty means absent) |

Keys, anchors and clocks are fixed to the conformance suite's, so seeds from the vectors pass the signature checks and the fuzzer spends its time in what follows. What is tested is that every rejection is a returned error rather than a panic, an overflow or a hang.

## Running them

```bash
cargo install cargo-fuzz --locked
rustup toolchain install nightly

# Seed each corpus from the conformance vectors first.
./fuzz/seed-corpus.sh

cargo +nightly fuzz run aat_verify -- -max_total_time=600
```

A crash is written to `fuzz/artifacts/<target>/` and replays with:

```bash
cargo +nightly fuzz run aat_verify fuzz/artifacts/aat_verify/crash-<hash>
```

Corpora and crash artifacts are not committed; `.gitignore` covers both. If a run turns something up, fix it with a regression test in the crate, and add the input to the conformance vectors as a negative case where it fits one.

## What CI does

CI runs each target for 30 seconds against the seeded corpus. That is a regression gate, not a hunt: finding new bugs needs runs measured in hours, which is what the commands above are for.
