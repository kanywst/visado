# visado-chain-act

Reads the RFC 8693 `act` (actor) claim of a verified OAuth access token as a delegation chain, the format-neutral `NormalizedChain` of [`visado-chain`](https://github.com/kanywst/visado/tree/main/crates/chain).

- `Verifier::decode` checks the claim's shape (each `act` an object with a string `sub`, a limited number of actors) and returns the actors from the least recent to the current one.
- `Verifier::verify` also requires the current actor (the outermost `act`) to be the authenticated caller, directly or through a configured mapping. Prior actors are informational, as RFC 8693 §4.1 requires, and are never compared with anything.
- Errors are named `act.*`.

The vectors in [conformance/act](https://github.com/kanywst/visado/tree/main/conformance/act) pass.

Pre-alpha. Licensed under Apache-2.0.
