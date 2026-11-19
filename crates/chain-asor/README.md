# visado-chain-asor

Verifies Agent Delegation Chains as defined by [draft-asor-wimse-agent-delegation-chain-03](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) and produces the format-neutral `NormalizedChain` of [`visado-chain`](https://github.com/kanywst/visado/tree/main/crates/chain).

- `Verifier::verify` runs the whole §6 algorithm for one request, including the DPoP proof of the leaf key (step 6) and the action check (step 8).
- `Verifier::check` runs what a verifier without a request can check: the parse rules, steps 1 to 5, and the leaf audience.
- Denials carry the outcome names of the draft's Table 2.

All 36 published vectors pass (see [conformance/asor](https://github.com/kanywst/visado/tree/main/conformance/asor)). Status lists (step 7) are not implemented, so a token with a `status` claim is denied as `status_unknown`.

Pre-alpha. Licensed under Apache-2.0.
