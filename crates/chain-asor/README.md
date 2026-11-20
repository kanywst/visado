# visado-chain-asor

Verifies Agent Delegation Chains as defined by [draft-asor-wimse-agent-delegation-chain-03](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) and produces the format-neutral `NormalizedChain` of [`visado-chain`](https://github.com/kanywst/visado/tree/main/crates/chain).

- `Verifier::verify` runs the whole §6 algorithm for one request, including the DPoP proof of the leaf key (step 6) and the action check (step 8).
- `Verifier::check` runs what a verifier without a request can check: the parse rules, steps 1 to 5, step 7 when status lists are configured, and the leaf audience.
- Step 7 looks each token's `status.status_list` reference up in a Token Status List ([draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/)). `StatusListVerifier` checks a fetched Status List Token; a `StatusLists` source, such as `MemoryStatusLists`, holds the verified lists. An unobtainable, expired or stale list is `status_unknown`; an `INVALID` or `SUSPENDED` entry is `revoked`.
- Denials carry the outcome names of the draft's Table 2.

All 36 published vectors pass (see [conformance/asor](https://github.com/kanywst/visado/tree/main/conformance/asor)), and so do visado's 27 status list vectors (see [conformance/asor-status](https://github.com/kanywst/visado/tree/main/conformance/asor-status)).

Pre-alpha. Licensed under Apache-2.0.
