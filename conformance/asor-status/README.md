# asor status list vectors

`vectors.json` tests step 7 of [draft-asor-wimse-agent-delegation-chain-03](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) §6: each token's `status` reference is looked up in a Token Status List ([draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/)). Neither draft publishes vectors for this, so these are visado's own.

The file gives the verification time `now`, the verifier's `max_age` (how long a fetched list is trusted when its `ttl` is longer or absent), the enforcement point's `audience`, and two Ed25519 keys as JWKs: `chain_anchor` signs the Delegation Tokens and `status_list_anchor` signs the Status List Tokens.

Each case gives a chain (`chain`, root first) and the fetches of the status list that came before `now` (`lists`, in order). A fetch has the list's `uri`, the time it was fetched (`fetched_at`) and the Status List Token it returned, or `null` if the fetch failed. A fetch that fails, or returns a list issued before the one held, keeps the list already held. Run the parse rules, steps 1 to 5, step 7 and the audience half of step 8. An accepted case has `"expect": "accept"`. A rejected one names the Table 2 outcome in `expect`, the position of the token that failed in `token`, and visado's reason in `reason`.

The list used by most cases has `bits` 2 and eight entries: index 0 `VALID`, 1 `INVALID`, 2 `SUSPENDED`, 3 the application-specific value `0x03`, and 4 to 7 `VALID`.

`crates/chain-asor/tests/status.rs` generates the file, fails when the committed one is stale, and runs every case: 27 cases, 3 accepted and 24 rejected. Regenerate with `VISADO_REGENERATE=1 cargo test -p visado-chain-asor`.
