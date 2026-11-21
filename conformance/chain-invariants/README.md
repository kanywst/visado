# Chain invariant vectors

`vectors.json` tests visado's format-neutral invariant engine and the authority algebras of its three chain formats (see [docs/design.md](../../docs/design.md), "Delegation chain"). No draft defines these checks over a normalized chain, so the cases are visado's own.

Each case gives a normalized chain (`chain`), the action it is asked to authorize (`action`: a `name` and the parameters as JSON text in `params_json`, or `null` for none) and which checks to run (`check`): `full` runs every invariant, `chain` only those that need no request (no status, holder proof or action check). The chain has the fields of `NormalizedChain` in `crates/chain`:

| Field | Value |
| --- | --- |
| `profile` | `aat-02`, `asor-03` or `rfc8693-act`; it selects the depth semantics |
| `principal` | `{issuer, subject}`, or `null` when the format names none |
| `root` | the trust anchor: `{issuer, key}` |
| `holder_proof` | whether the presenter proved possession of the leaf key |
| `hops` | first hop first |

Each hop has `id`, `depth`, `max_depth` (or `null`), `actor` (`{key}`, `{name}` or `{issuer, subject}`), `principal`, `delegator` (`null` for the first hop), `signer`, `signer_binding` (`root_anchor` or `parent_cnf`), `link` (`root`, `nested` or `{par_hash}`), `authority` (`{type, json}`, the authority as the format's canonical JSON), `validity` (`{issued_at, expires_at}`), `audience` (a list, or `null` for none), `cnf` (the holder key thumbprint, or `null`), `status` (`null`, `unchecked` or `valid`) and `assurance` (`verified` or `declared`).

The algebras are those of `attenuating_agent_token` (AAT §8 step 4p and step 6b), `agent_delegation` (asor-03 §4.3 rules 1 to 3 and step 8) and `rfc8693-act` (only the empty authority, and no action). Any other authority type is unknown and denied.

An accepted case names the depth semantics that applied in `expect` (`aat-holder-cap`, `asor-strict` or `uncapped`) and has `hop: null`. A rejected one names the deny code in `expect` and the position of the hop that broke the invariant in `hop` (`null` when no single hop did). Invariants are checked in the engine's order, so a case breaks exactly one.

`crates/extauthz/tests/chain_invariants.rs` generates the file, fails when the committed one is stale, and runs every case: 39 cases, 7 accepted and 32 rejected. Regenerate with `VISADO_REGENERATE=1 cargo test -p visado-extauthz --test chain_invariants`.
