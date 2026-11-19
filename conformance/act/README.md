# RFC 8693 act vectors

`vectors.json` tests how visado reads the `act` (actor) claim of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) §4.1. RFC 8693 publishes no test vectors, so these are visado's own, except for the claim sets of the RFC's Figure 5 ("Actor Claim") and Figure 6 ("Nested Actor Claim"), which are reproduced unchanged from the RFC (Copyright (c) 2020 IETF Trust and the persons identified as the document authors). Each case's `source` says which it is.

Each case gives a JWT claim set (`claims`; only `iss`, `sub`, `jti`, `iat`, `exp` and `act` are read, and the claim set is not signed), the identifier of the authenticated caller (`caller`), and optionally the verifier settings `max_actors` (default 8) and `actors` (a map from an actor's `sub` to the caller it is bound to). An accepted case has `"expect": "accept"`, the current actor in `actor`, and the prior actors, least recent first, in `prior_actors`. A rejected one has the error code in `expect`.

`crates/chain-act/tests/vectors.rs` runs every case: 20 cases, 6 accepted and 14 rejected.
