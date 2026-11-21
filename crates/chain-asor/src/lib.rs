//! Agent Delegation Chains, per draft-asor-wimse-agent-delegation-chain-03.
//!
//! A chain is a list of Delegation Tokens: RFC 9068 JWT access tokens in
//! JCS form, each carrying one `agent_delegation` authorization detail, the
//! Principal in `sub`, the acting agent in `client_id`, and a holder key in
//! `cnf.jkt`. Each child commits to its parent with `par_hash`.
//!
//! [`Verifier::verify`] runs the §6 algorithm for one request: the parse
//! rules, signatures under a trusted key (1), `par_hash` (2), depth and
//! principal (3), attenuation (4), time (5), the DPoP proof of the leaf key
//! (6), status (7) and the audience and action (8). A failure reports the
//! Table 2 [`Outcome`].
//!
//! Step 7 reads `status.status_list` references (Token Status List,
//! draft-ietf-oauth-status-list-21) from a [`StatusLists`] source, which
//! holds Status List Tokens a [`StatusListVerifier`] checked. A list that
//! cannot be obtained, has expired, or has outlived its `ttl` (or the
//! verifier's maximum age) is `status_unknown`; an `INVALID` or `SUSPENDED`
//! entry is `revoked`.
//!
//! [`Verifier::check`] runs what a verifier without a request can check
//! (the parse rules, steps 1 to 5 and the audience); the
//! [`ChainDecoder`](visado_chain::ChainDecoder) implementation runs the
//! parse rules and steps 1 to 5. Both yield a
//! [`NormalizedChain`](visado_chain::NormalizedChain) with `holder_proof`
//! false.
//!
//! Every token is signed by a configured trust anchor (the draft's
//! single-signer model). `Ed25519` and `ES256` are accepted by default;
//! `HS256` exists only to run the published test vectors.

mod authority;
mod dpop;
mod error;
mod scope;
mod status;
mod verify;

pub use authority::{Cumulative, DETAIL_TYPE, RunningTotals};
pub use dpop::{DPOP_ALGS, DPOP_TYP, HttpRequest};
pub use error::{AsorError, Outcome};
pub use status::{
    DEFAULT_STATUS_MAX_AGE, MemoryStatusLists, STATUS_LIST_TYPS, StatusList, StatusListError,
    StatusListVerifier, StatusLists,
};
pub use verify::{Action, Alg, Authorized, Limits, Presentation, TYPS, TrustAnchor, Verifier};
pub use visado_chain::replay::{MemoryReplayCache, ReplayCache};
