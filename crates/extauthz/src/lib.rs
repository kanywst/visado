//! The visado decision pipeline ([`Gate`]) and the Envoy ext_authz v3 gRPC
//! service around it ([`ExtAuthz`]).
//!
//! For each request the gate:
//!
//! 1. authenticates the caller (WIT with WPT or an HTTP signature, mTLS,
//!    JWT-SVID, or an OAuth access token),
//! 2. accepts an inbound Transaction Token only from a configured internal hop,
//! 3. asks the AuthZEN PDP, failing closed on any error,
//! 4. mints a Transaction Token, or forwards the verified inbound one,
//! 5. removes the inbound credentials so they never reach the upstream,
//!    and, when DPoP nonces are required, hands out a fresh `DPoP-Nonce` on
//!    every 401 and after every request with a DPoP proof,
//! 6. writes one [`audit::AuditRecord`] per decision under the
//!    `visado::audit` tracing target, hash-chained to the one before. Tokens
//!    are never logged.
//!
//! A gate given a [`RequestLog`] also keeps a summary of each recent decision
//! (identifiers, outcomes and the verified chain, never tokens) for the chain
//! view.

pub mod audit;
mod gate;
pub mod recent;
mod service;

pub use gate::{
    AAT_CHAIN_HEADER, AAT_POP_HEADER, CheckInput, DPOP_NONCE_HEADER, FORWARDED_HEADERS, Gate,
    GateConfig, Outcome, STRIPPED_HEADERS,
};
pub use recent::RequestLog;
pub use service::ExtAuthz;
