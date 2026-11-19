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
//! 6. writes an audit event under the `visado::audit` tracing target. Tokens
//!    are never logged.

mod gate;
mod service;

pub use gate::{
    AAT_CHAIN_HEADER, AAT_POP_HEADER, CheckInput, Gate, GateConfig, Outcome, STRIPPED_HEADERS,
};
pub use service::ExtAuthz;
