//! OAuth Transaction Tokens, per draft-ietf-oauth-transaction-tokens-11.
//!
//! - [`mint`] signs a claim set as a `txntoken+jwt`.
//! - [`verify`] checks a received token: signature, `aud` against the
//!   recipient's trust domain, and time (§12.2).
//! - [`replace`] builds a replacement token's claims and [`check_replacement`]
//!   checks one (§13.15).
//! - [`TokenRequest`] parses a request to a Transaction Token Service (§11.1).
//!
//! Signing uses `wimsey-jose`, so tokens are minted with `Ed25519`, `EdDSA`
//! or `ES256`. [`verify`] also takes `RS256` tokens from a Transaction Token
//! Service that signs with RSA, with keys of at least 2048 bits
//! ([`KeySet::with_rsa_key`]).
//!
//! ```
//! use visado_txn_token::{mint, verify, KeySet, Scope, TxnTokenClaims, Validation};
//! use wimsey_jose::SigningKey;
//!
//! let key = SigningKey::from_ed25519_seed(&[7; 32]);
//! let claims = TxnTokenClaims {
//!     iss: None,
//!     iat: 1_000,
//!     aud: "trust-domain.example".into(),
//!     exp: 1_060,
//!     txn: "97053963-771d-49cc-a4e3-20aad399c312".into(),
//!     sub: "user@example.com".into(),
//!     scope: Scope::parse("trade.stocks"),
//!     req_wl: "spiffe://trust-domain.example/gateway".into(),
//!     tctx: None,
//!     rctx: None,
//! };
//! let token = mint(&claims, Some("k1"), &key).unwrap();
//!
//! let keys = KeySet::new().with_key("k1", key.verifying_key());
//! let verified = verify(&token, &keys, &Validation::new("trust-domain.example", 1_010)).unwrap();
//! assert_eq!(verified.claims, claims);
//! ```

mod claims;
mod error;
mod keys;
mod replace;
mod request;
mod token;

pub use claims::{Scope, TxnTokenClaims};
pub use error::TxnTokenError;
pub use keys::{KeySet, MIN_RSA_BITS};
pub use replace::{Replacement, check_replacement, replace};
pub use request::{
    GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_REFRESH_TOKEN, TOKEN_TYPE_SELF_SIGNED,
    TOKEN_TYPE_TXN_TOKEN, TOKEN_TYPE_UNSIGNED_JSON, TokenRequest,
};
pub use token::{
    HEADER, MAX_TOKEN_LEN, TYP, Validation, VerifiedTxnToken, fingerprint, mint, verify,
};
