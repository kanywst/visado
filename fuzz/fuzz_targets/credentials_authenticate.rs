//! Caller authentication reads three headers straight off the request:
//! `workload-identity-token`, `authorization` (`WPT` or `Bearer`) and the
//! user-token header. All of them are parsed before anything is verified.
//!
//! Input layout, one header value per line, an empty line meaning the header
//! is absent:
//!
//! ```text
//! <workload-identity-token>
//! <authorization>
//! <x-user-token>
//! ```
//!
//! The issuers are the test fixtures from `visado-testkit`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use visado_credentials::{Authenticator, OAuthIssuer, RequestView, WitIssuer};
use visado_testkit::{NOW, OAUTH_ISSUER, TRUST_DOMAIN, oauth_jwks, wit_issuer_verifying_key};

const NAMES: [&str; 3] = ["workload-identity-token", "authorization", "x-user-token"];

fuzz_target!(|data: &str| {
    let jwks = serde_json::from_value(oauth_jwks()).expect("fixture JWKS parses");
    let auth = Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(
            OAUTH_ISSUER,
            "https://tools.td.example/mcp",
            jwks,
        ))
        .with_replay_limits(16, 60);

    let headers: Vec<(String, String)> = NAMES
        .iter()
        .zip(data.splitn(NAMES.len(), '\n'))
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| ((*name).to_owned(), value.to_owned()))
        .collect();
    let view = RequestView {
        method: "POST",
        scheme: "https",
        authority: "tools.td.example",
        path: "/mcp?session=1",
        headers: &headers,
        body: None,
        peer_certificate: None,
    };
    let _ = auth.authenticate(&view, NOW);
});
