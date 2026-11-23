//! Replay caches: one per proof type, a quota per caller, and how long a
//! proof is remembered.

use visado_credentials::{Authenticated, Authenticator, OAuthIssuer, RequestView, WitIssuer};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, dpop_access_token, dpop_proof, oauth_jwks, pop_key, wit,
    wit_issuer_verifying_key, wpt,
};
use wimsey_jose::SigningKey;

const AUDIENCE: &str = "https://tools.td.example/mcp";
const HTU: &str = "https://tools.td.example/mcp";
const CAPACITY: usize = 32;

fn authenticator() -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks))
        .with_replay_limits(CAPACITY, 60)
}

fn run(auth: &Authenticator, headers: &[(&str, &str)], now: u64) -> Result<Authenticated, String> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let view = RequestView {
        method: "POST",
        scheme: "https",
        authority: "tools.td.example",
        path: "/mcp",
        headers: &headers,
        body: None,
        peer_certificate: None,
    };
    auth.authenticate(&view, now)
        .map_err(|e| e.code().to_owned())
}

fn token(holder: &SigningKey) -> String {
    dpop_access_token(
        "alice",
        "mcp-client",
        "files.read",
        AUDIENCE,
        NOW + 300,
        holder,
    )
}

/// A DPoP request by `holder` with proof `jti` issued at `iat`.
fn dpop(auth: &Authenticator, holder: &SigningKey, jti: &str, iat: u64) -> Result<(), String> {
    let at = token(holder);
    let proof = dpop_proof(holder, "POST", HTU, &at, jti, iat);
    run(
        auth,
        &[("authorization", &format!("DPoP {at}")), ("dpop", &proof)],
        NOW,
    )
    .map(|_| ())
}

/// A WIT and WPT request from `workload` with WPT `jti`.
fn workload(auth: &Authenticator, workload: &str, jti: &str) -> Result<(), String> {
    let key = pop_key(1);
    let w = wit(workload, &key);
    let p = wpt(&w, &key, AUDIENCE, jti, None, None);
    run(
        auth,
        &[
            ("workload-identity-token", &w),
            ("authorization", &format!("WPT {p}")),
        ],
        NOW,
    )
    .map(|_| ())
}

/// The reported attack: one DPoP client sends proofs with fresh `jti`
/// values until the replay cache is full. A workload calling with a WIT and
/// a WPT must still get through.
#[test]
fn a_dpop_flood_does_not_lock_out_workloads() {
    let auth = authenticator().with_replay_key_quota(CAPACITY);
    let holder = pop_key(7);
    // iat as far ahead as the window allowed when the flood was reported.
    let refused = (0..=CAPACITY)
        .map(|i| dpop(&auth, &holder, &format!("flood-{i}"), NOW + 60))
        .filter(Result::is_err)
        .count();
    assert!(refused > 0, "the flood was never refused");
    assert_eq!(workload(&auth, "agent-a", "w-1"), Ok(()));
}

/// The same with proofs a client may legitimately send: a full DPoP cache
/// refuses DPoP proofs only.
#[test]
fn a_full_dpop_cache_refuses_only_dpop_proofs() {
    let auth = authenticator().with_replay_key_quota(CAPACITY);
    let holder = pop_key(7);
    for i in 0..CAPACITY {
        assert_eq!(dpop(&auth, &holder, &format!("p-{i}"), NOW), Ok(()));
    }
    assert_eq!(
        dpop(&auth, &pop_key(8), "other-key", NOW).unwrap_err(),
        "wpt.replay_cache_full"
    );
    assert_eq!(workload(&auth, "agent-a", "w-1"), Ok(()));
}

/// One DPoP key can hold only its quota of the cache, so other keys are
/// still served while it floods.
#[test]
fn one_dpop_key_holds_at_most_its_quota() {
    let auth = authenticator();
    let flood = pop_key(7);
    let quota = CAPACITY / 4;
    for i in 0..quota {
        assert_eq!(dpop(&auth, &flood, &format!("p-{i}"), NOW), Ok(()));
    }
    assert_eq!(
        dpop(&auth, &flood, "one-more", NOW).unwrap_err(),
        "credential.replay_quota"
    );
    assert_eq!(dpop(&auth, &pop_key(8), "p-0", NOW), Ok(()));
    // A replay is still reported as a replay.
    assert_eq!(dpop(&auth, &flood, "p-0", NOW).unwrap_err(), "dpop.replay");
}

/// The same for a workload, by WIT `sub`.
#[test]
fn one_workload_holds_at_most_its_quota() {
    let auth = authenticator().with_replay_key_quota(3);
    for jti in ["a", "b", "c"] {
        assert_eq!(workload(&auth, "agent-a", jti), Ok(()));
    }
    assert_eq!(
        workload(&auth, "agent-a", "d").unwrap_err(),
        "credential.replay_quota"
    );
    assert_eq!(workload(&auth, "agent-b", "d"), Ok(()));
}
