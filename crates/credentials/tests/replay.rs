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
const CAPACITY: usize = 256;

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
    client_token("mcp-client", holder)
}

fn client_token(client: &str, holder: &SigningKey) -> String {
    dpop_access_token("alice", client, "files.read", AUDIENCE, NOW + 300, holder)
}

/// A DPoP request by `holder` with proof `jti` issued at `iat`, at `NOW`.
fn dpop(auth: &Authenticator, holder: &SigningKey, jti: &str, iat: u64) -> Result<(), String> {
    dpop_at(auth, holder, jti, iat, NOW)
}

/// The same, received at `now`.
fn dpop_at(
    auth: &Authenticator,
    holder: &SigningKey,
    jti: &str,
    iat: u64,
    now: u64,
) -> Result<(), String> {
    let at = token(holder);
    let proof = dpop_proof(holder, "POST", HTU, &at, jti, iat);
    run(
        auth,
        &[("authorization", &format!("DPoP {at}")), ("dpop", &proof)],
        now,
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
    let auth = authenticator()
        .with_replay_key_quota(CAPACITY)
        .with_replay_client_quota(CAPACITY);
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
    let auth = authenticator()
        .with_replay_key_quota(CAPACITY)
        .with_replay_client_quota(CAPACITY);
    let holder = pop_key(7);
    for i in 0..CAPACITY {
        assert_eq!(dpop(&auth, &holder, &format!("p-{i}"), NOW), Ok(()));
    }
    assert_eq!(
        client_dpop(&auth, "other-client", &pop_key(8), "other-key").unwrap_err(),
        "wpt.replay_cache_full"
    );
    assert_eq!(workload(&auth, "agent-a", "w-1"), Ok(()));
}

/// Below half full the cache limits nobody: one key and one workload each
/// record far more than their quota.
#[test]
fn a_busy_caller_is_not_limited_while_the_cache_has_room() {
    let auth = authenticator();
    let quota = visado_credentials::default_replay_key_quota(CAPACITY);
    let busy = 25 * quota;
    assert!(busy < CAPACITY / 2);
    for i in 0..busy {
        assert_eq!(dpop(&auth, &pop_key(7), &format!("p-{i}"), NOW), Ok(()));
        assert_eq!(workload(&auth, "agent-a", &format!("w-{i}")), Ok(()));
    }
}

/// Once the cache is half full, a DPoP key past its quota is refused while
/// other keys are still served.
#[test]
fn under_pressure_one_dpop_key_holds_at_most_its_quota() {
    let auth = authenticator();
    let flood = pop_key(7);
    for i in 0..CAPACITY / 2 {
        assert_eq!(dpop(&auth, &flood, &format!("p-{i}"), NOW), Ok(()));
    }
    assert_eq!(
        dpop(&auth, &flood, "one-more", NOW).unwrap_err(),
        "credential.replay_quota"
    );
    // So is another key of the same client, past the client's quota; another
    // client's key is served.
    assert_eq!(
        dpop(&auth, &pop_key(8), "p-0", NOW).unwrap_err(),
        "credential.replay_quota"
    );
    assert_eq!(
        client_dpop(&auth, "other-client", &pop_key(8), "p-0"),
        Ok(())
    );
    // A replay is still reported as a replay.
    assert_eq!(dpop(&auth, &flood, "p-0", NOW).unwrap_err(), "dpop.replay");
}

/// The same for a workload, by WIT `sub`.
#[test]
fn under_pressure_one_workload_holds_at_most_its_quota() {
    let auth = authenticator().with_replay_key_quota(3);
    for i in 0..CAPACITY / 2 {
        assert_eq!(workload(&auth, "flood", &format!("f-{i}")), Ok(()));
    }
    for jti in ["a", "b", "c"] {
        assert_eq!(workload(&auth, "agent-a", jti), Ok(()));
    }
    assert_eq!(
        workload(&auth, "agent-a", "d").unwrap_err(),
        "credential.replay_quota"
    );
    assert_eq!(workload(&auth, "agent-b", "d"), Ok(()));
}

/// A DPoP `iat` may be ahead of the clock by the proof skew (5 s by
/// default), not by the whole `dpop_iat_window`.
#[test]
fn a_dpop_proof_from_the_future_is_refused() {
    let auth = authenticator();
    let holder = pop_key(7);
    assert_eq!(dpop(&auth, &holder, "p-1", NOW + 5), Ok(()));
    assert_eq!(
        dpop(&auth, &holder, "p-2", NOW + 6).unwrap_err(),
        "dpop.invalid"
    );
    assert_eq!(
        dpop(&auth, &holder, "p-3", NOW + 60).unwrap_err(),
        "dpop.invalid"
    );
    // The past keeps the whole window.
    assert_eq!(dpop(&auth, &holder, "p-4", NOW - 60), Ok(()));

    let strict = authenticator().with_proof_skew(0);
    assert_eq!(
        dpop(&strict, &holder, "p-5", NOW + 1).unwrap_err(),
        "dpop.invalid"
    );
    assert_eq!(dpop(&strict, &holder, "p-6", NOW), Ok(()));
}

/// A DPoP `jti` is remembered while its proof is accepted (until `iat` plus
/// the window), and no longer, so the space comes back as soon as it can.
#[test]
fn a_dpop_jti_lives_exactly_as_long_as_its_proof() {
    // One entry: the cache is always under pressure and the key's quota is
    // that entry.
    let auth = authenticator().with_replay_limits(1, 60);
    let holder = pop_key(7);
    assert_eq!(dpop(&auth, &holder, "p-1", NOW + 5), Ok(()));
    // NOW + 65 is the last second `iat` NOW + 5 is within the window.
    assert_eq!(
        dpop_at(&auth, &holder, "p-1", NOW + 5, NOW + 65).unwrap_err(),
        "dpop.replay"
    );
    assert_eq!(
        dpop_at(&auth, &holder, "p-2", NOW + 65, NOW + 65).unwrap_err(),
        "credential.replay_quota"
    );
    // A second later the entry is gone and the key's quota is free.
    assert_eq!(
        dpop_at(&auth, &holder, "p-1", NOW + 5, NOW + 66).unwrap_err(),
        "dpop.invalid"
    );
    assert_eq!(dpop_at(&auth, &holder, "p-2", NOW + 66, NOW + 66), Ok(()));
}

/// A DPoP request from OAuth client `client` with a token bound to `holder`.
fn client_dpop(
    auth: &Authenticator,
    client: &str,
    holder: &SigningKey,
    jti: &str,
) -> Result<(), String> {
    let at = client_token(client, holder);
    let proof = dpop_proof(holder, "POST", HTU, &at, jti, NOW);
    run(
        auth,
        &[("authorization", &format!("DPoP {at}")), ("dpop", &proof)],
        NOW,
    )
    .map(|_| ())
}

/// Under pressure, one client with many DPoP-bound keys holds one client
/// quota across all of them, so more keys do not buy it more of the cache.
#[test]
fn one_client_holds_at_most_its_quota_across_its_keys() {
    let auth = authenticator()
        .with_replay_key_quota(4)
        .with_replay_client_quota(6);
    // Another client brings the cache to half full, freely.
    for i in 0..CAPACITY / 2 {
        assert_eq!(
            client_dpop(&auth, "filler", &pop_key(20), &format!("f-{i}")),
            Ok(())
        );
    }
    let accepted = (1..=4)
        .flat_map(|key| (0..4).map(move |i| (key, i)))
        .filter(|(key, i)| {
            client_dpop(&auth, "mcp-client", &pop_key(*key), &format!("p-{key}-{i}")).is_ok()
        })
        .count();
    assert_eq!(accepted, 6, "four keys of one client share six entries");
    assert_eq!(
        client_dpop(&auth, "mcp-client", &pop_key(5), "p-5").unwrap_err(),
        "credential.replay_quota"
    );
    // Another client still has room.
    assert_eq!(
        client_dpop(&auth, "other-client", &pop_key(9), "p-9"),
        Ok(())
    );
}

/// The default quotas leave a large number of keys or clients needed to
/// fill a cache, with an absolute cap for large caches.
#[test]
fn default_quotas_are_a_small_share() {
    use visado_credentials::{
        DEFAULT_REPLAY_CAPACITY, default_replay_client_quota, default_replay_key_quota,
    };
    assert_eq!(default_replay_key_quota(DEFAULT_REPLAY_CAPACITY), 1_562);
    assert_eq!(default_replay_client_quota(DEFAULT_REPLAY_CAPACITY), 3_125);
    assert_eq!(default_replay_key_quota(10_000_000), 5_000);
    assert_eq!(default_replay_client_quota(10_000_000), 10_000);
    assert_eq!(default_replay_key_quota(100), 1);
    assert_eq!(default_replay_key_quota(0), 0);
}
