//! Step 7 with Token Status Lists: generates `conformance/asor-status/
//! vectors.json`, checks that the committed file is current, and runs every
//! case from the file. Set `VISADO_REGENERATE=1` to rewrite the file after an
//! intended change.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use visado_chain::algebra::{Action, Algebras};
use visado_chain::invariants::{Engine, Invariant};
use visado_chain::{ChainDecoder, StatusCheck};
use visado_chain_asor::{
    MemoryStatusLists, StatusListError, StatusListVerifier, TrustAnchor, Verifier,
};
use visado_testkit::{
    ASOR_ISSUER, STATUS_LIST_ISSUER, STATUS_LIST_URI, asor_anchor_key, asor_child_claims,
    asor_root_claims, asor_sign, pop_key, sign_dpop_proof, status_list_key, status_list_lst,
    status_list_token,
};
use wimsey_jose::Jwk;

const NOW: i64 = 1_800_000_000;
const MAX_AGE: i64 = 300;
const AUD: &str = "https://tools.example.com";

/// Index 0 is `VALID`, 1 `INVALID`, 2 `SUSPENDED`, 3 an application-specific
/// value; 4 to 7 are `VALID`.
const STATUSES: [u8; 8] = [0, 1, 2, 3, 0, 0, 0, 0];

fn now() -> u64 {
    u64::try_from(NOW).unwrap()
}

fn root_claims() -> Value {
    asor_root_claims(
        "r",
        "orchestrator",
        &pop_key(1),
        &json!(["crm.*"]),
        &json!([]),
        AUD,
        now(),
        5,
    )
}

fn reference(idx: i64) -> Value {
    json!({ "status_list": { "idx": idx, "uri": STATUS_LIST_URI } })
}

/// A one-token chain whose root carries `status`.
fn root_with(status: &Value) -> Vec<String> {
    let mut claims = root_claims();
    claims["status"] = status.clone();
    vec![asor_sign(&claims)]
}

/// A root with `root_status` and a child with `child_status`.
fn pair(root_status: &Value, child_status: &Value) -> Vec<String> {
    let mut claims = root_claims();
    claims["status"] = root_status.clone();
    let root = asor_sign(&claims);
    let mut child = asor_child_claims(
        "c",
        "reader",
        &root,
        &pop_key(2),
        1,
        &json!(["crm.read"]),
        &json!([]),
        AUD,
        now(),
    );
    child["status"] = child_status.clone();
    vec![root, asor_sign(&child)]
}

fn header() -> Value {
    json!({ "alg": "Ed25519", "kid": "status-1", "typ": "statuslist+jwt" })
}

fn list_claims(iat: i64) -> Value {
    json!({
        "iss": STATUS_LIST_ISSUER, "sub": STATUS_LIST_URI, "iat": iat, "exp": NOW + 3600,
        "ttl": 120, "status_list": { "bits": 2, "lst": status_list_lst(2, &STATUSES) },
    })
}

fn list() -> String {
    status_list_token(&header(), &list_claims(NOW - 10))
}

fn with(mut value: Value, path: &[&str], member: Value) -> Value {
    let (last, parents) = path.split_last().unwrap();
    let mut at = &mut value;
    for p in parents {
        at = &mut at[*p];
    }
    if member.is_null() {
        at.as_object_mut().unwrap().remove(*last);
    } else {
        at[*last] = member;
    }
    value
}

fn signed(claims: &Value) -> String {
    status_list_token(&header(), claims)
}

fn fetched(token: Value, at: i64) -> Value {
    let mut fetch = json!({ "uri": STATUS_LIST_URI, "fetched_at": at });
    fetch["token"] = token;
    fetch
}

fn fresh(token: String) -> Value {
    fetched(token.into(), NOW - 10)
}

fn case(name: &str, description: &str, chain: &[String], lists: &[Value], expect: &str) -> Value {
    json!({
        "name": name, "description": description, "chain": chain, "lists": lists,
        "expect": expect,
    })
}

fn deny(mut case: Value, token: usize, reason: &str) -> Value {
    case["token"] = json!(token);
    case["reason"] = json!(reason);
    case
}

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Value> {
    let other_key = sign_dpop_proof(&header(), &list_claims(NOW - 10), &pop_key(9));
    let expired_by_now = signed(&with(list_claims(NOW - 10), &["exp"], json!(NOW - 5)));
    let older = with(
        list_claims(NOW - 100),
        &["status_list", "lst"],
        json!(status_list_lst(2, &[0; 8])),
    );
    vec![
        case(
            "valid",
            "The root's entry is VALID.",
            &root_with(&reference(0)),
            &[fresh(list())],
            "accept",
        ),
        case(
            "valid-chain",
            "Both tokens carry a reference to a VALID entry.",
            &pair(&reference(0), &reference(4)),
            &[fresh(list())],
            "accept",
        ),
        deny(
            case(
                "revoked",
                "The entry is INVALID (0x01).",
                &root_with(&reference(1)),
                &[fresh(list())],
                "revoked",
            ),
            0,
            "token is revoked",
        ),
        deny(
            case(
                "suspended",
                "The entry is SUSPENDED (0x02).",
                &root_with(&reference(2)),
                &[fresh(list())],
                "revoked",
            ),
            0,
            "token is suspended",
        ),
        deny(
            case(
                "revoked-parent",
                "The child is VALID but its parent is INVALID: the whole chain is denied.",
                &pair(&reference(1), &reference(0)),
                &[fresh(list())],
                "revoked",
            ),
            0,
            "token is revoked",
        ),
        deny(
            case(
                "revoked-child",
                "The root is VALID, the child INVALID.",
                &pair(&reference(0), &reference(1)),
                &[fresh(list())],
                "revoked",
            ),
            1,
            "token is revoked",
        ),
        deny(
            case(
                "application-specific-value",
                "The entry is 0x03, an application-specific value this verifier does not know.",
                &root_with(&reference(3)),
                &[fresh(list())],
                "status_unknown",
            ),
            0,
            "status value not understood",
        ),
        deny(
            case(
                "index-out-of-range",
                "The list has 8 entries (2 bytes at 2 bits); idx 8 is past the end.",
                &root_with(&reference(8)),
                &[fresh(list())],
                "status_unknown",
            ),
            0,
            "status index out of range",
        ),
        deny(
            case(
                "no-list",
                "No list is held for the uri.",
                &root_with(&reference(0)),
                &[],
                "status_unknown",
            ),
            0,
            "no status list is configured for this uri",
        ),
        deny(
            case(
                "unreachable",
                "The only fetch of the list failed.",
                &root_with(&reference(0)),
                &[fetched(Value::Null, NOW - 10)],
                "status_unknown",
            ),
            0,
            "status list could not be fetched",
        ),
        case(
            "refresh-failed-within-ttl",
            "A refresh failed, but the list fetched before it is still within its ttl.",
            &root_with(&reference(0)),
            &[fresh(list()), fetched(Value::Null, NOW - 5)],
            "accept",
        ),
        deny(
            case(
                "stale-ttl",
                "The list was fetched 121 s ago and its ttl is 120 s.",
                &root_with(&reference(0)),
                &[fetched(signed(&list_claims(NOW - 200)).into(), NOW - 121)],
                "status_unknown",
            ),
            0,
            "status list outlived its time to live",
        ),
        deny(
            case(
                "stale-max-age",
                "The list has no ttl and was fetched 300 s ago, the verifier's max_age.",
                &root_with(&reference(0)),
                &[fetched(
                    signed(&with(list_claims(NOW - 400), &["ttl"], Value::Null)).into(),
                    NOW - 300,
                )],
                "status_unknown",
            ),
            0,
            "status list outlived its time to live",
        ),
        deny(
            case(
                "stale-iat-without-exp",
                "The list has no exp or ttl and was fetched 5 s ago, but was issued 400 s ago, past max_age.",
                &root_with(&reference(0)),
                &[fetched(
                    signed(&with(
                        with(list_claims(NOW - 400), &["ttl"], Value::Null),
                        &["exp"],
                        Value::Null,
                    ))
                    .into(),
                    NOW - 5,
                )],
                "status_unknown",
            ),
            0,
            "status list outlived its time to live",
        ),
        deny(
            case(
                "iat-in-the-future",
                "The list's iat was more than 60 s ahead of the clock when it was fetched.",
                &root_with(&reference(0)),
                &[fetched(signed(&list_claims(NOW + 120)).into(), NOW - 5)],
                "status_unknown",
            ),
            0,
            "status list iat is in the future",
        ),
        deny(
            case(
                "expired-since-fetch",
                "The list was valid when fetched; its exp has passed since.",
                &root_with(&reference(0)),
                &[fresh(expired_by_now)],
                "status_unknown",
            ),
            0,
            "status list expired",
        ),
        deny(
            case(
                "expired-at-fetch",
                "The list's exp had passed when it was fetched.",
                &root_with(&reference(0)),
                &[fresh(signed(&with(
                    list_claims(NOW - 100),
                    &["exp"],
                    json!(NOW - 20),
                )))],
                "status_unknown",
            ),
            0,
            "status list token expired or not yet valid",
        ),
        deny(
            case(
                "bad-signature",
                "The list is signed by a key that is not trusted for status lists.",
                &root_with(&reference(0)),
                &[fresh(other_key)],
                "status_unknown",
            ),
            0,
            "status list signature does not verify under a trusted key",
        ),
        deny(
            case(
                "issuer-mismatch",
                "The list's iss is not the issuer of the key that signed it.",
                &root_with(&reference(0)),
                &[fresh(signed(&with(
                    list_claims(NOW - 10),
                    &["iss"],
                    json!("https://other.example"),
                )))],
                "status_unknown",
            ),
            0,
            "status list signature does not verify under a trusted key",
        ),
        deny(
            case(
                "wrong-type",
                "The list's typ is JWT, not statuslist+jwt.",
                &root_with(&reference(0)),
                &[fresh(status_list_token(
                    &with(header(), &["typ"], json!("JWT")),
                    &list_claims(NOW - 10),
                ))],
                "status_unknown",
            ),
            0,
            "status list typ is not statuslist+jwt",
        ),
        deny(
            case(
                "subject-mismatch",
                "The list's sub names another list.",
                &root_with(&reference(0)),
                &[fresh(signed(&with(
                    list_claims(NOW - 10),
                    &["sub"],
                    json!("https://status.td.example/lists/2"),
                )))],
                "status_unknown",
            ),
            0,
            "status list sub is not the uri",
        ),
        deny(
            case(
                "bits-not-allowed",
                "bits is 3.",
                &root_with(&reference(0)),
                &[fresh(signed(&with(
                    list_claims(NOW - 10),
                    &["status_list", "bits"],
                    json!(3),
                )))],
                "status_unknown",
            ),
            0,
            "status_list.bits is not 1, 2, 4 or 8",
        ),
        deny(
            case(
                "lst-not-zlib",
                "lst is base64url but not ZLIB data.",
                &root_with(&reference(0)),
                &[fresh(signed(&with(
                    list_claims(NOW - 10),
                    &["status_list", "lst"],
                    json!("AAAA"),
                )))],
                "status_unknown",
            ),
            0,
            "status_list.lst is not ZLIB data",
        ),
        deny(
            case(
                "missing-iat",
                "The list has no iat.",
                &root_with(&reference(0)),
                &[fresh(signed(&with(
                    list_claims(NOW - 10),
                    &["iat"],
                    Value::Null,
                )))],
                "status_unknown",
            ),
            0,
            "status list iat is not an integer",
        ),
        deny(
            case(
                "rollback",
                "A list issued before the one held, which marks idx 1 VALID, does not replace it.",
                &root_with(&reference(1)),
                &[fresh(list()), fetched(signed(&older).into(), NOW - 5)],
                "revoked",
            ),
            0,
            "token is revoked",
        ),
        deny(
            case(
                "other-mechanism",
                "status names a mechanism other than status_list.",
                &root_with(&json!({ "other_mechanism": { "uri": STATUS_LIST_URI } })),
                &[fresh(list())],
                "status_unknown",
            ),
            0,
            "status mechanism not supported",
        ),
        deny(
            case(
                "negative-index",
                "status_list.idx is negative: the claim is malformed.",
                &root_with(&reference(-1)),
                &[fresh(list())],
                "malformed",
            ),
            0,
            "status_list.idx is not a non-negative integer",
        ),
    ]
}

fn anchor_json(issuer: &str, jwk: &Jwk, kid: Option<&str>) -> Value {
    json!({ "issuer": issuer, "kid": kid, "jwk": jwk })
}

fn build() -> Value {
    json!({
        "format": "visado-asor-status-vectors/v1",
        "suite": "asor-status",
        "spec": "draft-asor-wimse-agent-delegation-chain-03 §6 step 7, with draft-ietf-oauth-status-list-21",
        "now": NOW,
        "max_age": MAX_AGE,
        "audience": AUD,
        "chain_anchor": anchor_json(ASOR_ISSUER, &Jwk::from_verifying_key(&asor_anchor_key().verifying_key()), None),
        "status_list_anchor": anchor_json(STATUS_LIST_ISSUER, &Jwk::from_verifying_key(&status_list_key().verifying_key()), Some("status-1")),
        "cases": cases(),
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/asor-status/vectors.json")
}

fn anchor(value: &Value) -> TrustAnchor {
    let jwk: Jwk = serde_json::from_value(value["jwk"].clone()).unwrap();
    let anchor = TrustAnchor::new(
        value["issuer"].as_str().unwrap(),
        jwk.to_verifying_key().unwrap(),
    );
    match value["kid"].as_str() {
        Some(kid) => anchor.with_kid(kid),
        None => anchor,
    }
}

/// Loads `lists` in order, as a fetcher would, and checks the chain.
fn run(suite: &Value, case: &Value) -> Result<(), visado_chain_asor::AsorError> {
    let now = suite["now"].as_i64().unwrap();
    let lists = Arc::new(MemoryStatusLists::new());
    let status = StatusListVerifier::new(vec![anchor(&suite["status_list_anchor"])]);
    for fetch in case["lists"].as_array().unwrap() {
        let uri = fetch["uri"].as_str().unwrap();
        let at = fetch["fetched_at"].as_i64().unwrap();
        let result = match fetch["token"].as_str() {
            Some(token) => status.verify(token, uri, at),
            None => Err(StatusListError::Unavailable),
        };
        let _ = lists.update(uri, result);
    }
    let verifier = Verifier::new(
        vec![anchor(&suite["chain_anchor"])],
        vec![suite["audience"].as_str().unwrap().to_owned()],
    )
    .with_status_lists(lists)
    .with_status_max_age(suite["max_age"].as_i64().unwrap());
    let chain: Vec<String> = serde_json::from_value(case["chain"].clone()).unwrap();
    let checked = verifier.check(&chain, now)?;
    // Step 7 ran, so every reference is recorded as checked; a decoded
    // chain, which skips step 7, records the same references as unchecked.
    let decoded = verifier.decode(&chain, now).expect("decode after check");
    assert!(checked.hops.iter().any(|h| h.status.is_some()));
    for (c, d) in checked.hops.iter().zip(&decoded.hops) {
        assert_eq!(c.status.is_some(), d.status.is_some());
        assert!(c.status.is_none_or(|s| s == StatusCheck::Valid));
        assert!(d.status.is_none_or(|s| s == StatusCheck::Unchecked));
    }
    // The engine accepts the checked chain and refuses the decoded one,
    // whose references were never looked up.
    let engine = Engine::new(Algebras::new().with(Arc::new(verifier.algebra())));
    let action = Action {
        name: "crm.read",
        params_json: "{}",
    };
    let proved = |chain: visado_chain::NormalizedChain| visado_chain::NormalizedChain {
        holder_proof: true,
        ..chain
    };
    engine
        .check(&proved(checked), Some(&action))
        .expect("the engine agrees with step 7");
    assert_eq!(
        engine
            .check(&proved(decoded), Some(&action))
            .unwrap_err()
            .invariant,
        Invariant::Status
    );
    Ok(())
}

#[test]
fn vectors_are_fresh_and_pass() {
    let rendered = serde_json::to_string_pretty(&build()).unwrap() + "\n";
    if std::env::var_os("VISADO_REGENERATE").is_some() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), &rendered).unwrap();
    }
    let on_disk = std::fs::read_to_string(path()).expect("run with VISADO_REGENERATE=1 once");
    assert_eq!(
        on_disk, rendered,
        "vectors are stale; rerun with VISADO_REGENERATE=1"
    );
    let suite: Value = serde_json::from_str(&on_disk).unwrap();
    let cases = suite["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        match (case["expect"].as_str().unwrap(), run(&suite, case)) {
            ("accept", Ok(())) => {}
            ("accept", Err(e)) => panic!("{name}: {e}"),
            (expect, Ok(())) => panic!("{name}: accepted, expected {expect}"),
            (expect, Err(e)) => {
                assert_eq!(e.outcome().as_str(), expect, "{name}: {e}");
                assert_eq!(e.reason(), case["reason"].as_str().unwrap(), "{name}");
                assert_eq!(
                    Some(e.token().unwrap()),
                    case["token"].as_u64().map(|t| usize::try_from(t).unwrap()),
                    "{name}"
                );
            }
        }
    }
    assert_eq!(cases.len(), 27);
}

/// The lists of §4.2 of the status list draft decode to the statuses of
/// §4.1.
#[test]
fn draft_examples() {
    for (bits, lst, statuses) in [
        (
            1,
            "eNrbuRgAAhcBXQ",
            &[1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1][..],
        ),
        (
            2,
            "eNo76fITAAPfAgc",
            &[1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3][..],
        ),
    ] {
        let token = signed(&json!({
            "sub": STATUS_LIST_URI, "iat": NOW, "status_list": { "bits": bits, "lst": lst },
        }));
        let list = StatusListVerifier::new(vec![TrustAnchor::new(
            STATUS_LIST_ISSUER,
            status_list_key().verifying_key(),
        )])
        .verify(&token, STATUS_LIST_URI, NOW)
        .unwrap();
        for (i, status) in statuses.iter().enumerate() {
            assert_eq!(list.status(i as u64), Some(*status), "bits {bits} idx {i}");
        }
        assert_eq!(list.status(statuses.len() as u64), None);
    }
}

#[test]
fn size_limits() {
    let verifier = StatusListVerifier::new(vec![TrustAnchor::new(
        STATUS_LIST_ISSUER,
        status_list_key().verifying_key(),
    )]);
    let token = list();
    assert_eq!(
        verifier
            .clone()
            .with_max_sizes(token.len() - 1, 1024)
            .verify(&token, STATUS_LIST_URI, NOW),
        Err(StatusListError::TooLarge)
    );
    assert_eq!(
        verifier
            .with_max_sizes(token.len(), 1)
            .verify(&token, STATUS_LIST_URI, NOW),
        Err(StatusListError::TooLarge),
        "the list decompresses to 2 bytes"
    );
}
