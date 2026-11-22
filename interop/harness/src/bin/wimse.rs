//! WIMSE credential interop harness.
//!
//! Reads and writes JSON so drivers in other languages can use it. See
//! `interop/wimse/README.md`.
//!
//! - `wimse mint [--now N]`: prints WITs with WPTs and WITs with HTTP message
//!   signatures in three key suites (`ed25519`, `es256`, `es256-eddsa`). The
//!   proofs come from `visado-testkit`, the WITs from `wimsey-wit` with the
//!   testkit's claim shape. Each case is valid or carries one mutation, and
//!   comes with the issuer JWKS, the private proof key and visado's verdict.
//! - `wimse verify`: reads `{now, issuers: [{trust_domain, iss?, jwks}],
//!   cases: [...]}` on standard input and prints visado's verdict per case. A
//!   case carries `wit`, `method`, `uri`, optional `headers` and `body`, and
//!   either `wpt` or `pop_private_jwk`; with the key, the harness signs a WPT
//!   for the case (`wpt_aud` and `wpt_wit` override its `aud` and `wth`).

use std::io::Read;
use std::process::ExitCode;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use visado_credentials::{AuthError, Authenticated, Authenticator, RequestView, WitIssuer};
use visado_testkit as testkit;
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, Jwk, PrivateJwk, SigningKey, VerifyingKey};
use wimsey_wit::{Confirmation, WitClaims};

/// The `iss` of every minted WIT.
const ISSUER: &str = "https://wit.td.example";
/// The `kid` of the trusted issuer key.
const KID: &str = "wit-1";
/// The calling workload.
const CALLER: &str = "spiffe://td.example/agent-a";
/// The target of the WPT cases. The query is not part of the audience.
const WPT_URI: &str = "https://tools.td.example/tickets?status=open";
/// The target of the signed-request cases.
const SIG_URI: &str = "https://tools.td.example/tickets?a=1";
/// An audience that is not the target.
const OTHER_AUDIENCE: &str = "https://other.td.example/tickets";
/// The body of the signed-request cases.
const BODY: &str = r#"{"title":"interop"}"#;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.first().map(String::as_str) {
        Some("mint") => parse_now(&args[1..]).map(mint),
        Some("verify") => stdin().and_then(|input| verify_input(&input)),
        _ => Err("usage: wimse <mint [--now N] | verify>".to_owned()),
    };
    match out {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).expect("json"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("wimse: {e}");
            ExitCode::from(2)
        }
    }
}

fn parse_now(args: &[String]) -> Result<u64, String> {
    match args {
        [] => Ok(testkit::NOW),
        [flag, n] if flag == "--now" => n.parse().map_err(|e| format!("--now: {e}")),
        _ => Err("usage: wimse mint [--now N]".to_owned()),
    }
}

fn stdin() -> Result<Value, String> {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// A JWK as a verifying key. A key without `alg` gets the one its type
/// allows, as visado's `jwks_file` loader does.
fn verifying_key(value: &Value) -> Result<VerifyingKey, String> {
    let mut jwk: Jwk = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if jwk.alg.is_none() {
        jwk.alg = Some(default_alg(&jwk.kty, &jwk.crv)?.to_owned());
    }
    jwk.to_verifying_key().map_err(|e| e.to_string())
}

/// A private JWK as a signing key, `alg` defaulted like [`verifying_key`].
fn signing_key(value: &Value) -> Result<SigningKey, String> {
    let mut jwk: PrivateJwk = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if jwk.alg.is_none() {
        jwk.alg = Some(default_alg(&jwk.kty, &jwk.crv)?.to_owned());
    }
    jwk.to_signing_key().map_err(|e| e.to_string())
}

fn default_alg(kty: &str, crv: &str) -> Result<&'static str, String> {
    match (kty, crv) {
        ("EC", "P-256") => Ok("ES256"),
        ("OKP", "Ed25519") => Ok("EdDSA"),
        _ => Err(format!("unsupported key type {kty}/{crv}")),
    }
}

/// The configured WIT issuers. A JWK without `kid` is registered under the
/// empty `kid`, which a WIT without `kid` selects when it is the only key.
fn wit_issuers(value: &Value) -> Result<Vec<WitIssuer>, String> {
    let mut out = Vec::new();
    for issuer in value.as_array().into_iter().flatten() {
        let trust_domain = issuer["trust_domain"]
            .as_str()
            .ok_or("issuer without trust_domain")?;
        let mut wit = WitIssuer::new(trust_domain);
        if let Some(iss) = issuer["iss"].as_str() {
            wit = wit.expect_issuer(iss);
        }
        for key in issuer["jwks"]["keys"].as_array().into_iter().flatten() {
            let kid = key["kid"].as_str().unwrap_or_default();
            let verifying = verifying_key(key).map_err(|e| format!("key {kid:?}: {e}"))?;
            wit = wit.with_key(kid, verifying);
        }
        out.push(wit);
    }
    Ok(out)
}

fn verify_input(input: &Value) -> Result<Value, String> {
    let now = input["now"].as_u64().unwrap_or(testkit::NOW);
    let issuers = wit_issuers(&input["issuers"])?;
    let mut cases = Vec::new();
    for case in input["cases"].as_array().into_iter().flatten() {
        let now = case["now"].as_u64().unwrap_or(now);
        let verdict = match case.get("issuers") {
            Some(own) => verify_case(&wit_issuers(own)?, case, now),
            None => verify_case(&issuers, case, now),
        };
        let mut out = json!({ "id": case["id"], "expect": case["expect"] });
        merge(&mut out, verdict);
        if let Some(expect) = case["expect"].as_str() {
            out["agrees"] = json!(out["verdict"] == expect);
        }
        cases.push(out);
    }
    Ok(json!({
        "verifier": "visado",
        "version": env!("CARGO_PKG_VERSION"),
        "now": now,
        "cases": cases,
    }))
}

fn merge(into: &mut Value, from: Value) {
    if let (Some(into), Value::Object(from)) = (into.as_object_mut(), from) {
        into.extend(from);
    }
}

/// The parts of `uri` a [`RequestView`] takes.
fn split_uri(uri: &str) -> Result<(&str, &str, &str), String> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| format!("not an absolute URI: {uri}"))?;
    let at = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(at);
    Ok((scheme, authority, if path.is_empty() { "/" } else { path }))
}

/// The WPT audience for `uri`: without query or fragment.
fn audience(uri: &str) -> &str {
    uri.split(['?', '#']).next().unwrap_or(uri)
}

/// visado's verdict on one case, with a fresh replay cache.
fn verify_case(issuers: &[WitIssuer], case: &Value, now: u64) -> Value {
    match authenticate(issuers, case, now) {
        Ok((Ok(auth), _)) => json!({
            "verdict": "accept",
            "caller": auth.caller,
            "method": format!("{:?}", auth.method),
        }),
        Ok((Err(e), rfc9421)) => {
            let mut out = json!({ "verdict": "reject", "code": e.code(), "error": e.to_string() });
            if let Some(rfc9421) = rfc9421 {
                out["rfc9421_only"] = rfc9421;
            }
            out
        }
        Err(e) => json!({ "verdict": "reject", "code": "harness", "error": e }),
    }
}

type Outcome = (Result<Authenticated, AuthError>, Option<Value>);

fn authenticate(issuers: &[WitIssuer], case: &Value, now: u64) -> Result<Outcome, String> {
    let method = case["method"].as_str().unwrap_or("GET");
    let uri = case["uri"].as_str().ok_or("case without uri")?;
    let (scheme, authority, path) = split_uri(uri)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    for pair in case["headers"].as_array().into_iter().flatten() {
        let (Some(name), Some(value)) = (pair[0].as_str(), pair[1].as_str()) else {
            return Err("headers are [name, value] pairs".into());
        };
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    let wit = case["wit"].as_str();
    if let Some(wit) = wit {
        headers.push((visado_credentials::WIT_HEADER.to_owned(), wit.to_owned()));
    }
    let wpt = match (case["wpt"].as_str(), case.get("pop_private_jwk")) {
        (Some(wpt), _) => Some(wpt.to_owned()),
        (None, Some(jwk)) => {
            let key = signing_key(jwk).map_err(|e| format!("pop_private_jwk: {e}"))?;
            let bound = case["wpt_wit"].as_str().or(wit).ok_or("no WIT to bind")?;
            let aud = case["wpt_aud"].as_str().unwrap_or_else(|| audience(uri));
            let jti = format!("jti-{}", case["id"].as_str().unwrap_or("case"));
            Some(testkit::wpt_at(bound, &key, aud, &jti, None, None, now))
        }
        (None, None) => None,
    };
    if let Some(wpt) = &wpt {
        headers.push(("authorization".to_owned(), format!("WPT {wpt}")));
    }
    let body = case["body"].as_str().map(str::as_bytes);
    let view = RequestView {
        method,
        scheme,
        authority,
        path,
        headers: &headers,
        body,
        peer_certificate: None,
    };
    let authenticator = issuers
        .iter()
        .cloned()
        .fold(Authenticator::new(), Authenticator::with_wit_issuer);
    let result = authenticator.authenticate(&view, now);
    let rfc9421 = match (&result, wit) {
        (Err(_), Some(wit)) if wpt.is_none() => {
            Some(rfc9421_only(method, authority, path, &headers, wit, now))
        }
        _ => None,
    };
    Ok((result, rfc9421))
}

/// A diagnostic for a rejected signed request: the RFC 9421 signature alone,
/// checked with the WIT's `cnf` key (the WIT itself unverified) and none of
/// the WIMSE profile, audience or body checks.
fn rfc9421_only(
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    wit: &str,
    now: u64,
) -> Value {
    let field = |name: &str| {
        let values: Vec<&str> = headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect();
        values.join(", ")
    };
    let result = cnf_key(wit).and_then(|key| {
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let message = testkit::signature_request(method, authority, path, &pairs);
        let config = wimsey_httpsig::VerifyConfig {
            now: Some(now),
            leeway: 30,
            ..wimsey_httpsig::VerifyConfig::default()
        };
        wimsey_httpsig::verify(
            &message,
            &field("signature-input"),
            &field("signature"),
            &key,
            &config,
        )
        .map_err(|e| e.to_string())
    });
    match result {
        Ok(_) => json!({ "verdict": "accept" }),
        Err(e) => json!({ "verdict": "reject", "error": e }),
    }
}

/// The `cnf.jwk` of `wit`, read without verifying the WIT.
fn cnf_key(wit: &str) -> Result<VerifyingKey, String> {
    let claims = wit.split('.').nth(1).ok_or("WIT is not a JWS")?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(claims)
            .map_err(|e| format!("WIT claims: {e}"))?,
    )
    .map_err(|e| format!("WIT claims: {e}"))?;
    verifying_key(&claims["cnf"]["jwk"])
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

/// The keys of one suite.
struct Suite {
    name: &'static str,
    issuer: SigningKey,
    /// Signs WITs under the trusted `kid` without being trusted.
    rogue: SigningKey,
    pop: SigningKey,
}

fn p256(byte: u8) -> SigningKey {
    SigningKey::from_p256_scalar(&[byte; 32]).expect("p256 scalar")
}

fn suites() -> Vec<Suite> {
    vec![
        Suite {
            name: "ed25519",
            issuer: testkit::wit_issuer_key(),
            rogue: SigningKey::from_ed25519_seed(&[0x32; 32]),
            pop: testkit::pop_key(0x51),
        },
        Suite {
            name: "es256",
            issuer: p256(0x33),
            rogue: p256(0x34),
            pop: p256(0x52),
        },
        // ES256 issuer and an Ed25519 proof key under the RFC 8037 name, as in
        // the draft-ietf-wimse-wpt-02 examples.
        Suite {
            name: "es256-eddsa",
            issuer: p256(0x33),
            rogue: p256(0x34),
            pop: testkit::pop_key(0x53)
                .with_algorithm(Algorithm::EdDsa)
                .expect("EdDSA relabel"),
        },
    ]
}

/// A WIT with the testkit's claim shape.
fn wit(issuer: &SigningKey, kid: Option<&str>, pop: &SigningKey, iat: u64, jti: &str) -> String {
    let claims = WitClaims {
        iss: Some(ISSUER.into()),
        sub: WorkloadIdentifier::parse(CALLER).expect("valid identifier"),
        iat: Some(iat),
        exp: iat + 600,
        jti: Some(jti.into()),
        cnf: Confirmation {
            jwk: Jwk::from_verifying_key(&pop.verifying_key()),
        },
    };
    wimsey_wit::issue(&claims, kid, issuer).expect("wit issues")
}

/// `token` with the first character after the first `separator` (searched
/// from the end for a JWS, from the start for a `Signature` field) changed, so
/// the signature bytes differ; the last character may carry only padding bits.
fn tamper(token: &str, separator: char) -> String {
    let at = if separator == '.' {
        token.rfind('.')
    } else {
        token.find(separator)
    }
    .expect("separator")
        + 1;
    let mut bytes = token.as_bytes().to_vec();
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).expect("ascii")
}

fn jwks(key: &SigningKey) -> Value {
    let mut jwk = serde_json::to_value(Jwk::from_verifying_key(&key.verifying_key())).expect("jwk");
    jwk["kid"] = json!(KID);
    json!({ "keys": [jwk] })
}

fn mint(now: u64) -> Value {
    let suites: Vec<Value> = suites()
        .iter()
        .map(|suite| mint_suite(suite, now))
        .collect();
    json!({
        "implementation": "visado",
        "version": env!("CARGO_PKG_VERSION"),
        "now": now,
        "suites": suites,
    })
}

fn mint_suite(suite: &Suite, now: u64) -> Value {
    let issuers = json!([{ "trust_domain": testkit::TRUST_DOMAIN, "iss": ISSUER, "jwks": jwks(&suite.issuer) }]);
    let trusted = wit_issuers(&issuers).expect("own issuer");
    let mut cases = wpt_cases(suite, now);
    cases.extend(signature_cases(suite, now));
    for case in &mut cases {
        let verdict = verify_case(&trusted, case, now);
        case["visado"] = verdict;
    }
    json!({
        "suite": suite.name,
        "issuers": issuers,
        "pop_private_jwk": PrivateJwk::from_signing_key(&suite.pop),
        "cases": cases,
    })
}

/// One minted case. `wit_expect` is whether the WIT alone is valid, and on a
/// signed request `sig_expect` whether the RFC 9421 signature and the body
/// digest alone are.
fn case(suite: &Suite, kind: &str, mutation: &str, expect: &str, wit_ok: bool) -> Value {
    let verdict = |ok: bool| if ok { "accept" } else { "reject" };
    let mut c = json!({
        "id": format!("{}/{kind}/{mutation}", suite.name),
        "kind": kind,
        "mutation": mutation,
        "expect": expect,
        "wit_expect": verdict(wit_ok),
    });
    if kind == "httpsig" {
        let sig_ok = !matches!(
            mutation,
            "signature_tampered" | "body_changed" | "covered_header_changed" | "query_changed"
        );
        c["sig_expect"] = json!(verdict(sig_ok));
    }
    c
}

fn wpt_cases(suite: &Suite, now: u64) -> Vec<Value> {
    let pop = &suite.pop;
    let aud = audience(WPT_URI);
    let valid = wit(&suite.issuer, Some(KID), pop, now - 5, "wit-valid");
    let proof = |wit: &str, aud: &str, at: u64| {
        let jti = format!("jti-{}-{at}-{}", suite.name, &wit[wit.len() - 8..]);
        testkit::wpt_at(wit, pop, aud, &jti, None, None, at)
    };
    let expired = wit(&suite.issuer, Some(KID), pop, now - 1205, "wit-expired");
    let rogue = wit(&suite.rogue, Some(KID), pop, now - 5, "wit-rogue");
    let tampered = tamper(&valid, '.');
    let other = wit(&suite.issuer, Some(KID), pop, now - 5, "wit-other");
    let no_kid = wit(&suite.issuer, None, pop, now - 5, "wit-no-kid");
    let rows: Vec<(&str, &str, bool, String, String)> = vec![
        (
            "valid",
            "accept",
            true,
            valid.clone(),
            proof(&valid, aud, now),
        ),
        (
            "expired_wit",
            "reject",
            false,
            expired.clone(),
            proof(&expired, aud, now),
        ),
        (
            "untrusted_issuer",
            "reject",
            false,
            rogue.clone(),
            proof(&rogue, aud, now),
        ),
        (
            "wit_signature_tampered",
            "reject",
            false,
            tampered.clone(),
            proof(&tampered, aud, now),
        ),
        (
            "wth_mismatch",
            "reject",
            true,
            valid.clone(),
            proof(&other, aud, now),
        ),
        (
            "other_audience",
            "reject",
            true,
            valid.clone(),
            proof(&valid, OTHER_AUDIENCE, now),
        ),
        (
            "wpt_signature_tampered",
            "reject",
            true,
            valid.clone(),
            tamper(&proof(&valid, aud, now), '.'),
        ),
        (
            "expired_wpt",
            "reject",
            true,
            valid.clone(),
            proof(&valid, aud, now - 200),
        ),
        (
            "wit_no_kid",
            "accept",
            true,
            no_kid.clone(),
            proof(&no_kid, aud, now),
        ),
    ];
    rows.into_iter()
        .map(|(mutation, expect, wit_ok, wit, wpt)| {
            let mut c = case(suite, "wpt", mutation, expect, wit_ok);
            merge(
                &mut c,
                json!({ "method": "GET", "uri": WPT_URI, "wit": wit, "wpt": wpt }),
            );
            c
        })
        .collect()
}

fn signature_cases(suite: &Suite, now: u64) -> Vec<Value> {
    let valid = wit(&suite.issuer, Some(KID), &suite.pop, now - 5, "wit-valid");
    let expired = wit(
        &suite.issuer,
        Some(KID),
        &suite.pop,
        now - 1205,
        "wit-expired",
    );
    let rogue = wit(&suite.rogue, Some(KID), &suite.pop, now - 5, "wit-rogue");
    let rows: Vec<(&str, &str, bool, &String)> = vec![
        ("valid", "accept", true, &valid),
        ("expired_wit", "reject", false, &expired),
        ("untrusted_issuer", "reject", false, &rogue),
        ("other_audience", "reject", true, &valid),
        ("signature_tampered", "reject", true, &valid),
        ("body_changed", "reject", true, &valid),
        ("covered_header_changed", "reject", true, &valid),
        ("query_changed", "reject", true, &valid),
    ];
    rows.into_iter()
        .map(|(mutation, expect, wit_ok, wit)| {
            let mut c = case(suite, "httpsig", mutation, expect, wit_ok);
            merge(&mut c, signed_request(suite, mutation, wit, now));
            c
        })
        .collect()
}

/// A signed POST, then changed after signing as `mutation` says.
fn signed_request(suite: &Suite, mutation: &str, wit: &str, now: u64) -> Value {
    let digest = testkit::content_digest(BODY.as_bytes());
    let length = BODY.len().to_string();
    let mut headers: Vec<(&str, String)> = vec![
        ("content-type", "application/json".to_owned()),
        ("content-digest", digest),
        ("content-length", length),
    ];
    let (_, authority, path) = split_uri(SIG_URI).expect("uri");
    let mut signed: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    signed.push((visado_credentials::WIT_HEADER, wit));
    let nonce = format!("nonce-{}-{mutation}-5f3c9a1e", suite.name);
    let spec = testkit::SignatureSpec {
        nonce: &nonce,
        created: now,
        audience: if mutation == "other_audience" {
            OTHER_AUDIENCE
        } else {
            audience(SIG_URI)
        },
        cover: &[],
    };
    let (input, signature) =
        testkit::http_signature("POST", authority, path, &signed, &suite.pop, &spec);
    let signature = if mutation == "signature_tampered" {
        tamper(&signature, ':')
    } else {
        signature
    };
    let mut body = BODY.to_owned();
    let mut uri = SIG_URI.to_owned();
    match mutation {
        "body_changed" => r#"{"title":"swapped"}"#.clone_into(&mut body),
        "covered_header_changed" => "text/plain".clone_into(&mut headers[0].1),
        "query_changed" => uri = SIG_URI.replace("a=1", "a=2"),
        _ => {}
    }
    headers.push(("signature-input", input));
    headers.push(("signature", signature));
    let headers: Vec<Value> = headers.iter().map(|(n, v)| json!([n, v])).collect();
    json!({ "method": "POST", "uri": uri, "headers": headers, "body": body, "wit": wit })
}
