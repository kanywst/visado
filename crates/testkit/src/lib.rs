//! Fixed-key fixtures for visado tests. Not for production use.

#![allow(clippy::missing_panics_doc, clippy::too_many_arguments)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, Jwk, PrivateJwk, SigningKey, VerifyingKey};
use wimsey_wit::{Confirmation, WitClaims};
use wimsey_wpt::WptClaims;

/// A fixed time used across tests.
pub const NOW: u64 = 1_800_000_000;

/// The trust domain used across tests.
pub const TRUST_DOMAIN: &str = "td.example";

/// The OAuth issuer used across tests.
pub const OAUTH_ISSUER: &str = "https://idp.example";

/// The WIT issuer's signing key.
#[must_use]
pub fn wit_issuer_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x31; 32])
}

/// A workload's proof-of-possession key, derived from `seed`.
#[must_use]
pub fn pop_key(seed: u8) -> SigningKey {
    SigningKey::from_ed25519_seed(&[seed; 32])
}

/// The OAuth issuer's signing key (`EdDSA`).
///
/// # Panics
///
/// Never: the relabel from `Ed25519` to `EdDSA` is always valid.
#[must_use]
pub fn oauth_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x41; 32])
        .with_algorithm(Algorithm::EdDsa)
        .expect("EdDSA relabel")
}

/// The OAuth issuer's JWKS as JSON, with `kid` "idp-1".
#[must_use]
pub fn oauth_jwks() -> Value {
    let mut jwk = serde_json::to_value(Jwk::from_verifying_key(&oauth_key().verifying_key()))
        .expect("jwk serializes");
    jwk["kid"] = json!("idp-1");
    jwk["use"] = json!("sig");
    json!({ "keys": [jwk] })
}

/// The WIT issuer's verifying key.
#[must_use]
pub fn wit_issuer_verifying_key() -> VerifyingKey {
    wit_issuer_key().verifying_key()
}

/// A WIT for `workload` (a path in [`TRUST_DOMAIN`]) bound to `pop`, valid for
/// 10 minutes from [`NOW`], with `kid` "wit-1".
///
/// # Panics
///
/// If `workload` does not make a valid identifier.
#[must_use]
pub fn wit(workload: &str, pop: &SigningKey) -> String {
    wit_for(&format!("spiffe://{TRUST_DOMAIN}/{workload}"), pop)
}

/// A WIT for the full workload identifier `id`, signed by the test issuer.
///
/// # Panics
///
/// If `id` is not a valid identifier.
#[must_use]
pub fn wit_for(id: &str, pop: &SigningKey) -> String {
    wit_at(id, pop, NOW)
}

/// A WIT for `id` bound to `pop`, issued at `now` and valid for 10 minutes.
#[must_use]
pub fn wit_at(id: &str, pop: &SigningKey, now: u64) -> String {
    let claims = WitClaims {
        iss: Some("https://wit.td.example".into()),
        sub: WorkloadIdentifier::parse(id).expect("valid identifier"),
        iat: Some(now - 5),
        exp: now + 600,
        jti: None,
        cnf: Confirmation {
            jwk: Jwk::from_verifying_key(&pop.verifying_key()),
        },
    };
    wimsey_wit::issue(&claims, Some("wit-1"), &wimsey_issuer_key()).expect("wit issues")
}

fn wimsey_issuer_key() -> SigningKey {
    wit_issuer_key()
}

/// A WPT over `wit` for `audience`, with `jti`, optionally binding a Txn-Token
/// and a user token carried in `user_header`.
///
/// # Panics
///
/// Never for valid inputs.
#[must_use]
pub fn wpt(
    wit: &str,
    pop: &SigningKey,
    audience: &str,
    jti: &str,
    txn_token: Option<&str>,
    user: Option<(&str, &str)>,
) -> String {
    wpt_at(wit, pop, audience, jti, txn_token, user, NOW)
}

/// Like [`wpt`], expiring 60 seconds after `now`.
#[must_use]
pub fn wpt_at(
    wit: &str,
    pop: &SigningKey,
    audience: &str,
    jti: &str,
    txn_token: Option<&str>,
    user: Option<(&str, &str)>,
    now: u64,
) -> String {
    let claims = WptClaims {
        aud: audience.into(),
        exp: now + 60,
        jti: jti.into(),
        wth: wimsey_wpt::wit_thumbprint(wit),
        tth: txn_token.map(wimsey_wpt::txn_token_thumbprint),
        oth: user.map(|(header, value)| {
            std::iter::once(wimsey_wpt::other_token_entry(header, value)).collect()
        }),
    };
    wimsey_wpt::issue(&claims, pop).expect("wpt issues")
}

/// An access token from [`OAUTH_ISSUER`] for `sub`, with `client_id`, `scope`
/// and `aud`, expiring at `exp`.
#[must_use]
pub fn access_token(sub: &str, client_id: &str, scope: &str, aud: &str, exp: u64) -> String {
    signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": sub, "aud": aud, "client_id": client_id,
        "scope": scope, "iat": NOW - 5, "exp": exp, "jti": format!("at-{sub}-{exp}"),
    }))
}

/// An access token with exactly `claims`, signed by the test OAuth issuer.
#[must_use]
pub fn signed_access_token(claims: &Value) -> String {
    let header = json!({ "typ": "at+jwt", "alg": "EdDSA", "kid": "idp-1" });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json"));
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json"));
    let input = format!("{h}.{c}");
    let sig = URL_SAFE_NO_PAD.encode(oauth_key().sign(input.as_bytes()));
    format!("{input}.{sig}")
}

/// The AAT trust anchor's signing key.
#[must_use]
pub fn aat_anchor_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x61; 32])
}

/// The AAT trust anchor's issuer.
pub const AAT_ISSUER: &str = "https://aat.td.example";

fn sign_aat(typ: &str, payload: &Value, key: &SigningKey) -> String {
    // serde_json maps keep keys sorted and print without whitespace, which is
    // the JCS form for the strings and integers used here.
    let header = json!({ "alg": key.algorithm().as_str(), "typ": typ });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json"));
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("json"));
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    format!("{input}.{sig}")
}

fn signing_input_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let input = token.rsplit_once('.').map_or(token, |(i, _)| i);
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

fn aat_detail(tools: &Value) -> Value {
    json!([{ "type": "attenuating_agent_token", "tools": tools }])
}

/// A root AAT from [`AAT_ISSUER`] delegating `tools` to `holder`, for the
/// enforcement point `audience`.
#[must_use]
pub fn aat_root(
    jti: &str,
    holder: &SigningKey,
    tools: &Value,
    now: u64,
    max_depth: u32,
    audience: &str,
) -> String {
    let payload = json!({
        "jti": jti, "iss": AAT_ISSUER, "aud": audience, "iat": now, "exp": now + 600,
        "del_depth": 0, "del_max_depth": max_depth,
        "cnf": { "jwk": Jwk::from_verifying_key(&holder.verifying_key()) },
        "authorization_details": aat_detail(tools),
    });
    let mut payload = payload;
    if let Some(jwk) = payload["cnf"]["jwk"].as_object_mut() {
        jwk.remove("alg");
    }
    sign_aat("aat+jwt", &payload, &aat_anchor_key())
}

/// A child AAT of `parent` (held by `parent_holder`) delegating `tools` to
/// `holder`, at depth `depth`.
#[must_use]
pub fn aat_child(
    jti: &str,
    parent: &str,
    parent_holder: &SigningKey,
    holder: &SigningKey,
    tools: &Value,
    depth: u32,
    max_depth: u32,
    now: u64,
) -> String {
    let iss = format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        visado_chain_aat::jwk_thumbprint(&parent_holder.verifying_key())
    );
    let mut payload = json!({
        "jti": jti, "iss": iss, "iat": now, "exp": now + 300,
        "del_depth": depth, "del_max_depth": max_depth,
        "par_hash": signing_input_hash(parent),
        "cnf": { "jwk": Jwk::from_verifying_key(&holder.verifying_key()) },
        "authorization_details": aat_detail(tools),
    });
    if let Some(jwk) = payload["cnf"]["jwk"].as_object_mut() {
        jwk.remove("alg");
    }
    sign_aat("aat+jwt", &payload, parent_holder)
}

/// A proof of possession by `holder` of the leaf token `leaf` (whose `jti` is
/// `leaf_jti`), for calling `tool` with `args` at `audience`.
#[must_use]
pub fn aat_pop(
    jti: &str,
    leaf: &str,
    leaf_jti: &str,
    holder: &SigningKey,
    tool: &str,
    args: &Value,
    audience: &str,
    now: u64,
) -> String {
    let payload = json!({
        "jti": jti, "iat": now, "aat_id": leaf_jti, "aat_hash": signing_input_hash(leaf),
        "aat_tool": tool, "hta": args, "aat_aud": audience,
    });
    sign_aat("aat-pop+jwt", &payload, holder)
}

/// The `nonce`, `created` and audience of a test HTTP message signature.
#[derive(Debug, Clone)]
pub struct SignatureSpec<'a> {
    /// `nonce`.
    pub nonce: &'a str,
    /// `created`; `expires` is 60 seconds later.
    pub created: u64,
    /// `wimse-aud`.
    pub audience: &'a str,
    /// Header fields to cover besides the ones the profile requires, such as
    /// the user token header.
    pub cover: &'a [&'a str],
}

/// A WIMSE HTTP message signature by `pop` over a request with `method`,
/// `authority`, `path_and_query` and `headers`, covering what
/// draft-ietf-wimse-http-signature requires. Returns the `Signature-Input` and
/// `Signature` header values.
#[must_use]
pub fn http_signature(
    method: &str,
    authority: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
    pop: &SigningKey,
    spec: &SignatureSpec<'_>,
) -> (String, String) {
    let request = signature_request(method, authority, path_and_query, headers);
    let mut components = wimsey_httpsig::request_components(&request);
    components.extend(
        spec.cover
            .iter()
            .map(|h| wimsey_httpsig::Component::header(h)),
    );
    let params = wimsey_httpsig::SignatureParams {
        created: Some(spec.created),
        expires: Some(spec.created + 60),
        nonce: Some(spec.nonce.to_owned()),
        tag: Some(wimsey_httpsig::WIMSE_TAG.to_owned()),
        wimse_aud: Some(spec.audience.to_owned()),
        ..wimsey_httpsig::SignatureParams::default()
    };
    let signed = wimsey_httpsig::sign(&request, &components, &params, "wimse", pop)
        .expect("signature signs");
    (signed.signature_input, signed.signature)
}

/// The RFC 9421 view of a request, as a verifier builds it.
#[must_use]
pub fn signature_request(
    method: &str,
    authority: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
) -> wimsey_httpsig::HttpRequest {
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query.to_owned())),
        None => (path_and_query, None),
    };
    wimsey_httpsig::HttpRequest {
        method: method.to_owned(),
        authority: authority.to_owned(),
        path: path.to_owned(),
        query,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// The `Content-Digest` value for `body`.
#[must_use]
pub fn content_digest(body: &[u8]) -> String {
    wimsey_httpsig::content_digest_sha256(body)
}

/// The workload CA's signing key.
#[must_use]
pub fn workload_ca_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x81; 32])
}

/// The workload CA for [`TRUST_DOMAIN`], valid from a day before [`NOW`] for a
/// year.
#[must_use]
pub fn workload_ca() -> wimsey_mtls::WorkloadCa {
    wimsey_mtls::WorkloadCa::from_ed25519(&workload_ca_key(), NOW - 86_400, NOW + 31_536_000)
        .expect("CA builds")
}

/// A workload certificate (X.509-SVID) for the identifier `id` and `key`,
/// issued by [`workload_ca`] and valid from a minute before [`NOW`] for an
/// hour.
#[must_use]
pub fn wic(id: &str, key: &VerifyingKey) -> Vec<u8> {
    wic_at(id, key, NOW - 60, NOW + 3600)
}

/// Like [`wic`], valid between `not_before` and `not_after`.
#[must_use]
pub fn wic_at(id: &str, key: &VerifyingKey, not_before: u64, not_after: u64) -> Vec<u8> {
    let id = WorkloadIdentifier::parse(id).expect("valid identifier");
    workload_ca()
        .issue(&id, key, not_before, not_after)
        .expect("certificate issues")
}

/// `der` as one PEM `CERTIFICATE` block.
#[must_use]
pub fn certificate_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// `der` as Envoy reports a peer certificate in `source.certificate`:
/// URL-encoded PEM.
#[must_use]
pub fn envoy_peer_certificate(der: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in certificate_pem(der).bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The JWT-SVID signing key (`ES256`).
///
/// # Panics
///
/// Never: the scalar is a valid P-256 key.
#[must_use]
pub fn jwt_svid_key() -> SigningKey {
    SigningKey::from_p256_scalar(&[0x71; 32]).expect("P-256 key")
}

/// A fixed RSA-2048 key for `RS256` JWT-SVIDs, PKCS#1 DER in base64. A test
/// key: anyone can sign with it.
const RSA_TEST_KEY: &str = concat!(
    "MIIEpAIBAAKCAQEAtAzkLeJlV04Q3l/uwFp8vXN02Ktb+cK3PA9WtAjsXi3RN1YiYidnDgy35BD76M92iMKFCZpOey",
    "RZxK9KuAf175q692wIdHnXdyUVLeq9G/wghBzqSc5JjjiNZVoyi7Jzl9fhRmn4mbcFA4SfIdyEjvizFOimIpt321DH",
    "rrg+TfZcbEEgcLwdJ353h697ozdm/lKg1uJvGe+qIFth9s77SGc0AAQAFSNfYHM3yu+EsEvTD8dzOi7YOClglgYimC",
    "12qObTNj6KFt9PiCdtgPSiblONkWaLWYmb6lDquLQjCwjaDTy3DKxng5g2lUqjotRfIa4683MI5RAwVlp7t55PgQID",
    "AQABAoIBACxNxML2o62nL7bsX60Uxv9+Hrkm90+epmRguNq9nF3zQ7ksWHMTE4RtRD2aIUZw8E+oH8DUZ63c7LrdUF",
    "M24EEob4us2WrBxW9ToGHHUmfFs0GW9N6a5FYa284d8vSVgWSSciQXtNysII90TYzxPGwKzdQeCC1ZWJWOi8gWHXyk",
    "sbv+bt/IhrGzPIIXfFATWTObQkOFGeTk6/gZ6yunFt6boItM5CpYmk4kae8tLlhG4qeYOujJArTP1rOV14/raH8O1p",
    "u19FOyyEC1IzhVy2BdFlfTsTO9tLR4158JYCXOMMcstxVzFNPqiD7tgzpHvhozRWPfb6M4ItqEjSZjZ60CgYEA5sMx",
    "1Laax1JG6DmQRxR/hjNoMNgM/nYpStuve/eHUC7/cmUL96m7tRE6lPPlkBzMrL6Xzjm4JWtXL1ow+mShgI06y1kZtX",
    "MfKAaerpXx4/+C/+3X+FhihL4Gs3dIyqaUzP8tDPMgcv/gw4oHdN9INaG7tAHv2BctuSM56jF4keUCgYEAx73gdqUc",
    "E78pAd0tXPUt4OmUFb492HXqavvCtcfPOvcDQkJkkKcdDz26TsQVJpQKa3rOuqyvnhEHtrrFNF18/ik9VWIlORGaII",
    "2SqyuWw7d2RjpNifgHuAt204tVB8kZByPHJwkL13KqVpfXTrD1at5wlkSnuuuApvrwqeyoXW0CgYB1GQfoUOEp0+53",
    "WP6FkzlC+EMexgOR/JPnkKLz3R+k6LRncC8qdc7yitOXUkxjXLnfzrdpxpBTLK0JMlM4PGhXu1LibUxGbyyYOwO6xA",
    "wDDl2DUUYOl4smoOb1msotS2qmu7Y4pAcLVBzSHPC7tbIGxRNivLjghqKFGAMDfCcaoQKBgQClU4eIDK/JtG8XyN90",
    "UsfPouZcfOOp2CfYt1v5pFHlp3D+FgAxLvFBnUEpUumCzgQ15CdaofaWadgtqjfyWPNNWAsZMixHKUeebDAbF/ApPS",
    "BbjoSBj1esQWjwPiJ6WDwsCbQcnkM76AAPvoyK6LOp6kXcSyVd9PG+xHQQ4f6VnQKBgQC6KSRpqobirue9jgJtaP7V",
    "L/FUE66iarb3OkQSRXeHEAOtX/UGzCmYl59fyYW2WTIOCF2aKz+DL1jw8dwI30hCEVbuG5oca/uQb0cL+jinLnOT9E",
    "Nal8PCsPcAbLCNoyS5zI2C/wZsQbZbkqLnMi+GqLeeXLaZ+++ae9dkOxKoNQ==",
);

/// The modulus of [`RSA_TEST_KEY`], base64url.
const RSA_TEST_N: &str = "tAzkLeJlV04Q3l_uwFp8vXN02Ktb-cK3PA9WtAjsXi3RN1YiYidnDgy35BD76M92iMKFCZpOeyRZxK9KuAf175q692wIdHnXdyUVLeq9G_wghBzqSc5JjjiNZVoyi7Jzl9fhRmn4mbcFA4SfIdyEjvizFOimIpt321DHrrg-TfZcbEEgcLwdJ353h697ozdm_lKg1uJvGe-qIFth9s77SGc0AAQAFSNfYHM3yu-EsEvTD8dzOi7YOClglgYimC12qObTNj6KFt9PiCdtgPSiblONkWaLWYmb6lDquLQjCwjaDTy3DKxng5g2lUqjotRfIa4683MI5RAwVlp7t55PgQ";

/// A SPIFFE trust bundle for [`TRUST_DOMAIN`] with two JWT-SVID keys,
/// "svid-es" (`ES256`, [`jwt_svid_key`]) and "svid-rs" (`RS256`), and one
/// X.509 entry that a JWT verifier must skip.
#[must_use]
pub fn jwt_bundle() -> Value {
    let mut es = serde_json::to_value(Jwk::from_verifying_key(&jwt_svid_key().verifying_key()))
        .expect("jwk serializes");
    es["kid"] = json!("svid-es");
    es["use"] = json!("jwt-svid");
    json!({
        "keys": [
            es,
            { "kty": "RSA", "kid": "svid-rs", "use": "jwt-svid", "alg": "RS256",
               "n": RSA_TEST_N, "e": "AQAB" },
            { "kty": "EC", "use": "x509-svid", "crv": "P-256",
               "x": es["x"], "y": es["y"], "x5c": [] },
        ],
        "spiffe_sequence": 1,
    })
}

/// A JWT-SVID for `sub` with `aud`, expiring at `exp`, signed `ES256` with
/// "svid-es".
#[must_use]
pub fn jwt_svid(sub: &str, aud: &str, exp: u64) -> String {
    signed_jwt_svid(
        &json!({ "alg": "ES256", "typ": "JWT", "kid": "svid-es" }),
        &json!({ "sub": sub, "aud": [aud], "exp": exp, "iat": NOW - 5 }),
    )
}

/// A JWT with exactly `header` and `claims`, signed with [`jwt_svid_key`] when
/// `alg` is `ES256` and with the RSA test key when it is `RS256`.
///
/// # Panics
///
/// For any other `alg`.
#[must_use]
pub fn signed_jwt_svid(header: &Value, claims: &Value) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("json"));
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json"));
    let input = format!("{h}.{c}");
    let signature = match header["alg"].as_str() {
        Some("ES256") => jwt_svid_key().sign(input.as_bytes()).to_vec(),
        Some("RS256") => {
            use base64::engine::general_purpose::STANDARD;
            let der = STANDARD.decode(RSA_TEST_KEY).expect("key decodes");
            let key = jsonwebtoken::EncodingKey::from_rsa_der(&der);
            let signed =
                jsonwebtoken::crypto::sign(input.as_bytes(), &key, jsonwebtoken::Algorithm::RS256)
                    .expect("RS256 signs");
            URL_SAFE_NO_PAD.decode(signed).expect("base64url")
        }
        other => panic!("unsupported alg {other:?}"),
    };
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// The asor trust anchor's signing key.
#[must_use]
pub fn asor_anchor_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x71; 32])
}

/// The asor trust anchor's issuer.
pub const ASOR_ISSUER: &str = "https://asor.td.example";

/// The Principal of the asor test chains.
pub const ASOR_PRINCIPAL: &str = "user:alice";

/// Signs `header` and `payload`, both given as the exact JSON text to encode,
/// with the asor anchor key.
#[must_use]
pub fn asor_sign_raw(header: &str, payload: &str) -> String {
    let h = URL_SAFE_NO_PAD.encode(header);
    let p = URL_SAFE_NO_PAD.encode(payload);
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(asor_anchor_key().sign(input.as_bytes()));
    format!("{input}.{sig}")
}

/// A Delegation Token with exactly `payload`, signed by the asor anchor.
/// `serde_json` maps keep keys sorted and print without whitespace, which is
/// the JCS form for the strings and integers used here.
#[must_use]
pub fn asor_sign(payload: &Value) -> String {
    asor_sign_raw(
        r#"{"alg":"Ed25519","typ":"at+jwt"}"#,
        &serde_json::to_string(payload).expect("json"),
    )
}

/// The claims of a root Delegation Token from [`ASOR_ISSUER`] for
/// [`ASOR_PRINCIPAL`], acted on by `client_id` holding `holder`, granting
/// `scopes` under `constraints`, for `audience`, valid 10 minutes from `now`.
#[must_use]
pub fn asor_root_claims(
    jti: &str,
    client_id: &str,
    holder: &SigningKey,
    scopes: &Value,
    constraints: &Value,
    audience: &str,
    now: u64,
    max_depth: u32,
) -> Value {
    json!({
        "iss": ASOR_ISSUER, "sub": ASOR_PRINCIPAL, "client_id": client_id, "aud": audience,
        "iat": now, "exp": now + 600, "jti": jti, "del_depth": 0, "del_max_depth": max_depth,
        "cnf": { "jkt": visado_chain_aat::jwk_thumbprint(&holder.verifying_key()) },
        "authorization_details": [
            { "type": "agent_delegation", "scopes": scopes, "constraints": constraints }
        ],
    })
}

/// The claims of a child of `parent` at `depth`, like [`asor_root_claims`]
/// but valid 5 minutes and committing to `parent` with `par_hash`.
#[must_use]
pub fn asor_child_claims(
    jti: &str,
    client_id: &str,
    parent: &str,
    holder: &SigningKey,
    depth: u32,
    scopes: &Value,
    constraints: &Value,
    audience: &str,
    now: u64,
) -> Value {
    json!({
        "iss": ASOR_ISSUER, "sub": ASOR_PRINCIPAL, "client_id": client_id, "aud": audience,
        "iat": now, "exp": now + 300, "jti": jti, "del_depth": depth,
        "par_hash": signing_input_hash(parent),
        "cnf": { "jkt": visado_chain_aat::jwk_thumbprint(&holder.verifying_key()) },
        "authorization_details": [
            { "type": "agent_delegation", "scopes": scopes, "constraints": constraints }
        ],
    })
}

/// A DPoP proof (RFC 9449) by `holder` for `method` on `uri`, presenting the
/// access token `token`.
#[must_use]
pub fn dpop_proof(
    holder: &SigningKey,
    method: &str,
    uri: &str,
    token: &str,
    jti: &str,
    now: u64,
) -> String {
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(holder) });
    sign_dpop_proof(&header, &dpop_claims(method, uri, token, jti, now), holder)
}

/// The public JWK of `holder` as a DPoP proof header carries it: no `alg`.
#[must_use]
pub fn dpop_jwk(holder: &SigningKey) -> Value {
    let mut jwk = serde_json::to_value(Jwk::from_verifying_key(&holder.verifying_key()))
        .expect("jwk serializes");
    if let Some(jwk) = jwk.as_object_mut() {
        jwk.remove("alg");
    }
    jwk
}

/// DPoP proof claims for `method` on `uri` at `now`, with `ath` over `token`.
#[must_use]
pub fn dpop_claims(method: &str, uri: &str, token: &str, jti: &str, now: u64) -> Value {
    use sha2::{Digest, Sha256};
    json!({
        "jti": jti, "htm": method, "htu": uri, "iat": now,
        "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
    })
}

/// A DPoP proof with exactly `header` and `claims`, signed by `key`, for
/// tests that need a malformed proof.
#[must_use]
pub fn sign_dpop_proof(header: &Value, claims: &Value, key: &SigningKey) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("json"));
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json"));
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    format!("{input}.{sig}")
}

/// An access token like [`access_token`], DPoP-bound to `holder` with
/// `cnf.jkt` (RFC 9449 §6.1).
#[must_use]
pub fn dpop_access_token(
    sub: &str,
    client_id: &str,
    scope: &str,
    aud: &str,
    exp: u64,
    holder: &SigningKey,
) -> String {
    let jkt = visado_chain_aat::jwk_thumbprint(&holder.verifying_key());
    signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": sub, "aud": aud, "client_id": client_id,
        "scope": scope, "iat": NOW - 5, "exp": exp, "jti": format!("at-{sub}-{exp}"),
        "cnf": { "jkt": jkt },
    }))
}

/// A WIT-SVID and its private key, as SPIRE's Workload API hands them out.
#[derive(Debug)]
pub struct SpireWitSvid {
    /// The WIT-SVID.
    pub wit: String,
    /// The SPIFFE ID in the WIT's `sub`.
    pub spiffe_id: String,
    /// The private half of the WIT's `cnf.jwk`.
    pub key: SigningKey,
}

/// Reads the first WIT-SVID from the output of
/// `spire-agent api fetch wit -output json`.
///
/// SPIRE's private key JWK carries no `alg`, so the key takes the `alg` of the
/// WIT's `cnf.jwk`, and must match it.
///
/// # Errors
///
/// Returns a description of what is missing or malformed.
pub fn spire_wit_svid(output: &str) -> Result<SpireWitSvid, String> {
    let output: Value = serde_json::from_str(output).map_err(|e| format!("output: {e}"))?;
    let svid = output
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|item| item["svids"].get(0))
        .ok_or("no svids in the output")?;
    let wit = svid["wit_svid"].as_str().ok_or("no wit_svid")?.to_owned();
    let claims = wit.split('.').nth(1).ok_or("WIT is not a JWS")?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(claims)
            .map_err(|e| format!("WIT claims: {e}"))?,
    )
    .map_err(|e| format!("WIT claims: {e}"))?;
    let spiffe_id = claims["sub"].as_str().ok_or("WIT has no sub")?.to_owned();
    let cnf: Jwk = serde_json::from_value(claims["cnf"]["jwk"].clone())
        .map_err(|e| format!("cnf.jwk: {e}"))?;
    let mut private: PrivateJwk =
        serde_json::from_str(svid["wit_svid_key"].as_str().ok_or("no wit_svid_key")?)
            .map_err(|e| format!("wit_svid_key: {e}"))?;
    private.alg.clone_from(&cnf.alg);
    let key = private
        .to_signing_key()
        .map_err(|e| format!("wit_svid_key: {e}"))?;
    if Jwk::from_verifying_key(&key.verifying_key()) != cnf {
        return Err("wit_svid_key is not the key in cnf.jwk".into());
    }
    Ok(SpireWitSvid {
        wit,
        spiffe_id,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_spire_wit_svid() {
        let key = SigningKey::from_p256_scalar(&[0x17; 32]).expect("p256 key");
        let wit = wit("agent-a", &key);
        let mut private = serde_json::to_value(PrivateJwk::from_signing_key(&key)).expect("jwk");
        private.as_object_mut().expect("object").remove("alg");
        let output = json!([
            { "svids": [{ "hint": "", "spiffe_id": "spiffe://td.example/agent-a",
                          "wit_svid": wit, "wit_svid_key": private.to_string() }] },
            { "bundles": { "spiffe://td.example": "{\"keys\":[]}" } },
        ]);

        let svid = spire_wit_svid(&output.to_string()).expect("svid");
        assert_eq!(svid.spiffe_id, "spiffe://td.example/agent-a");
        assert_eq!(svid.wit, wit);
        assert_eq!(svid.key.verifying_key(), key.verifying_key());

        let other = SigningKey::from_p256_scalar(&[0x18; 32]).expect("p256 key");
        let mut wrong = serde_json::to_value(PrivateJwk::from_signing_key(&other)).expect("jwk");
        wrong.as_object_mut().expect("object").remove("alg");
        let output = json!([{ "svids": [{ "wit_svid": wit, "wit_svid_key": wrong.to_string() }] }]);
        assert!(spire_wit_svid(&output.to_string()).is_err());
    }
}
