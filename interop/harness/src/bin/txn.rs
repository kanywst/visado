//! Transaction Token interop harness.
//!
//! Reads and writes JSON so scripts in other languages can drive it. See
//! `interop/txn-token/README.md`.
//!
//! - `txn mint [--now N]`: prints Txn-Tokens signed by visado (ES256,
//!   Ed25519 and `EdDSA`), the public JWKs, and a set of negative cases, each
//!   with visado's own verdict. The output is the input format of
//!   `txn verify`.
//! - `txn verify`: reads `{trust_domain, now, keys: [JWK], cases: [{id,
//!   token, now?, trust_domain?}]}` on standard input and prints one verdict
//!   per case with visado's error code.

use std::io::Read;
use std::process::ExitCode;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use visado_txn_token::{
    KeySet, Scope, TxnSigningKey, TxnTokenClaims, Validation, mint, mint_with, verify,
};
use wimsey_jose::{Algorithm, Jwk, SigningKey};

/// The default time minted tokens are issued around and checked at.
const NOW: u64 = 1_800_000_000;
/// The trust domain every minted token names.
const TRUST_DOMAIN: &str = "trust-domain.example";
/// The `iss` minted tokens carry, where they carry one.
const ISSUER: &str = "https://tts.trust-domain.example";
/// Lifetime of minted tokens, in seconds.
const LIFETIME: u64 = 300;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.first().map(String::as_str) {
        Some("mint") => parse_now(&args[1..]).map(mint_cases),
        Some("verify") => stdin().map(|input| verify_cases(&input)),
        _ => Err("usage: txn <mint [--now N] | verify>".to_owned()),
    };
    match out {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).expect("json"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("txn: {e}");
            ExitCode::from(2)
        }
    }
}

fn parse_now(args: &[String]) -> Result<u64, String> {
    match args {
        [] => Ok(NOW),
        [flag, n] if flag == "--now" => n.parse().map_err(|e| format!("--now: {e}")),
        _ => Err("usage: txn mint [--now N]".to_owned()),
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

/// Builds a [`KeySet`] from JWKs. A JWK with `kid` is selected by it; one
/// without becomes the unnamed key. RSA keys go to `with_rsa_key`. Keys that
/// cannot be read are reported, not fatal.
fn key_set(jwks: &[Value]) -> (KeySet, Vec<Value>, Vec<Value>) {
    let mut keys = KeySet::new();
    let mut loaded = Vec::new();
    let mut errors = Vec::new();
    for value in jwks {
        let kid = value.get("kid").and_then(Value::as_str);
        if value.get("kty").and_then(Value::as_str) == Some("RSA") {
            let part = |name: &str| {
                value
                    .get(name)
                    .and_then(Value::as_str)
                    .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                    .unwrap_or_default()
            };
            let (n, e) = (part("n"), part("e"));
            let added = match kid {
                Some(kid) => keys.clone().with_rsa_key(kid, &n, &e),
                None => keys.clone().with_unnamed_rsa_key(&n, &e),
            };
            match added {
                Ok(next) => {
                    keys = next;
                    loaded.push(json!({ "kid": kid, "alg": "RS256" }));
                }
                Err(error) => errors.push(json!({
                    "kid": kid, "kty": "RSA", "alg": value.get("alg"), "error": error.to_string(),
                })),
            }
            continue;
        }
        let key = serde_json::from_value::<Jwk>(value.clone())
            .map_err(|e| e.to_string())
            .and_then(|jwk| jwk.to_verifying_key().map_err(|e| e.to_string()));
        match key {
            Ok(key) => {
                loaded.push(json!({ "kid": kid, "alg": key.algorithm().as_str() }));
                keys = match kid {
                    Some(kid) => keys.with_key(kid, key),
                    None => keys.with_unnamed_key(key),
                };
            }
            Err(error) => errors.push(json!({
                "kid": kid,
                "kty": value.get("kty"),
                "alg": value.get("alg"),
                "error": error,
            })),
        }
    }
    (keys, loaded, errors)
}

fn verify_cases(input: &Value) -> Value {
    let jwks = input["keys"].as_array().cloned().unwrap_or_default();
    let (keys, loaded, key_errors) = key_set(&jwks);
    let trust_domain = input["trust_domain"].as_str().unwrap_or_default();
    let now = input["now"].as_u64().unwrap_or(NOW);
    let cases: Vec<Value> = input["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|case| {
            let validation = Validation::new(
                case["trust_domain"].as_str().unwrap_or(trust_domain),
                case["now"].as_u64().unwrap_or(now),
            );
            verdict(
                case["id"].as_str().unwrap_or_default(),
                &verify(
                    case["token"].as_str().unwrap_or_default(),
                    &keys,
                    &validation,
                ),
            )
        })
        .collect();
    json!({
        "verifier": "visado",
        "version": env!("CARGO_PKG_VERSION"),
        "keys_loaded": loaded,
        "key_errors": key_errors,
        "cases": cases,
    })
}

fn verdict(
    id: &str,
    result: &Result<visado_txn_token::VerifiedTxnToken, visado_txn_token::TxnTokenError>,
) -> Value {
    match result {
        Ok(verified) => json!({
            "id": id,
            "verdict": "accept",
            "tctx": verified.claims.tctx,
            "rctx": verified.claims.rctx,
        }),
        Err(e) => json!({
            "id": id,
            "verdict": "reject",
            "error": e.code(),
            "detail": e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

struct Keys {
    es256: SigningKey,
    ed25519: SigningKey,
    eddsa: SigningKey,
    /// The test-only RSA key of `visado-txn-token`'s tests.
    rs256: TxnSigningKey,
}

impl Keys {
    fn new() -> Self {
        Self {
            es256: SigningKey::from_p256_scalar(&[0x31; 32]).expect("P-256 scalar"),
            ed25519: SigningKey::from_ed25519_seed(&[0x32; 32]),
            eddsa: SigningKey::from_ed25519_seed(&[0x33; 32])
                .with_algorithm(Algorithm::EdDsa)
                .expect("EdDSA"),
            rs256: TxnSigningKey::from_rsa_jwk(
                &serde_json::from_str(include_str!(
                    "../../../../crates/txn-token/tests/fixtures/rsa-2048.private.jwk.json"
                ))
                .expect("jwk"),
            )
            .expect("RSA key"),
        }
    }

    fn jwks(&self) -> Vec<Value> {
        [
            ("visado-es256", &self.es256),
            ("visado-ed25519", &self.ed25519),
            ("visado-eddsa", &self.eddsa),
        ]
        .into_iter()
        .map(|(kid, key)| {
            let mut jwk =
                serde_json::to_value(Jwk::from_verifying_key(&key.verifying_key())).expect("jwk");
            jwk["kid"] = json!(kid);
            jwk["use"] = json!("sig");
            jwk
        })
        .chain(std::iter::once({
            let mut jwk = self
                .rs256
                .public_jwk()
                .expect("RSA fixture has a public JWK");
            jwk["kid"] = json!("visado-rs256");
            jwk["use"] = json!("sig");
            jwk
        }))
        .collect()
    }
}

fn claims(now: u64, iss: Option<&str>) -> TxnTokenClaims {
    let ctx = |v: Value| v.as_object().cloned();
    TxnTokenClaims {
        iss: iss.map(ToOwned::to_owned),
        iat: now,
        aud: TRUST_DOMAIN.to_owned(),
        exp: now + LIFETIME,
        txn: "97053963-771d-49cc-a4e3-20aad399c312".to_owned(),
        sub: "user@trust-domain.example".to_owned(),
        scope: Scope::parse("trade.stocks"),
        req_wl: "spiffe://trust-domain.example/gateway".to_owned(),
        tctx: ctx(json!({
            "action": "BUY",
            "ticker": "MSFT",
            "quantity": "100",
            "customer_type": { "geo": "US", "level": "VIP" },
        })),
        rctx: ctx(json!({ "req_ip": "198.51.100.7", "authn": "urn:ietf:rfc:6749" })),
    }
}

/// Signs an arbitrary header and claim set, for cases [`mint`] refuses.
fn sign_raw(header: &Value, claims: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("json")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json")),
    );
    let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    format!("{input}.{signature}")
}

fn es256_header(typ: Option<&str>) -> Value {
    let mut header = json!({ "alg": "ES256", "kid": "visado-es256" });
    if let Some(typ) = typ {
        header["typ"] = json!(typ);
    }
    header
}

/// The claims of `claims(now, Some(ISSUER))` as JSON, with `edit` applied.
fn edited(now: u64, edit: impl FnOnce(&mut Map<String, Value>)) -> Value {
    let mut value = serde_json::to_value(claims(now, Some(ISSUER))).expect("json");
    edit(value.as_object_mut().expect("object"));
    value
}

/// Flips one bit of the signature.
fn tamper(token: &str) -> String {
    let (input, signature) = token.rsplit_once('.').expect("compact JWS");
    let mut raw = URL_SAFE_NO_PAD.decode(signature).expect("base64url");
    raw[0] ^= 0x01;
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw))
}

fn case(id: &str, token: String, expect: &str, why: &str) -> Value {
    json!({ "id": id, "token": Value::String(token), "expect": expect, "why": why })
}

#[allow(clippy::too_many_lines)]
fn mint_cases(now: u64) -> Value {
    let keys = Keys::new();
    let valid = claims(now, Some(ISSUER));
    let es256 = |c: &TxnTokenClaims| mint(c, Some("visado-es256"), &keys.es256).expect("mint");
    let es256_raw = |c: &Value| sign_raw(&es256_header(Some("txntoken+jwt")), c, &keys.es256);

    let expired = TxnTokenClaims {
        iat: now - 2 * LIFETIME,
        exp: now - LIFETIME,
        ..valid.clone()
    };
    let boundary = TxnTokenClaims {
        iat: now - LIFETIME,
        exp: now,
        ..valid.clone()
    };
    let wrong_aud = TxnTokenClaims {
        aud: "other-domain.example".to_owned(),
        ..valid.clone()
    };
    let future = TxnTokenClaims {
        iat: now + LIFETIME,
        exp: now + 2 * LIFETIME,
        ..valid.clone()
    };
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"txntoken+jwt"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid).expect("json")),
    );

    let cases = vec![
        case(
            "es256-valid",
            es256(&valid),
            "accept",
            "§9.2 all REQUIRED claims, tctx and rctx",
        ),
        case(
            "ed25519-valid",
            mint(&valid, Some("visado-ed25519"), &keys.ed25519).expect("mint"),
            "accept",
            "alg Ed25519 (RFC 9864); draft-11 names no algorithm",
        ),
        case(
            "eddsa-valid",
            mint(&valid, Some("visado-eddsa"), &keys.eddsa).expect("mint"),
            "accept",
            "alg EdDSA (RFC 8037)",
        ),
        case(
            "rs256-valid",
            mint_with(&valid, Some("visado-rs256"), &keys.rs256).expect("mint"),
            "accept",
            "alg RS256, the only alg in a draft-11 example (§9.1)",
        ),
        case(
            "rs256-expired",
            mint_with(&expired, Some("visado-rs256"), &keys.rs256).expect("mint"),
            "reject",
            "§12.2 expiry",
        ),
        case(
            "rs256-tampered",
            tamper(&mint_with(&valid, Some("visado-rs256"), &keys.rs256).expect("mint")),
            "reject",
            "§12.2 signature",
        ),
        case(
            "es256-no-iss",
            es256(&claims(now, None)),
            "accept",
            "§9.2 iss OPTIONAL",
        ),
        case(
            "es256-expired",
            es256(&expired),
            "reject",
            "§12.2 not expired",
        ),
        case(
            "es256-exp-equals-now",
            es256(&boundary),
            "reject",
            "RFC 7519 §4.1.4: now must be before exp (leeway allowed)",
        ),
        case(
            "es256-wrong-aud",
            es256(&wrong_aud),
            "reject",
            "§9.2 aud, §12.2 trust domain",
        ),
        case(
            "es256-tampered",
            tamper(&es256(&valid)),
            "reject",
            "§12.2 signature",
        ),
        case(
            "es256-missing-scope",
            es256_raw(&edited(now, |c| {
                c.remove("scope");
            })),
            "reject",
            "§9.2 scope REQUIRED",
        ),
        case(
            "es256-missing-req_wl",
            es256_raw(&edited(now, |c| {
                c.remove("req_wl");
            })),
            "reject",
            "§9.2 req_wl REQUIRED",
        ),
        case(
            "es256-missing-txn",
            es256_raw(&edited(now, |c| {
                c.remove("txn");
            })),
            "reject",
            "§9.2 txn REQUIRED",
        ),
        case(
            "es256-missing-iat",
            es256_raw(&edited(now, |c| {
                c.remove("iat");
            })),
            "reject",
            "§9.2 iat REQUIRED",
        ),
        case(
            "es256-empty-scope",
            es256_raw(&edited(now, |c| {
                c.insert("scope".into(), json!(""));
            })),
            "unspecified",
            "§9.2 scope REQUIRED; an empty value is not addressed",
        ),
        case(
            "es256-aud-array",
            es256_raw(&edited(now, |c| {
                c.insert("aud".into(), json!([TRUST_DOMAIN]));
            })),
            "unspecified",
            "RFC 7519 §4.1.3 allows an array; §9.2 does not say",
        ),
        case(
            "es256-iat-future",
            es256(&future),
            "unspecified",
            "no iat check in §12.2",
        ),
        case(
            "es256-typ-media-type",
            sign_raw(
                &es256_header(Some("application/txntoken+jwt")),
                &serde_json::to_value(&valid).expect("json"),
                &keys.es256,
            ),
            "unspecified",
            "§9.1 value txntoken+jwt; RFC 7515 §4.1.9 equivalence",
        ),
        case(
            "es256-no-typ",
            sign_raw(
                &es256_header(None),
                &serde_json::to_value(&valid).expect("json"),
                &keys.es256,
            ),
            "reject",
            "§9.1 typ MUST be present",
        ),
        case("alg-none", unsigned, "reject", "§12.2 signature"),
    ];

    let jwks = keys.jwks();
    let mut input = json!({
        "minter": "visado",
        "version": env!("CARGO_PKG_VERSION"),
        "trust_domain": TRUST_DOMAIN,
        "issuer": ISSUER,
        "now": now,
        "keys": jwks,
        "cases": cases,
    });
    let own = verify_cases(&input);
    if let (Some(cases), Some(verdicts)) = (input["cases"].as_array_mut(), own["cases"].as_array())
    {
        for (case, verdict) in cases.iter_mut().zip(verdicts) {
            case["visado"] = verdict.clone();
        }
    }
    input
}
