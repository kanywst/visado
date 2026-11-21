//! Prints a request for the lab in `deploy/lab` that authenticates without a
//! WPT, at the current time: one `Name: value` header per line, then
//! `BODY: <body>` if there is one.
//!
//! ```text
//! lab_methods sig <svid-dir> <workload> <path> <body> [--send <body>]
//! lab_methods dpop <path> [--bearer | --nonce <nonce>]
//! lab_methods bearer [--expired]
//! ```
//!
//! `sig`: a POST of `body` as JSON, signed with an HTTP message signature
//! (draft-ietf-wimse-http-signature) by the workload's SPIRE WIT-SVID key, read
//! from `<svid-dir>/<workload>.json` (the output of
//! `spire-agent api fetch wit -output json`). The signature covers the
//! `Content-Digest` of `body`; `--send` puts another body on the wire.
//!
//! `dpop`: a GET with an access token for bob, DPoP-bound (RFC 9449) to a fixed
//! demo key and signed with the fixed OAuth demo key, and a DPoP proof by that
//! key. `--bearer` sends the token as `Bearer` without the proof; `--nonce`
//! puts a server-provided nonce (RFC 9449 §9) in the proof.
//!
//! `bearer`: an access token for bob with no `cnf`, signed with the fixed
//! OAuth demo key, as `Authorization: Bearer`. `--expired` makes it one that
//! expired two minutes ago.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

const AUTHORITY: &str = "tools.td.example";

fn usage() -> ! {
    eprintln!(
        "usage: lab_methods sig <svid-dir> <workload> <path> <body> [--send <body>]\n       lab_methods dpop <path> [--bearer | --nonce <nonce>]\n       lab_methods bearer [--expired]"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970");
    let now = clock.as_secs();
    let nonce = format!("{}-{}", clock.as_nanos(), std::process::id());
    match args.first().map(String::as_str) {
        Some("sig") => {
            let (Some(dir), Some(workload), Some(path), Some(body)) =
                (args.get(1), args.get(2), args.get(3), args.get(4))
            else {
                usage()
            };
            let sent = match (args.get(5).map(String::as_str), args.get(6)) {
                (None, _) => body,
                (Some("--send"), Some(sent)) => sent,
                _ => usage(),
            };
            signed(dir, workload, path, body, sent, now, &nonce);
        }
        Some("dpop") => {
            let Some(path) = args.get(1) else { usage() };
            let mode = match (args.get(2).map(String::as_str), args.get(3), args.get(4)) {
                (None, _, _) => Dpop::Proof(None),
                (Some("--bearer"), None, _) => Dpop::Bearer,
                (Some("--nonce"), Some(server), None) => Dpop::Proof(Some(server)),
                _ => usage(),
            };
            dpop(path, &mode, now, &nonce);
        }
        Some("bearer") => {
            let expired = match args.get(1).map(String::as_str) {
                None => false,
                Some("--expired") if args.len() == 2 => true,
                _ => usage(),
            };
            bearer(expired, now, &nonce);
        }
        _ => usage(),
    }
}

fn signed(dir: &str, workload: &str, path: &str, body: &str, sent: &str, now: u64, nonce: &str) {
    let file = Path::new(dir).join(format!("{workload}.json"));
    let output =
        std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let svid = visado_testkit::spire_wit_svid(&output)
        .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let digest = visado_testkit::content_digest(body.as_bytes());
    let headers = [
        ("workload-identity-token", svid.wit.as_str()),
        ("content-type", "application/json"),
        ("content-digest", digest.as_str()),
    ];
    let (input, signature) = visado_testkit::http_signature(
        "POST",
        AUTHORITY,
        path,
        &headers,
        &svid.key,
        &visado_testkit::SignatureSpec {
            nonce,
            created: now,
            audience: &format!("http://{AUTHORITY}{path}"),
            cover: &[],
        },
    );
    println!("Workload-Identity-Token: {}", svid.wit);
    println!("Content-Type: application/json");
    println!("Content-Digest: {digest}");
    println!("Signature-Input: {input}");
    println!("Signature: {signature}");
    println!("BODY: {sent}");
}

fn bearer(expired: bool, now: u64, nonce: &str) {
    let (iat, exp) = if expired {
        (now - 420, now - 120)
    } else {
        (now, now + 300)
    };
    let token = visado_testkit::signed_access_token(&json!({
        "iss": visado_testkit::OAUTH_ISSUER,
        "sub": "bob",
        "aud": format!("http://{AUTHORITY}"),
        "client_id": "bearer-client",
        "scope": "tickets.read",
        "iat": iat,
        "exp": exp,
        "jti": format!("at-{nonce}"),
    }));
    println!("Authorization: Bearer {token}");
}

/// What `lab_methods dpop` sends.
enum Dpop<'a> {
    /// The token as `Bearer`, without a proof.
    Bearer,
    /// The token as `DPoP` with a proof, carrying the server's nonce if
    /// given.
    Proof(Option<&'a String>),
}

fn dpop(path: &str, mode: &Dpop<'_>, now: u64, nonce: &str) {
    let holder = visado_testkit::pop_key(0x61);
    let token = visado_testkit::signed_access_token(&json!({
        "iss": visado_testkit::OAUTH_ISSUER,
        "sub": "bob",
        "aud": format!("http://{AUTHORITY}"),
        "client_id": "dpop-client",
        "scope": "tickets.read",
        "iat": now,
        "exp": now + 300,
        "jti": format!("at-{nonce}"),
        "cnf": { "jkt": visado_chain_aat::jwk_thumbprint(&holder.verifying_key()) },
    }));
    let server_nonce = match mode {
        Dpop::Bearer => {
            println!("Authorization: Bearer {token}");
            return;
        }
        Dpop::Proof(server_nonce) => server_nonce,
    };
    let uri = format!("http://{AUTHORITY}{path}");
    let mut claims =
        visado_testkit::dpop_claims("GET", &uri, &token, &format!("proof-{nonce}"), now);
    if let Some(server_nonce) = server_nonce {
        claims["nonce"] = json!(server_nonce);
    }
    let header = json!({
        "alg": "Ed25519",
        "typ": "dpop+jwt",
        "jwk": visado_testkit::dpop_jwk(&holder),
    });
    let proof = visado_testkit::sign_dpop_proof(&header, &claims, &holder);
    println!("Authorization: DPoP {token}");
    println!("DPoP: {proof}");
}
