//! Prints a request for the lab in `deploy/lab` that authenticates without a
//! WPT, at the current time: one `Name: value` header per line, then
//! `BODY: <body>` if there is one.
//!
//! ```text
//! lab_methods sig <svid-dir> <workload> <path> <body> [--send <body>]
//! lab_methods dpop <path> [--bearer]
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
//! key. `--bearer` sends the token as `Bearer` without the proof.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

const AUTHORITY: &str = "tools.td.example";

fn usage() -> ! {
    eprintln!(
        "usage: lab_methods sig <svid-dir> <workload> <path> <body> [--send <body>]\n       lab_methods dpop <path> [--bearer]"
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
            let bearer = match args.get(2).map(String::as_str) {
                None => false,
                Some("--bearer") => true,
                _ => usage(),
            };
            dpop(path, bearer, now, &nonce);
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

fn dpop(path: &str, bearer: bool, now: u64, nonce: &str) {
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
    if bearer {
        println!("Authorization: Bearer {token}");
        return;
    }
    let proof = visado_testkit::dpop_proof(
        &holder,
        "GET",
        &format!("http://{AUTHORITY}{path}"),
        &token,
        &format!("proof-{nonce}"),
        now,
    );
    println!("Authorization: DPoP {token}");
    println!("DPoP: {proof}");
}
