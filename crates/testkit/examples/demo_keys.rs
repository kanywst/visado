//! Writes the fixed demo keys used by `deploy/local` to the given directory.
//! These keys are public; never use them outside a demo.

use std::path::PathBuf;

use wimsey_jose::{Jwk, PrivateJwk, SigningKey};

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "deploy/local/keys".into()));
    std::fs::create_dir_all(&dir).expect("create key directory");
    let txn = SigningKey::from_ed25519_seed(&[0x51; 32]);
    let write = |name: &str, value: serde_json::Value| {
        let text = serde_json::to_string_pretty(&value).expect("json") + "\n";
        std::fs::write(dir.join(name), text).expect("write key");
    };
    write("txn-signing.private.jwk.json", serde_json::to_value(PrivateJwk::from_signing_key(&txn)).expect("jwk"));
    write(
        "wit-issuer.jwk.json",
        serde_json::to_value(Jwk::from_verifying_key(&visado_testkit::wit_issuer_verifying_key())).expect("jwk"),
    );
    write("oauth-jwks.json", visado_testkit::oauth_jwks());
}
