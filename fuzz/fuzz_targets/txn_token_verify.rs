//! Transaction Token verification runs over an untrusted compact JWS: three
//! base64url parts, a JSON header and a JSON claim set, all from the caller.
//!
//! The keys and validation are the conformance suite's, so seeds taken from
//! `conformance/txn-token/vectors.json` verify and the fuzzer starts deep in
//! the claim checks. What is being tested is that every rejection is a
//! returned error rather than a panic, an overflow or a hang.
#![no_main]

use libfuzzer_sys::fuzz_target;
use visado_txn_token::{KeySet, Validation, fingerprint, verify};
use wimsey_jose::SigningKey;

fuzz_target!(|data: &str| {
    let ed = SigningKey::from_ed25519_seed(&[0x11; 32]).verifying_key();
    let p256 = SigningKey::from_p256_scalar(&[0x22; 32])
        .expect("a fixed valid scalar")
        .verifying_key();

    let named = KeySet::new()
        .with_key("ed", ed.clone())
        .with_key("p256", p256);
    let unnamed = KeySet::new().with_unnamed_key(ed);

    let validation = Validation::new("trust-domain.example", 1_800_000_000).with_max_lifetime(300);
    let lenient = Validation::new("trust-domain.example", 1_800_000_000).with_leeway(u64::MAX);

    let _ = verify(data, &named, &validation);
    let _ = verify(data, &named, &lenient);
    let _ = verify(data, &unnamed, &validation);
    let _ = fingerprint(data);
});
