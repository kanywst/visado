//! `ChainDecoder::decode` runs §8 steps 1 to 5 over an untrusted chain of
//! compact JWS, separated here by `,`. No PoP and no invocation: this is the
//! path a caller reaches when only the chain is inspected.
//!
//! The anchors and clock are the conformance suite's, so seeds taken from
//! `conformance/aat/aat-jws-vectors.json` verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use visado_chain::ChainDecoder;
use visado_chain_aat::{TrustAnchor, Verifier};
use wimsey_jose::SigningKey;

fuzz_target!(|data: &str| {
    let verifier = Verifier::new(
        vec![
            TrustAnchor::new(
                "https://auth.example.com",
                SigningKey::from_ed25519_seed(&[0x01; 32]).verifying_key(),
            ),
            TrustAnchor::new(
                "https://auth.example.org",
                SigningKey::from_ed25519_seed(&[0x05; 32]).verifying_key(),
            ),
        ],
        vec!["https://tools.example.com".to_owned()],
    );
    let chain: Vec<String> = data.split(',').map(ToOwned::to_owned).collect();
    let _ = verifier.decode(&chain, 1_704_067_500);
});
