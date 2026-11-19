//! The whole §8 algorithm over an untrusted presentation: a chain of compact
//! JWS, a PoP JWT, a tool name and the arguments as JSON text.
//!
//! Input layout, one field per line:
//!
//! ```text
//! <token>,<token>,...
//! <pop jwt>
//! <tool>
//! <args json>
//! ```
//!
//! The trust anchors, audience and clock are the conformance suite's, so seeds
//! taken from `conformance/aat/aat-jws-vectors.json` pass the signature checks
//! and the fuzzer spends its time in attenuation, constraint matching and the
//! PoP claims rather than guessing signatures.
#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use visado_chain_aat::{
    Invocation, Limits, MemoryReplayCache, Policy, Presentation, TrustAnchor, Verifier,
};
use wimsey_jose::SigningKey;

const NOW: i64 = 1_704_067_500;

fn verifiers() -> [Verifier; 2] {
    let anchors = vec![
        TrustAnchor::new(
            "https://auth.example.com",
            SigningKey::from_ed25519_seed(&[0x01; 32]).verifying_key(),
        ),
        TrustAnchor::new(
            "https://auth.example.org",
            SigningKey::from_ed25519_seed(&[0x05; 32]).verifying_key(),
        ),
    ];
    let audiences = vec!["https://tools.example.com".to_owned()];
    let default = Verifier::new(anchors.clone(), audiences.clone());
    // Tight limits and every optional requirement, so the size, depth and
    // policy branches are reachable from short inputs too.
    let strict = Verifier::new(anchors, audiences)
        .with_limits(Limits {
            max_delegation_depth: 2,
            max_constraint_depth: 4,
            max_constraint_nodes: 16,
            max_token_size: 4096,
            max_chain_size: 8192,
            ..Limits::default()
        })
        .with_policy(Policy {
            require_chain_aud: true,
            require_pop_aud: true,
            nonces: Some(BTreeSet::from(["n-1".to_owned()])),
        });
    [default, strict]
}

fuzz_target!(|data: &str| {
    let mut fields = data.splitn(4, '\n');
    let chain: Vec<String> = fields
        .next()
        .unwrap_or("")
        .split(',')
        .map(ToOwned::to_owned)
        .collect();
    let pop = fields.next().unwrap_or("");
    let tool = fields.next().unwrap_or("");
    let args_json = fields.next().unwrap_or("");

    let presentation = Presentation { chain: &chain, pop };
    let invocation = Invocation { tool, args_json };
    for verifier in verifiers() {
        let _ = verifier.verify(&presentation, &invocation, NOW, None);
        let replay = MemoryReplayCache::new(4);
        let _ = verifier.verify(&presentation, &invocation, NOW, Some(&replay));
    }
});
