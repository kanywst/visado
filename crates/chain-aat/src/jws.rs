//! The AAT protected header (§3.5) and algorithm allowlist (§9.11).

use visado_chain::jose::b64;
use visado_chain::json;
use wimsey_jose::{Algorithm, VerifyingKey};

/// The algorithms on the allowlist (§9.11). `EdDSA` is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Ed25519,
    Es256,
}

impl Alg {
    fn parse(alg: &str) -> Option<Self> {
        match alg {
            "Ed25519" => Some(Self::Ed25519),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// Whether `key`'s type and curve fit this algorithm.
    pub(crate) fn fits(self, key: &VerifyingKey) -> bool {
        match self {
            Self::Ed25519 => matches!(key.algorithm(), Algorithm::Ed25519 | Algorithm::EdDsa),
            Self::Es256 => key.algorithm() == Algorithm::Es256,
        }
    }
}

/// What the protected header contributed.
#[derive(Debug)]
pub(crate) struct Header {
    pub(crate) alg: Alg,
    pub(crate) kid: Option<String>,
}

/// Checks the protected header (§3.5; §8 steps 3a, 4a and 7a): `alg` on the
/// allowlist, `typ` exactly `typ`, and no `crit`, since this implementation
/// understands no extension header parameter. Key-bearing parameters such as
/// `jwk` are ignored.
pub(crate) fn header(part: &str, typ: &str) -> Option<Header> {
    let value = json::parse(&b64(part)?).ok()?;
    value.as_object()?;
    let alg = Alg::parse(value.get("alg")?.as_str()?)?;
    if value.get("typ")?.as_str()? != typ {
        return None;
    }
    if value.get("crit").is_some() {
        return None;
    }
    let kid = match value.get("kid") {
        None => None,
        Some(v) => Some(v.as_str()?.to_owned()),
    };
    Some(Header { alg, kid })
}
