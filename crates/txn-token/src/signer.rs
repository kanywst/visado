//! The key a Transaction Token Service signs with: `Ed25519` or `ES256`
//! through `wimsey-jose`, or `RS256` with an RSA key.

use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::EncodingKey;
use serde_json::{Value, json};
use wimsey_jose::{Jwk, SigningKey};

use crate::error::TxnTokenError;
use crate::keys::KeySet;

/// A key that signs Transaction Tokens.
///
/// [`SigningKey`] converts into one with `into()`; an RSA key comes from a
/// private JWK with [`TxnSigningKey::from_rsa_jwk`] and signs `RS256`.
#[derive(Clone)]
pub struct TxnSigningKey(Inner);

#[derive(Clone)]
enum Inner {
    Jose(SigningKey),
    Rsa {
        key: EncodingKey,
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

impl fmt::Debug for TxnSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxnSigningKey")
            .field("alg", &self.alg())
            .finish_non_exhaustive()
    }
}

impl From<SigningKey> for TxnSigningKey {
    fn from(key: SigningKey) -> Self {
        Self(Inner::Jose(key))
    }
}

impl TxnSigningKey {
    /// An `RS256` key from a private RSA JWK (RFC 7518 §6.3.2) with `n`, `e`,
    /// `d`, `p`, `q`, `dp`, `dq` and `qi`. Other members are ignored.
    ///
    /// # Errors
    ///
    /// [`TxnTokenError::WeakKey`] for a modulus shorter than
    /// [`MIN_RSA_BITS`](crate::MIN_RSA_BITS); [`TxnTokenError::InvalidKey`] for a JWK that is not
    /// an RSA private key with every member above, or whose members do not
    /// form a key that signs.
    pub fn from_rsa_jwk(jwk: &Value) -> Result<Self, TxnTokenError> {
        if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
            return Err(TxnTokenError::InvalidKey("not an RSA key"));
        }
        let member = |name: &'static str| -> Result<Vec<u8>, TxnTokenError> {
            jwk.get(name)
                .and_then(Value::as_str)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .filter(|v| !v.is_empty())
                .ok_or(TxnTokenError::InvalidKey(name))
        };
        let n = member("n")?;
        let e = member("e")?;
        // The minimum size is checked as for a verification key.
        KeySet::new().with_rsa_key("", &n, &e)?;
        let parts = [
            &[0u8][..],
            &n,
            &e,
            &member("d")?,
            &member("p")?,
            &member("q")?,
            &member("dp")?,
            &member("dq")?,
            &member("qi")?,
        ];
        let key = EncodingKey::from_rsa_der(&pkcs1(&parts));
        // A key whose members do not fit together fails here, not at mint.
        jsonwebtoken::crypto::sign(b"probe", &key, jsonwebtoken::Algorithm::RS256)
            .map_err(|_| TxnTokenError::InvalidKey("RSA key does not sign"))?;
        Ok(Self(Inner::Rsa { key, n, e }))
    }

    /// The JOSE `alg` of tokens this key mints.
    #[must_use]
    pub fn alg(&self) -> &'static str {
        match &self.0 {
            Inner::Jose(key) => key.algorithm().as_str(),
            Inner::Rsa { .. } => "RS256",
        }
    }

    /// The public key as a JWK, without `kid` or `use`.
    #[must_use]
    pub fn public_jwk(&self) -> Value {
        match &self.0 {
            Inner::Jose(key) => serde_json::to_value(Jwk::from_verifying_key(&key.verifying_key()))
                .unwrap_or(Value::Null),
            Inner::Rsa { n, e, .. } => json!({
                "kty": "RSA", "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(n), "e": URL_SAFE_NO_PAD.encode(e),
            }),
        }
    }

    /// A [`KeySet`] that verifies this key's tokens under `kid`.
    #[must_use]
    pub fn key_set(&self, kid: &str) -> KeySet {
        match &self.0 {
            Inner::Jose(key) => KeySet::new().with_key(kid, key.verifying_key()),
            Inner::Rsa { n, e, .. } => KeySet::new().with_rsa_key(kid, n, e).unwrap_or_default(),
        }
    }

    /// The Base64url signature over `input`.
    pub(crate) fn sign(&self, input: &[u8]) -> Result<String, TxnTokenError> {
        match &self.0 {
            Inner::Jose(key) => Ok(URL_SAFE_NO_PAD.encode(key.sign(input))),
            Inner::Rsa { key, .. } => {
                jsonwebtoken::crypto::sign(input, key, jsonwebtoken::Algorithm::RS256)
                    .map_err(|_| TxnTokenError::InvalidKey("RSA signing failed"))
            }
        }
    }
}

/// A PKCS#1 `RSAPrivateKey` (RFC 8017 §A.1.2): a SEQUENCE of INTEGERs, each
/// given as unsigned big-endian bytes.
fn pkcs1(integers: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for int in integers {
        let first = int.iter().position(|b| *b != 0).unwrap_or(int.len() - 1);
        let int = &int[first..];
        let mut value = Vec::with_capacity(int.len() + 1);
        if int[0] & 0x80 != 0 {
            value.push(0);
        }
        value.extend_from_slice(int);
        tlv(0x02, &value, &mut body);
    }
    let mut out = Vec::new();
    tlv(0x30, &body, &mut out);
    out
}

fn tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap_or(0));
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(value);
}
