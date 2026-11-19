//! The TOML configuration file.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use visado_chain_aat::{Policy, TrustAnchor, Verifier};
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::GateConfig;
use visado_txn_token::Scope;
use wimsey_jose::{Jwk, PrivateJwk, VerifyingKey};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub trust_domain: String,
    #[serde(default = "default_grpc")]
    pub grpc_listen: SocketAddr,
    #[serde(default = "default_http")]
    pub http_listen: SocketAddr,
    #[serde(default = "default_lifetime")]
    pub txn_lifetime: u64,
    pub default_scope: String,
    #[serde(default)]
    pub internal_callers: BTreeSet<String>,
    #[serde(default)]
    pub user_token_header: Option<String>,
    #[serde(default)]
    pub allowed_authorities: BTreeSet<String>,
    #[serde(default = "default_replay_capacity")]
    pub replay_capacity: usize,
    #[serde(default = "default_max_wpt_lifetime")]
    pub max_wpt_lifetime: u64,
    pub signing_key: KeyFile,
    pub pdp: PdpConfig,
    #[serde(default)]
    pub wit_issuers: Vec<WitIssuerConfig>,
    #[serde(default)]
    pub oauth_issuers: Vec<OAuthIssuerConfig>,
    #[serde(default)]
    pub telemetry: Option<TelemetryConfig>,
    #[serde(default)]
    pub aat: Option<AatConfig>,
    #[serde(default)]
    pub asor: Option<AsorConfig>,
}

/// AAT delegation-chain verification.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatConfig {
    /// Identifiers of this enforcement point, matched exactly against `aud`.
    pub audiences: Vec<String>,
    pub trust_anchors: Vec<AatAnchorConfig>,
    /// Deny unless some token in the chain names this enforcement point in
    /// `aud`. On by default, so a chain cannot be replayed at another
    /// enforcement point that trusts the same anchor.
    #[serde(default = "yes")]
    pub require_chain_aud: bool,
    /// Deny a proof of possession without `aat_aud`. On by default.
    #[serde(default = "yes")]
    pub require_pop_aud: bool,
    /// Deny requests that carry no chain. Has no default: an operator who
    /// enables AAT must decide whether a request may leave the chain out.
    pub required: bool,
}

/// asor delegation-chain verification
/// (draft-asor-wimse-agent-delegation-chain-03).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsorConfig {
    /// Identifiers of this enforcement point, matched exactly against the
    /// leaf token's `aud`.
    pub audiences: Vec<String>,
    /// Keys trusted to sign Delegation Tokens. Each key's type sets its
    /// algorithm: `Ed25519` for an OKP key, `ES256` for a P-256 key.
    pub trust_anchors: Vec<AatAnchorConfig>,
    /// Deny requests that carry no chain. Has no default, as for `[aat]`.
    pub required: bool,
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatAnchorConfig {
    pub issuer: String,
    #[serde(default)]
    pub kid: Option<String>,
    pub jwk_file: PathBuf,
}

/// Where to send OpenTelemetry traces.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// OTLP gRPC endpoint, for example `http://otel-collector:4317`.
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

fn default_service_name() -> String {
    "visado".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub kid: String,
    pub jwk_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdpConfig {
    pub endpoint: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Name of an environment variable holding a bearer token for the PDP.
    #[serde(default)]
    pub bearer_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitIssuerConfig {
    pub trust_domain: String,
    #[serde(default)]
    pub issuer: Option<String>,
    pub keys: Vec<KeyFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthIssuerConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_file: PathBuf,
    /// Prefix for `sub` and `client_id`; required when several issuers are trusted.
    #[serde(default)]
    pub subject_prefix: Option<String>,
}

// Loopback by default: ext_authz responses carry minted Transaction Tokens, so
// only the proxy should reach the gRPC port.
fn default_grpc() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9191))
}

fn default_http() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

const fn default_replay_capacity() -> usize {
    100_000
}

const fn default_max_wpt_lifetime() -> u64 {
    60
}

/// The longest Transaction Token lifetime accepted in configuration, in seconds.
pub const MAX_TXN_LIFETIME: u64 = 300;

const fn default_lifetime() -> u64 {
    60
}

// Below Envoy's usual ext_authz timeout, so visado denies before Envoy gives up.
const fn default_timeout_ms() -> u64 {
    150
}

/// Everything built from the file.
pub struct Loaded {
    pub gate: GateConfig,
    pub authenticator: Authenticator,
    pub pdp_endpoint: String,
    pub pdp_timeout: Duration,
    pub pdp_bearer: Option<String>,
    pub public_jwk: Jwk,
    pub grpc_listen: SocketAddr,
    pub http_listen: SocketAddr,
    pub telemetry: Option<TelemetryConfig>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Loaded, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        config.validate()?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.build(base)
    }

    fn validate(&self) -> Result<(), String> {
        if self.trust_domain.trim().is_empty() {
            return Err("trust_domain is empty".into());
        }
        if !(1..=MAX_TXN_LIFETIME).contains(&self.txn_lifetime) {
            return Err(format!(
                "txn_lifetime must be 1..={MAX_TXN_LIFETIME} seconds"
            ));
        }
        if self.pdp.timeout_ms == 0 {
            return Err("pdp.timeout_ms must be positive".into());
        }
        if self.replay_capacity == 0 || self.max_wpt_lifetime == 0 {
            return Err("replay_capacity and max_wpt_lifetime must be positive".into());
        }
        if self.pdp.bearer_env.is_some() && !is_https_or_loopback(&self.pdp.endpoint) {
            return Err("pdp.bearer_env needs an https endpoint (or loopback)".into());
        }
        let mut domains = BTreeSet::new();
        for issuer in &self.wit_issuers {
            if !domains.insert(&issuer.trust_domain) {
                return Err(format!(
                    "duplicate wit_issuers trust_domain {}",
                    issuer.trust_domain
                ));
            }
        }
        let mut issuers = BTreeSet::new();
        for issuer in &self.oauth_issuers {
            if !issuers.insert(&issuer.issuer) {
                return Err(format!("duplicate oauth_issuers issuer {}", issuer.issuer));
            }
        }
        Ok(())
    }

    fn build(self, base: &Path) -> Result<Loaded, String> {
        let private: PrivateJwk = read_json(&base.join(&self.signing_key.jwk_file))?;
        let signing_key = private
            .to_signing_key()
            .map_err(|e| format!("signing key: {e}"))?;
        let public_jwk = private.to_public();

        let mut authenticator =
            Authenticator::new().with_replay_limits(self.replay_capacity, self.max_wpt_lifetime);
        if let Some(header) = &self.user_token_header {
            authenticator = authenticator.with_user_token_header(header);
        }
        for issuer in self.wit_issuers {
            let mut wit = WitIssuer::new(issuer.trust_domain);
            if let Some(iss) = issuer.issuer {
                wit = wit.expect_issuer(iss);
            }
            for key in issuer.keys {
                let jwk: Jwk = read_json(&base.join(&key.jwk_file))?;
                let verifying = jwk
                    .to_verifying_key()
                    .map_err(|e| format!("{}: {e}", key.jwk_file.display()))?;
                wit = wit.with_key(key.kid, verifying);
            }
            authenticator = authenticator.with_wit_issuer(wit);
        }
        for issuer in self.oauth_issuers {
            let jwks = read_json(&base.join(&issuer.jwks_file))?;
            let mut oauth = OAuthIssuer::new(issuer.issuer, issuer.audience, jwks);
            if let Some(prefix) = issuer.subject_prefix {
                oauth = oauth.with_subject_prefix(prefix);
            }
            authenticator = authenticator.with_oauth_issuer(oauth);
        }
        authenticator.check()?;

        let require_chain = self.aat.as_ref().is_some_and(|a| a.required)
            || self.asor.as_ref().is_some_and(|a| a.required);
        let aat = self.aat.map(|c| c.verifier(base)).transpose()?;
        let asor = self.asor.map(|c| c.verifier(base)).transpose()?;

        let pdp_bearer = match &self.pdp.bearer_env {
            Some(name) => Some(std::env::var(name).map_err(|_| format!("{name} is not set"))?),
            None => None,
        };
        let default_scope = Scope::parse(&self.default_scope);
        if default_scope.is_empty() {
            return Err("default_scope is empty".into());
        }
        Ok(Loaded {
            gate: GateConfig {
                trust_domain: self.trust_domain,
                signing_key,
                kid: self.signing_key.kid,
                txn_lifetime: self.txn_lifetime,
                default_scope,
                internal_callers: self.internal_callers,
                allowed_authorities: self.allowed_authorities,
                aat,
                asor,
                require_chain,
            },
            authenticator,
            pdp_endpoint: self.pdp.endpoint,
            pdp_timeout: Duration::from_millis(self.pdp.timeout_ms),
            pdp_bearer,
            public_jwk,
            grpc_listen: self.grpc_listen,
            http_listen: self.http_listen,
            telemetry: self.telemetry,
        })
    }
}

impl AatConfig {
    fn verifier(self, base: &Path) -> Result<Verifier, String> {
        let mut anchors = Vec::new();
        for anchor in &self.trust_anchors {
            let mut trusted = TrustAnchor::new(anchor.issuer.clone(), anchor_key(base, anchor)?);
            if let Some(kid) = &anchor.kid {
                trusted = trusted.with_kid(kid.clone());
            }
            anchors.push(trusted);
        }
        if anchors.is_empty() || self.audiences.is_empty() {
            return Err("aat needs at least one trust anchor and one audience".into());
        }
        Ok(Verifier::new(anchors, self.audiences).with_policy(Policy {
            require_chain_aud: self.require_chain_aud,
            require_pop_aud: self.require_pop_aud,
            nonces: None,
        }))
    }
}

impl AsorConfig {
    fn verifier(self, base: &Path) -> Result<visado_chain_asor::Verifier, String> {
        let mut anchors = Vec::new();
        for anchor in &self.trust_anchors {
            let key = anchor_key(base, anchor)?;
            let mut trusted = visado_chain_asor::TrustAnchor::new(anchor.issuer.clone(), key);
            if let Some(kid) = &anchor.kid {
                trusted = trusted.with_kid(kid.clone());
            }
            anchors.push(trusted);
        }
        if anchors.is_empty() || self.audiences.is_empty() {
            return Err("asor needs at least one trust anchor and one audience".into());
        }
        Ok(visado_chain_asor::Verifier::new(anchors, self.audiences))
    }
}

fn anchor_key(base: &Path, anchor: &AatAnchorConfig) -> Result<VerifyingKey, String> {
    let jwk: Jwk = read_json(&base.join(&anchor.jwk_file))?;
    jwk.to_verifying_key()
        .map_err(|e| format!("{}: {e}", anchor.jwk_file.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn is_https_or_loopback(endpoint: &str) -> bool {
    endpoint.starts_with("https://")
        || endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://[::1]")
}

#[cfg(test)]
mod tests {
    use super::Config;

    const BASE: &str = r#"
trust_domain = "td.example"
default_scope = "read"
[signing_key]
kid = "k"
jwk_file = "k.json"
[pdp]
endpoint = "http://127.0.0.1:8181/access/v1/evaluation"
"#;

    fn parse(extra: &str) -> Result<(), String> {
        let config: Config =
            toml::from_str(&format!("{extra}\n{BASE}")).map_err(|e| e.to_string())?;
        config.validate()
    }

    #[test]
    fn defaults_are_valid_and_loopback() {
        parse("").unwrap();
        let config: Config = toml::from_str(BASE).unwrap();
        assert!(config.grpc_listen.ip().is_loopback());
        assert!(config.http_listen.ip().is_loopback());
        assert_eq!(config.pdp.timeout_ms, 150);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse("txn_lifetime = 0").is_err());
        assert!(parse("txn_lifetime = 3600").is_err());
        assert!(parse("replay_capacity = 0").is_err());
        assert!(parse("unknown_key = 1").is_err());
        let blank: Config = toml::from_str(&BASE.replace("td.example", " ")).unwrap();
        assert!(blank.validate().is_err());
        let zero: Config = toml::from_str(&format!("{BASE}timeout_ms = 0\n")).unwrap();
        assert!(zero.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_issuers() {
        let dup = r#"
[[oauth_issuers]]
issuer = "https://idp"
audience = "a"
jwks_file = "j"
[[oauth_issuers]]
issuer = "https://idp"
audience = "b"
jwks_file = "j"
"#;
        let config: Config = toml::from_str(&format!("{BASE}{dup}")).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn aat_must_say_whether_a_chain_is_required() {
        let without = format!("{BASE}[aat]\naudiences = [\"a\"]\ntrust_anchors = []\n");
        assert!(toml::from_str::<Config>(&without).is_err());
        let with =
            format!("{BASE}[aat]\naudiences = [\"a\"]\ntrust_anchors = []\nrequired = true\n");
        assert!(toml::from_str::<Config>(&with).is_ok());
    }

    #[test]
    fn asor_must_say_whether_a_chain_is_required() {
        let without = format!("{BASE}[asor]\naudiences = [\"a\"]\ntrust_anchors = []\n");
        assert!(toml::from_str::<Config>(&without).is_err());
        let with =
            format!("{BASE}[asor]\naudiences = [\"a\"]\ntrust_anchors = []\nrequired = false\n");
        assert!(toml::from_str::<Config>(&with).is_ok());
    }

    #[test]
    fn pdp_bearer_needs_tls() {
        let remote = BASE.replace("http://127.0.0.1:8181", "http://pdp.example");
        let config: Config = toml::from_str(&format!("{remote}bearer_env = \"T\"\n")).unwrap();
        assert!(config.validate().is_err());
    }
}
