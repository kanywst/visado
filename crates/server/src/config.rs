//! The TOML configuration file.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::GateConfig;
use visado_txn_token::Scope;
use wimsey_jose::{Jwk, PrivateJwk};

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
    pub signing_key: KeyFile,
    pub pdp: PdpConfig,
    #[serde(default)]
    pub wit_issuers: Vec<WitIssuerConfig>,
    #[serde(default)]
    pub oauth_issuers: Vec<OAuthIssuerConfig>,
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
}

fn default_grpc() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9191))
}

fn default_http() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

const fn default_lifetime() -> u64 {
    60
}

const fn default_timeout_ms() -> u64 {
    500
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
}

impl Config {
    pub fn load(path: &Path) -> Result<Loaded, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let config: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.build(base)
    }

    fn build(self, base: &Path) -> Result<Loaded, String> {
        let private: PrivateJwk = read_json(&base.join(&self.signing_key.jwk_file))?;
        let signing_key = private
            .to_signing_key()
            .map_err(|e| format!("signing key: {e}"))?;
        let public_jwk = private.to_public();

        let mut authenticator = Authenticator::new();
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
            authenticator = authenticator.with_oauth_issuer(OAuthIssuer::new(
                issuer.issuer,
                issuer.audience,
                jwks,
            ));
        }

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
            },
            authenticator,
            pdp_endpoint: self.pdp.endpoint,
            pdp_timeout: Duration::from_millis(self.pdp.timeout_ms),
            pdp_bearer,
            public_jwk,
            grpc_listen: self.grpc_listen,
            http_listen: self.http_listen,
        })
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
