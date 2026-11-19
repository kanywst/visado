//! The TOML configuration file.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use visado_chain_aat::{Policy, TrustAnchor, Verifier};
use visado_credentials::{Authenticator, JwtBundle, OAuthIssuer, WitIssuer, X509Bundle};
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
    /// The longest HTTP message signature window (`expires` minus
    /// `created`), and the oldest `created` accepted, in seconds.
    #[serde(default = "default_max_wpt_lifetime")]
    pub max_signature_lifetime: u64,
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
    pub mtls: Option<MtlsConfig>,
    #[serde(default)]
    pub jwt_svid: Option<JwtSvidConfig>,
    #[serde(default)]
    pub asor: Option<AsorConfig>,
}

/// SPIFFE JWT-SVIDs as bearer tokens.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtSvidConfig {
    /// This service's names, matched exactly against `aud`.
    pub audiences: Vec<String>,
    pub trust_bundles: Vec<JwtBundleConfig>,
}

/// The JWT signing keys for one trust domain.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtBundleConfig {
    pub trust_domain: String,
    /// A SPIFFE trust bundle (JWK set); keys with `use` `jwt-svid` are used.
    pub bundle_file: PathBuf,
}

/// mTLS with X.509-SVIDs. The proxy must terminate the client's TLS itself and
/// pass the peer certificate (Envoy: `include_peer_certificate`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    pub trust_bundles: Vec<X509BundleConfig>,
    /// A certificate is public, so anyone who can call the gRPC port can claim
    /// any workload's. Unless this is set, `[mtls]` needs a loopback
    /// `grpc_listen`; set it only when the network lets nothing but the proxy
    /// reach that port.
    #[serde(default)]
    pub grpc_reachable_only_by_proxy: bool,
}

/// The CA for one trust domain. Leaf certificates must be issued directly by
/// it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509BundleConfig {
    pub trust_domain: String,
    /// One PEM certificate.
    pub ca_file: PathBuf,
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

/// The longest HTTP signature window accepted in configuration, in seconds.
/// The draft asks for minutes, not hours.
pub const MAX_SIGNATURE_LIFETIME: u64 = 300;

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
        // WPT and HTTP signature audiences name the request's own authority;
        // without a list, anyone who sets Host matches any audience.
        if self.allowed_authorities.is_empty() {
            return Err("allowed_authorities must list the authorities this gate protects".into());
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
        if !(1..=MAX_SIGNATURE_LIFETIME).contains(&self.max_signature_lifetime) {
            return Err(format!(
                "max_signature_lifetime must be 1..={MAX_SIGNATURE_LIFETIME} seconds"
            ));
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
        if let Some(mtls) = &self.mtls {
            if !self.grpc_listen.ip().is_loopback() && !mtls.grpc_reachable_only_by_proxy {
                return Err("[mtls] needs a loopback grpc_listen, or grpc_reachable_only_by_proxy = true when only the proxy can reach the port".into());
            }
            check_trust_domains(
                "mtls.trust_bundles",
                mtls.trust_bundles.iter().map(|b| &b.trust_domain),
            )?;
        }
        if let Some(jwt) = &self.jwt_svid {
            check_trust_domains(
                "jwt_svid.trust_bundles",
                jwt.trust_bundles.iter().map(|b| &b.trust_domain),
            )?;
            if jwt.audiences.is_empty() || jwt.audiences.iter().any(|a| a.trim().is_empty()) {
                return Err("jwt_svid.audiences needs at least one non-empty audience".into());
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

        let mut authenticator = Authenticator::new()
            .with_replay_limits(self.replay_capacity, self.max_wpt_lifetime)
            .with_signature_lifetime(self.max_signature_lifetime);
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
        let authenticator = with_svid_bundles(authenticator, self.mtls, self.jwt_svid, base)?;
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
                act: None,
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

/// Adds the SPIFFE trust bundles: X.509 CAs for mTLS and JWT keys for
/// JWT-SVIDs.
fn with_svid_bundles(
    mut authenticator: Authenticator,
    mtls: Option<MtlsConfig>,
    jwt_svid: Option<JwtSvidConfig>,
    base: &Path,
) -> Result<Authenticator, String> {
    for bundle in mtls.map(|m| m.trust_bundles).unwrap_or_default() {
        let path = base.join(&bundle.ca_file);
        let pem = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let trusted = X509Bundle::from_pem(bundle.trust_domain, &pem)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        authenticator = authenticator.with_x509_bundle(trusted);
    }
    if let Some(jwt) = jwt_svid {
        for bundle in jwt.trust_bundles {
            let path = base.join(&bundle.bundle_file);
            let json: serde_json::Value = read_json(&path)?;
            let trusted = JwtBundle::from_spiffe_bundle(bundle.trust_domain, &json)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            authenticator = authenticator.with_jwt_bundle(trusted);
        }
        for audience in jwt.audiences {
            authenticator = authenticator.with_jwt_svid_audience(audience);
        }
    }
    Ok(authenticator)
}

/// At least one trust domain, each a bare name (no scheme or path) and listed
/// once.
fn check_trust_domains<'a>(
    what: &str,
    domains: impl Iterator<Item = &'a String>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for domain in domains {
        if domain.is_empty()
            || domain.contains([':', '/'])
            || domain != &domain.to_ascii_lowercase()
        {
            return Err(format!("{what}: {domain:?} is not a trust domain name"));
        }
        if !seen.insert(domain) {
            return Err(format!("{what}: duplicate trust_domain {domain}"));
        }
    }
    if seen.is_empty() {
        return Err(format!("{what} is empty"));
    }
    Ok(())
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
allowed_authorities = ["tools.td.example"]
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

    /// Like `parse`, with `tables` after the base file.
    fn parse_tables(tables: &str) -> Result<(), String> {
        let config: Config =
            toml::from_str(&format!("{BASE}\n{tables}")).map_err(|e| e.to_string())?;
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
        assert!(parse("max_signature_lifetime = 0").is_err());
        assert!(parse("max_signature_lifetime = 3600").is_err());
        assert!(parse("max_signature_lifetime = 120").is_ok());
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
    fn mtls_needs_distinct_trust_domains() {
        let bundle = |td: &str| {
            format!("[[mtls.trust_bundles]]\ntrust_domain = \"{td}\"\nca_file = \"ca.pem\"\n")
        };
        assert!(parse_tables(&bundle("td.example")).is_ok());
        assert!(parse_tables("[mtls]\ntrust_bundles = []\n").is_err());
        assert!(
            parse_tables(&format!("{}{}", bundle("td.example"), bundle("td.example"))).is_err()
        );
        assert!(parse_tables(&bundle("spiffe://td.example")).is_err());
        assert!(parse_tables(&bundle("")).is_err());
        let open = |extra: &str| {
            let config: Config = toml::from_str(&format!(
                "grpc_listen = \"0.0.0.0:9191\"\n{BASE}[mtls]\n{extra}[[mtls.trust_bundles]]\ntrust_domain = \"td.example\"\nca_file = \"ca.pem\"\n"
            ))
            .unwrap();
            config.validate()
        };
        assert!(open("").is_err());
        assert!(open("grpc_reachable_only_by_proxy = true\n").is_ok());
        assert!(parse_tables("[[mtls.trust_bundles]]\ntrust_domain = \"td.example\"\nca_file = \"ca.pem\"\nchain = true\n").is_err());
    }

    #[test]
    fn jwt_svid_needs_an_audience_and_bundles() {
        let bundle =
            "[[jwt_svid.trust_bundles]]\ntrust_domain = \"td.example\"\nbundle_file = \"b.json\"\n";
        assert!(
            parse_tables(&format!(
                "[jwt_svid]\naudiences = [\"spiffe://td.example/visado\"]\n{bundle}"
            ))
            .is_ok()
        );
        assert!(parse_tables(&format!("[jwt_svid]\naudiences = []\n{bundle}")).is_err());
        assert!(parse_tables(&format!("[jwt_svid]\naudiences = [\" \"]\n{bundle}")).is_err());
        assert!(parse_tables("[jwt_svid]\naudiences = [\"a\"]\ntrust_bundles = []\n").is_err());
        assert!(
            toml::from_str::<Config>(&format!("{BASE}[jwt_svid]\ntrust_bundles = []\n")).is_err()
        );
    }

    #[test]
    fn loads_svid_trust_bundles_relative_to_the_file() {
        use visado_testkit::{certificate_pem, jwt_bundle, workload_ca};
        let dir = std::env::temp_dir().join(format!("visado-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/local/keys/txn-signing.private.jwk.json");
        std::fs::copy(key, dir.join("k.json")).unwrap();
        std::fs::write(
            dir.join("ca.pem"),
            certificate_pem(workload_ca().certificate_der()),
        )
        .unwrap();
        std::fs::write(dir.join("b.json"), jwt_bundle().to_string()).unwrap();
        let tables = "[mtls]\n[[mtls.trust_bundles]]\ntrust_domain = \"td.example\"\nca_file = \"ca.pem\"\n\
            [jwt_svid]\naudiences = [\"spiffe://td.example/visado\"]\n\
            [[jwt_svid.trust_bundles]]\ntrust_domain = \"td.example\"\nbundle_file = \"b.json\"\n";
        let path = dir.join("visado.toml");
        std::fs::write(&path, format!("{BASE}{tables}")).unwrap();
        let loaded = Config::load(&path);

        std::fs::write(dir.join("ca.pem"), "not a certificate").unwrap();
        let bad_ca = Config::load(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(loaded.is_ok());
        assert!(bad_ca.is_err());
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
