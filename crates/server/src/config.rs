//! The TOML configuration file.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use visado_chain_aat::{Policy, TrustAnchor, Verifier};
use visado_credentials::{Authenticator, JwtBundle, OAuthIssuer, WitIssuer, X509Bundle};
use visado_extauthz::GateConfig;
use visado_txn_token::Scope;
use wimsey_jose::{Jwk, PrivateJwk, VerifyingKey};

use crate::status::{Source, StatusRefresh};

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
    /// How far a DPoP proof's `iat` may be from now, either way, in seconds.
    #[serde(default = "default_dpop_iat_window")]
    pub dpop_iat_window: u64,
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
    #[serde(default)]
    pub act: Option<ActConfig>,
    #[serde(default)]
    pub chain_view: ChainViewConfig,
}

/// The chain view: recent decisions and their delegation chains, served on
/// the HTTP listener. It shows caller and principal identities, so it is off
/// by default and refuses a non-loopback `http_listen` unless
/// `allow_remote` is set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainViewConfig {
    #[serde(default)]
    pub enabled: bool,
    /// How many recent decisions to keep in memory. 0 keeps none.
    #[serde(default = "default_chain_view_capacity")]
    pub capacity: usize,
    /// Serve the view on a non-loopback `http_listen`.
    #[serde(default)]
    pub allow_remote: bool,
    /// `Host` values (without the port) the view answers. Others get 421,
    /// which keeps a DNS-rebound page from reading the view through the
    /// browser.
    #[serde(default = "default_chain_view_hosts")]
    pub allowed_hosts: Vec<String>,
}

impl Default for ChainViewConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: default_chain_view_capacity(),
            allow_remote: false,
            allowed_hosts: default_chain_view_hosts(),
        }
    }
}

const fn default_chain_view_capacity() -> usize {
    256
}

fn default_chain_view_hosts() -> Vec<String> {
    ["localhost", "127.0.0.1", "[::1]"]
        .map(str::to_owned)
        .to_vec()
}

/// The most decisions the chain view may keep.
pub const MAX_CHAIN_VIEW_CAPACITY: usize = 10_000;

/// What the server needs to serve the chain view.
#[derive(Debug)]
pub struct ChainView {
    pub capacity: usize,
    pub allowed_hosts: Vec<String>,
}

/// RFC 8693 `act` (actor) chains in the caller's access token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActConfig {
    /// Deny requests that carry no chain. Has no default, as for `[aat]`.
    pub required: bool,
    /// The most actors one `act` claim may name, the current one included.
    #[serde(default = "default_max_actors")]
    pub max_actors: usize,
    /// Maps an actor's `act.sub` to the caller identifier it must
    /// authenticate as, for issuers that name actors differently. Without an
    /// entry, `act.sub` must equal the caller identifier.
    #[serde(default)]
    pub actors: BTreeMap<String, String>,
}

const fn default_max_actors() -> usize {
    visado_chain_act::DEFAULT_MAX_ACTORS
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
    /// Token Status Lists for step 7. Without this section, a token with a
    /// `status` claim is denied (`asor.status_unknown`).
    #[serde(default)]
    pub status: Option<AsorStatusConfig>,
}

/// The Token Status Lists the gate holds for step 7
/// (draft-ietf-oauth-status-list-21).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsorStatusConfig {
    /// Keys trusted to sign Status List Tokens. A token with an `iss` must
    /// name the key's issuer.
    pub trust_anchors: Vec<AatAnchorConfig>,
    /// The lists. A token whose `status_list.uri` is not one of them is
    /// denied: the gate never fetches a URI a token names.
    pub lists: Vec<StatusListConfig>,
    /// How long a fetched list is trusted, in seconds, when its `ttl` is
    /// longer or absent.
    #[serde(default = "default_status_max_age")]
    pub max_age: u64,
    /// How often each list is fetched again, in seconds. Sooner when the
    /// held list would otherwise go stale first.
    #[serde(default = "default_status_refresh")]
    pub refresh: u64,
    /// The timeout of one HTTP fetch, in milliseconds.
    #[serde(default = "default_status_timeout_ms")]
    pub timeout_ms: u64,
}

/// One Status List Token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusListConfig {
    /// The list's URI, as tokens name it in `status_list.uri` and the list
    /// in `sub`.
    pub uri: String,
    /// Read the token from this file, at startup and at each refresh,
    /// instead of fetching `uri`.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

const fn default_status_max_age() -> u64 {
    visado_chain_asor::DEFAULT_STATUS_MAX_AGE.unsigned_abs()
}

const fn default_status_refresh() -> u64 {
    60
}

const fn default_status_timeout_ms() -> u64 {
    2000
}

/// The longest `max_age` for status lists: a day.
pub const MAX_STATUS_MAX_AGE: u64 = 86_400;

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
    /// Single keys, each in its own JWK file.
    #[serde(default)]
    pub keys: Vec<KeyFile>,
    /// A JWK set, such as a SPIRE WIT bundle. Read at startup.
    #[serde(default)]
    pub jwks_file: Option<PathBuf>,
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

const fn default_dpop_iat_window() -> u64 {
    60
}

/// The widest DPoP `iat` window accepted in configuration, in seconds.
/// RFC 9449 §11.1 expects seconds or minutes, and every proof is remembered
/// for this long.
pub const MAX_DPOP_IAT_WINDOW: u64 = 300;

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
    pub chain_view: Option<ChainView>,
    pub asor_status: Option<StatusRefresh>,
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
        if !(1..=MAX_DPOP_IAT_WINDOW).contains(&self.dpop_iat_window) {
            return Err(format!(
                "dpop_iat_window must be 1..={MAX_DPOP_IAT_WINDOW} seconds"
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
            if issuer.keys.is_empty() == issuer.jwks_file.is_none() {
                return Err(format!(
                    "wit_issuers {} needs exactly one of keys and jwks_file",
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
        self.validate_chains()?;
        self.validate_chain_view()?;
        let mut issuers = BTreeSet::new();
        for issuer in &self.oauth_issuers {
            if !issuers.insert(&issuer.issuer) {
                return Err(format!("duplicate oauth_issuers issuer {}", issuer.issuer));
            }
        }
        Ok(())
    }

    /// The chain sections: `[act]` itself and `required` across formats.
    fn validate_chains(&self) -> Result<(), String> {
        if let Some(act) = &self.act {
            if !(1..=visado_chain_act::MAX_ACTORS_LIMIT).contains(&act.max_actors) {
                return Err(format!(
                    "act.max_actors must be 1..={}",
                    visado_chain_act::MAX_ACTORS_LIMIT
                ));
            }
            if act
                .actors
                .iter()
                .any(|(actor, caller)| actor.is_empty() || caller.trim().is_empty())
            {
                return Err("act.actors needs non-empty actors and callers".into());
            }
            if self.oauth_issuers.is_empty() {
                return Err("[act] needs at least one oauth_issuers entry".into());
            }
        }
        // One request carries one chain, so a format with required = false
        // would let a request without any chain through even when another
        // format says a chain is required.
        let required: BTreeSet<bool> = [
            self.aat.as_ref().map(|c| c.required),
            self.asor.as_ref().map(|c| c.required),
            self.act.as_ref().map(|c| c.required),
        ]
        .into_iter()
        .flatten()
        .collect();
        if let Some(status) = self.asor.as_ref().and_then(|a| a.status.as_ref()) {
            status.validate()?;
        }
        if required.len() > 1 {
            return Err(
                "[aat], [asor] and [act] must all set the same required value: whether a request without a chain is denied applies to every format".into(),
            );
        }
        Ok(())
    }
    fn validate_chain_view(&self) -> Result<(), String> {
        let view = &self.chain_view;
        if !view.enabled {
            return Ok(());
        }
        if !self.http_listen.ip().is_loopback() && !view.allow_remote {
            return Err("[chain_view] shows caller and principal identities: it needs a loopback http_listen, or allow_remote = true".into());
        }
        if view.capacity > MAX_CHAIN_VIEW_CAPACITY {
            return Err(format!(
                "chain_view.capacity must be 0..={MAX_CHAIN_VIEW_CAPACITY}"
            ));
        }
        if view.allowed_hosts.is_empty()
            || view.allowed_hosts.iter().any(|h| {
                // The request Host loses its port before the comparison, so an
                // entry with one could never match. A colon is allowed only
                // inside a bracketed IPv6 literal such as [::1].
                let port = if h.starts_with('[') {
                    !h.ends_with(']')
                } else {
                    h.contains(':')
                };
                h.is_empty() || port || h.contains(['/', ' ', '@']) || h != &h.to_ascii_lowercase()
            })
        {
            return Err(
                "chain_view.allowed_hosts needs lowercase host names without a port".into(),
            );
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
            .with_signature_lifetime(self.max_signature_lifetime)
            .with_dpop_iat_window(self.dpop_iat_window);
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
            if let Some(file) = &issuer.jwks_file {
                let path = base.join(file);
                let set: JwkSet = read_json(&path)?;
                for (kid, verifying) in set.verifying_keys(&path)? {
                    wit = wit.with_key(kid, verifying);
                }
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
            || self.asor.as_ref().is_some_and(|a| a.required)
            || self.act.as_ref().is_some_and(|a| a.required);
        let act = self.act.map(ActConfig::verifier);
        let aat = self.aat.map(|c| c.verifier(base)).transpose()?;
        let (asor, asor_status) = match self.asor {
            Some(c) => {
                let (verifier, status) = c.verifier(base)?;
                (Some(verifier), status)
            }
            None => (None, None),
        };

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
                act,
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
            chain_view: self.chain_view.enabled.then_some(ChainView {
                capacity: self.chain_view.capacity,
                allowed_hosts: self.chain_view.allowed_hosts,
            }),
            asor_status,
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

impl ActConfig {
    fn verifier(self) -> visado_chain_act::Verifier {
        let mut verifier = visado_chain_act::Verifier::new().with_max_actors(self.max_actors);
        for (actor, caller) in self.actors {
            verifier = verifier.with_actor(actor, caller);
        }
        verifier
    }
}

impl AsorConfig {
    fn verifier(
        self,
        base: &Path,
    ) -> Result<(visado_chain_asor::Verifier, Option<StatusRefresh>), String> {
        let anchors = asor_anchors(base, &self.trust_anchors)?;
        if anchors.is_empty() || self.audiences.is_empty() {
            return Err("asor needs at least one trust anchor and one audience".into());
        }
        let verifier = visado_chain_asor::Verifier::new(anchors, self.audiences);
        let Some(status) = self.status else {
            return Ok((verifier, None));
        };
        let refresh = status.refresh(base)?;
        let verifier = verifier
            .with_status_lists(refresh.lists.clone())
            .with_status_max_age(refresh.max_age);
        Ok((verifier, Some(refresh)))
    }
}

impl AsorStatusConfig {
    /// Checked by `Config::validate`, before any file is read.
    fn validate(&self) -> Result<(), String> {
        if self.lists.is_empty() {
            return Err("asor.status.lists is empty".into());
        }
        let mut uris = BTreeSet::new();
        for list in &self.lists {
            if list.uri.trim().is_empty() || !uris.insert(&list.uri) {
                return Err(format!(
                    "asor.status.lists: {:?} is empty or listed twice",
                    list.uri
                ));
            }
            // A list fetched over plain http could be swapped for an older
            // one that still verifies.
            if list.file.is_none() && !is_https_or_loopback(&list.uri) {
                return Err(format!(
                    "asor.status.lists: {} needs an https uri (or loopback), or a file",
                    list.uri
                ));
            }
        }
        if !(1..=MAX_STATUS_MAX_AGE).contains(&self.max_age) {
            return Err(format!(
                "asor.status.max_age must be 1..={MAX_STATUS_MAX_AGE} seconds"
            ));
        }
        if !(1..self.max_age).contains(&self.refresh) {
            return Err("asor.status.refresh must be at least 1 and less than max_age".into());
        }
        if !(1..=self.refresh.saturating_mul(1000)).contains(&self.timeout_ms) {
            return Err("asor.status.timeout_ms must be positive and at most refresh".into());
        }
        Ok(())
    }

    /// Builds the lists and loads the file ones, so a bad file stops
    /// startup.
    fn refresh(self, base: &Path) -> Result<StatusRefresh, String> {
        let anchors = asor_anchors(base, &self.trust_anchors)?;
        if anchors.is_empty() {
            return Err("asor.status needs at least one trust anchor".into());
        }
        let refresh = StatusRefresh {
            lists: Arc::new(visado_chain_asor::MemoryStatusLists::new()),
            verifier: visado_chain_asor::StatusListVerifier::new(anchors),
            sources: self
                .lists
                .into_iter()
                .map(|list| {
                    let source = list
                        .file
                        .map_or(Source::Http, |file| Source::File(base.join(file)));
                    (list.uri, source)
                })
                .collect(),
            max_age: i64::try_from(self.max_age).map_err(|e| e.to_string())?,
            refresh: Duration::from_secs(self.refresh),
            timeout: Duration::from_millis(self.timeout_ms),
        };
        refresh.load_files()?;
        Ok(refresh)
    }
}

fn asor_anchors(
    base: &Path,
    anchors: &[AatAnchorConfig],
) -> Result<Vec<visado_chain_asor::TrustAnchor>, String> {
    anchors
        .iter()
        .map(|anchor| {
            let key = anchor_key(base, anchor)?;
            let trusted = visado_chain_asor::TrustAnchor::new(anchor.issuer.clone(), key);
            Ok(match &anchor.kid {
                Some(kid) => trusted.with_kid(kid.clone()),
                None => trusted,
            })
        })
        .collect()
}

fn anchor_key(base: &Path, anchor: &AatAnchorConfig) -> Result<VerifyingKey, String> {
    let jwk: Jwk = read_json(&base.join(&anchor.jwk_file))?;
    jwk.to_verifying_key()
        .map_err(|e| format!("{}: {e}", anchor.jwk_file.display()))
}

/// A JWK set as a SPIFFE bundle or a JWKS endpoint serves it.
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<SetKey>,
}

#[derive(Deserialize)]
struct SetKey {
    kid: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    #[serde(flatten)]
    jwk: Jwk,
}

impl JwkSet {
    /// Every key with its `kid`. A key without `alg` (SPIRE writes none) gets
    /// the one algorithm its type allows: `ES256` for P-256, `EdDSA` for
    /// Ed25519. Any other key, a missing or repeated `kid`, or an empty set
    /// fails, so a bundle is never trusted only in part.
    fn verifying_keys(self, path: &Path) -> Result<Vec<(String, VerifyingKey)>, String> {
        let err = |m: &str| format!("{}: {m}", path.display());
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for key in self.keys {
            if key
                .key_use
                .as_deref()
                .is_some_and(|u| u != "sig" && u != "wit-svid")
            {
                continue;
            }
            let kid = key.kid.ok_or_else(|| err("a key has no kid"))?;
            if !seen.insert(kid.clone()) {
                return Err(err(&format!("kid {kid} appears twice")));
            }
            let mut jwk = key.jwk;
            if jwk.alg.is_none() {
                jwk.alg = match (jwk.kty.as_str(), jwk.crv.as_str()) {
                    ("EC", "P-256") => Some("ES256".into()),
                    ("OKP", "Ed25519") => Some("EdDSA".into()),
                    _ => return Err(err(&format!("key {kid}: unsupported key type"))),
                };
            }
            let verifying = jwk
                .to_verifying_key()
                .map_err(|e| err(&format!("key {kid}: {e}")))?;
            out.push((kid, verifying));
        }
        if out.is_empty() {
            return Err(err("no signing keys"));
        }
        Ok(out)
    }
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
        assert!(parse("dpop_iat_window = 0").is_err());
        assert!(parse("dpop_iat_window = 3600").is_err());
        assert!(parse("dpop_iat_window = 10").is_ok());
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
    fn a_wit_issuer_takes_keys_or_a_jwks_file() {
        let issuer =
            |body: &str| format!("{BASE}[[wit_issuers]]\ntrust_domain = \"td.example\"\n{body}");
        let config: Config = toml::from_str(&issuer("jwks_file = \"b.json\"\n")).unwrap();
        assert!(config.validate().is_ok());
        let config: Config = toml::from_str(&issuer("")).unwrap();
        assert!(config.validate().is_err(), "neither");
        let both = "jwks_file = \"b.json\"\nkeys = [{ kid = \"k\", jwk_file = \"k.json\" }]\n";
        let config: Config = toml::from_str(&issuer(both)).unwrap();
        assert!(config.validate().is_err(), "both");
    }

    #[test]
    fn a_jwks_file_is_trusted_whole_or_not_at_all() {
        use super::JwkSet;
        use std::path::Path;
        let ec = serde_json::json!({"kty": "EC", "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"});
        let with = |extra: serde_json::Value| {
            let mut key = ec.clone();
            key.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            key
        };
        let keys = |keys: Vec<serde_json::Value>| -> Result<usize, String> {
            let set: JwkSet = serde_json::from_value(serde_json::json!({ "keys": keys })).unwrap();
            set.verifying_keys(Path::new("b.json")).map(|k| k.len())
        };
        // SPIRE's WIT bundle: kid, no alg, no use.
        assert_eq!(keys(vec![with(serde_json::json!({"kid": "a"}))]), Ok(1));
        // Keys for other SVID types in the same bundle are skipped.
        assert_eq!(
            keys(vec![
                with(serde_json::json!({"kid": "a"})),
                with(serde_json::json!({"kid": "b", "use": "x509-svid"})),
            ]),
            Ok(1)
        );
        assert!(keys(vec![]).is_err(), "empty");
        assert!(keys(vec![ec.clone()]).is_err(), "no kid");
        assert!(
            keys(vec![
                with(serde_json::json!({"kid": "a"})),
                with(serde_json::json!({"kid": "a"}))
            ])
            .is_err(),
            "repeated kid"
        );
        assert!(
            keys(vec![with(serde_json::json!({"kid": "a", "alg": "EdDSA"}))]).is_err(),
            "alg disagrees with the key"
        );
        assert!(
            keys(vec![
                serde_json::json!({"kid": "r", "kty": "RSA", "crv": "", "x": "", "n": "AQAB"})
            ])
            .is_err(),
            "unsupported key"
        );
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
    fn act_must_say_whether_a_chain_is_required() {
        let issuer =
            "[[oauth_issuers]]\nissuer = \"https://idp\"\naudience = \"a\"\njwks_file = \"j\"\n";
        assert!(toml::from_str::<Config>(&format!("{BASE}{issuer}[act]\n")).is_err());
        assert!(parse_tables(&format!("{issuer}[act]\nrequired = false\n")).is_ok());
        let config: Config =
            toml::from_str(&format!("{BASE}{issuer}[act]\nrequired = true\n")).unwrap();
        let act = config.act.unwrap();
        assert_eq!(act.max_actors, visado_chain_act::DEFAULT_MAX_ACTORS);
        assert!(act.actors.is_empty());
    }

    #[test]
    fn act_settings_are_checked() {
        let issuer =
            "[[oauth_issuers]]\nissuer = \"https://idp\"\naudience = \"a\"\njwks_file = \"j\"\n";
        let act = |extra: &str| parse_tables(&format!("{issuer}[act]\nrequired = true\n{extra}"));
        assert!(act("max_actors = 1\n").is_ok());
        assert!(act("max_actors = 32\n").is_ok());
        assert!(act("max_actors = 0\n").is_err());
        assert!(act("max_actors = 33\n").is_err());
        assert!(act("unknown = 1\n").is_err());
        assert!(
            act("[act.actors]\n\"agent-b-client\" = \"spiffe://td.example/agent-b\"\n").is_ok()
        );
        assert!(act("[act.actors]\n\"agent-b-client\" = \" \"\n").is_err());
        assert!(act("[act.actors]\n\"\" = \"spiffe://td.example/agent-b\"\n").is_err());
        // An act chain is read from an access token, so an issuer is needed.
        assert!(parse_tables("[act]\nrequired = true\n").is_err());
    }

    #[test]
    fn chain_formats_must_agree_on_required() {
        let issuer =
            "[[oauth_issuers]]\nissuer = \"https://idp\"\naudience = \"a\"\njwks_file = \"j\"\n";
        let tables = |aat: bool, asor: Option<bool>, act: Option<bool>| {
            let asor = asor.map_or(String::new(), |r| {
                format!("[asor]\naudiences = [\"a\"]\ntrust_anchors = []\nrequired = {r}\n")
            });
            let act = act.map_or(String::new(), |r| format!("[act]\nrequired = {r}\n"));
            let t = format!(
                "{issuer}[aat]\naudiences = [\"a\"]\ntrust_anchors = []\nrequired = {aat}\n{asor}{act}"
            );
            parse_tables(&t)
        };
        assert!(tables(true, None, Some(true)).is_ok());
        assert!(tables(false, Some(false), Some(false)).is_ok());
        let err = tables(true, None, Some(false)).unwrap_err();
        assert!(err.contains("same required value"), "{err}");
        assert!(tables(false, Some(true), None).is_err());
        assert!(tables(true, Some(true), Some(false)).is_err());
    }

    #[test]
    fn the_chain_view_is_off_by_default() {
        let config: Config = toml::from_str(BASE).unwrap();
        assert!(!config.chain_view.enabled);
        assert_eq!(config.chain_view.capacity, 256);
        parse_tables("[chain_view]\nenabled = true").unwrap();
    }

    #[test]
    fn chain_view_hosts_have_no_port() {
        let parse = |hosts: &str| {
            let config: Config = toml::from_str(&format!(
                "{BASE}\n[chain_view]\nenabled = true\nallowed_hosts = [{hosts}]"
            ))
            .map_err(|e| e.to_string())?;
            config.validate()
        };
        parse(r#""localhost", "127.0.0.1", "[::1]""#).unwrap();
        assert!(parse(r#""localhost:8080""#).is_err());
        assert!(parse(r#""[::1]:8080""#).is_err());
        assert!(parse(r#""::1""#).is_err());
    }

    #[test]
    fn the_chain_view_stays_on_loopback_unless_allowed() {
        let remote = "http_listen = \"0.0.0.0:8080\"";
        let parse_remote = |view: &str| {
            let config: Config =
                toml::from_str(&format!("{remote}\n{BASE}\n{view}")).map_err(|e| e.to_string())?;
            config.validate()
        };
        parse_remote("").unwrap();
        parse_remote("[chain_view]\nenabled = false").unwrap();
        let err = parse_remote("[chain_view]\nenabled = true").unwrap_err();
        assert!(err.contains("allow_remote"), "{err}");
        parse_remote("[chain_view]\nenabled = true\nallow_remote = true").unwrap();
    }

    #[test]
    fn chain_view_settings_are_checked() {
        assert!(parse_tables("[chain_view]\nenabled = true\ncapacity = 0").is_ok());
        assert!(parse_tables("[chain_view]\nenabled = true\ncapacity = 10001").is_err());
        assert!(parse_tables("[chain_view]\nenabled = true\nallowed_hosts = []").is_err());
        assert!(
            parse_tables("[chain_view]\nenabled = true\nallowed_hosts = [\"Localhost\"]").is_err()
        );
        assert!(
            parse_tables("[chain_view]\nenabled = true\nallowed_hosts = [\"visado.internal\"]")
                .is_ok()
        );
        assert!(parse_tables("[chain_view]\nenabled = true\nport = 1").is_err());
    }

    fn asor_status(status: &str) -> String {
        format!(
            "[asor]\naudiences = [\"a\"]\ntrust_anchors = []\nrequired = true\n\
             [asor.status]\ntrust_anchors = []\n{status}"
        )
    }

    #[test]
    fn asor_status_settings_are_checked() {
        let list = "lists = [{ uri = \"https://s.example/1\" }]\n";
        parse_tables(&asor_status(list)).unwrap();
        let config: Config = toml::from_str(&format!("{BASE}{}", asor_status(list))).unwrap();
        let status = config.asor.unwrap().status.unwrap();
        assert_eq!(
            (status.max_age, status.refresh, status.timeout_ms),
            (300, 60, 2000)
        );
        parse_tables(&asor_status(
            "lists = [{ uri = \"http://127.0.0.1:8080/1\" }]\n",
        ))
        .unwrap();
        parse_tables(&asor_status(
            "lists = [{ uri = \"http://s.example/1\", file = \"l.jwt\" }]\n",
        ))
        .unwrap();
        for bad in [
            "lists = []\n",
            "lists = [{ uri = \"\" }]\n",
            "lists = [{ uri = \"http://s.example/1\" }]\n",
            "lists = [{ uri = \"https://s.example/1\" }, { uri = \"https://s.example/1\" }]\n",
            &format!("{list}max_age = 0\n"),
            &format!("{list}max_age = 86401\n"),
            &format!("{list}refresh = 300\n"),
            &format!("{list}refresh = 0\n"),
            &format!("{list}timeout_ms = 0\n"),
            &format!("{list}timeout_ms = 60001\n"),
            &format!("{list}ttl = 1\n"),
        ] {
            assert!(parse_tables(&asor_status(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn asor_status_files_must_verify_at_startup() {
        use visado_testkit::{
            ASOR_ISSUER, STATUS_LIST_ISSUER, STATUS_LIST_URI, asor_anchor_key, status_list_key,
            status_list_lst, status_list_token,
        };
        use wimsey_jose::Jwk;
        let dir = std::env::temp_dir().join(format!("visado-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/local/keys/txn-signing.private.jwk.json");
        std::fs::copy(key, dir.join("k.json")).unwrap();
        let jwk = |key: &wimsey_jose::SigningKey| {
            serde_json::to_string(&Jwk::from_verifying_key(&key.verifying_key())).unwrap()
        };
        std::fs::write(dir.join("asor.json"), jwk(&asor_anchor_key())).unwrap();
        std::fs::write(dir.join("status.json"), jwk(&status_list_key())).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let list = |sub: &str| {
            status_list_token(
                &serde_json::json!({ "alg": "Ed25519", "typ": "statuslist+jwt" }),
                &serde_json::json!({
                    "sub": sub, "iat": now, "exp": now + 3600,
                    "status_list": { "bits": 1, "lst": status_list_lst(1, &[0, 1]) },
                }),
            )
        };
        let tables = format!(
            "[asor]\naudiences = [\"a\"]\nrequired = true\n\
             trust_anchors = [{{ issuer = \"{ASOR_ISSUER}\", jwk_file = \"asor.json\" }}]\n\
             [asor.status]\n\
             trust_anchors = [{{ issuer = \"{STATUS_LIST_ISSUER}\", jwk_file = \"status.json\" }}]\n\
             lists = [{{ uri = \"{STATUS_LIST_URI}\", file = \"list.jwt\" }}]\n"
        );
        let path = dir.join("visado.toml");
        std::fs::write(&path, format!("{BASE}{tables}")).unwrap();
        let missing = Config::load(&path).err();
        std::fs::write(dir.join("list.jwt"), list(STATUS_LIST_URI) + "\n").unwrap();
        let loaded = Config::load(&path).map(|l| l.asor_status.is_some());
        std::fs::write(dir.join("list.jwt"), list("https://other.example/1")).unwrap();
        let other = Config::load(&path).err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(missing.is_some_and(|e| e.contains("could not be fetched")));
        assert_eq!(loaded, Ok(true));
        assert!(other.is_some_and(|e| e.contains("sub is not the uri")));
    }

    #[test]
    fn pdp_bearer_needs_tls() {
        let remote = BASE.replace("http://127.0.0.1:8181", "http://pdp.example");
        let config: Config = toml::from_str(&format!("{remote}bearer_env = \"T\"\n")).unwrap();
        assert!(config.validate().is_err());
    }
}
