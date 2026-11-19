# Dex ID-JAG / Resource AS / OSS IdPs / SPIRE WIT: research (2026-11-18)

Dex ID-JAG issuance (#4611, merged 2026-11-11) is not in any Dex release. The latest is v2.46.1 (2026-10-21), with no newer tags or RCs, so it needs a master build. Two follow-ups merged on 2026-11-12: #5149 and #5150.

Dex only issues ID-JAGs. Its DEP lists the Resource AS role (RFC 7523) as a non-goal.

Keycloak's experimental Resource AS (receiver) for ID-JAG first shipped in 26.7.0 (2026-07-09), not 26.6. 26.6 only has the generic RFC 7523 JWT Authorization Grant. The latest Keycloak is 26.8.2. Keycloak is the most realistic OSS Resource AS for a demo.

SPIRE v1.16.0 (2026-11-05) has experimental WIT-SVIDs (`experimental { enable_wit_svids = true }` on both server and agent), served by the Workload API `FetchWITSVID`. go-spiffe #415 (WPT minting) is still an open draft.

## 1. Dex #4611 (issuance)

Sources: PR body and diff, `gh pr diff 4611 --repo dexidp/dex`.

### Config

- `oauth2.tokenExchange.tokenTypes`: listing `urn:ietf:params:oauth:token-type:id-jag` enables ID-JAG issuance. Other allowed values are `...:id_token` and `...:access_token`, which have no effect. Any other value is a config error.
- `expiry.idJAGTokens`: Go duration. Default 5m.
- `staticClients[].idJAGPolicies: {allowedAudiences: [...], allowedScopes: [...]}`
  - A client without a policy is denied.
  - Public clients cannot have a policy (config validation).
  - Policies exist only on static clients. DB/gRPC clients cannot get ID-JAGs. CEL-based policies are future work.
- The token-exchange grant must be enabled, or the server refuses to start.
- Discovery advertises `identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"]`.
- `id_jag_signing_alg_values_supported` was removed (it is OPTIONAL in the draft).
- Metrics: `dex_id_jag_requests_total{result}`, `dex_id_jag_policy_rejections_total{reason}`, `dex_id_jag_scope_modifications_total`.

### Request (POST /token)

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`
- `subject_token_type=urn:ietf:params:oauth:token-type:id_token`: the only accepted type. It must be a Dex ID token issued to this same client (aud/azp is checked). Dex access tokens are ID-token-shaped and verify too, but the type string must still be id_token. Logout tokens are rejected.
- `audience`: exactly one value. Must appear in some policy, otherwise `invalid_target`. Must be in this client's policy, otherwise `access_denied` (400).
- `connector_id`: REQUIRED. This is a Dex-specific parameter and must match the connector encoded in the subject token's `sub`.
- `resource`: at most 1. Must be an absolute URI with no fragment, otherwise `invalid_target`.
- `scope`: intersected with `allowedScopes`. If some scopes were requested and none are allowed: `invalid_scope`.
- Client authentication with a secret is required. A public client or one without a secret gets `invalid_client` (401).
- If the session has ended for a session-bound client, the request is rejected.
- Errors fixed after #4611:
  - #5150: a bad subject_token_type returns `invalid_request`.
  - #5149: `requested_token_type` is checked before the connector is called.

### Response

`access_token`=`<ID-JAG>`, `issued_token_type`=id-jag, `token_type`=`N_A`, `expires_in`. `scope` is returned only when it was reduced. No refresh token.

### ID-JAG

- Header: `typ: oauth-id-jag+jwt`. Signed by Dex's normal signer (local rotating keys or Vault), so it is verifiable through Dex `jwks_uri` (/keys). The algorithm is the signer's (RS256 by default).
- Claims:
  - `iss`: Dex issuer.
  - `sub`: the Dex ID-token sub, an opaque base64 protobuf of user ID and connector ID.
  - `aud`: a string, not an array.
  - `client_id`: the Dex client ID.
  - `jti`: UUID.
  - `iat`, `exp`.
  - Optional: `resource`, `scope` (space-joined), and `email` (only if `email_verified`).
- Dex's own verifiers refuse any token whose `typ` is set and is not `JWT` (#5150). So an ID-JAG cannot be used at userinfo, introspection or `id_token_hint`.

### Deviations from / gaps vs draft-06 (latest, 2026-10-31)

- No SAML2 `subject_token` (the draft says the IdP MUST accept ID Token or SAML). No refresh_token subject (a MAY in the draft).
- No `authorization_details`, `actor_token`/`act`, `tenant`, `aud_tenant`, `aud_sub`, `sub_id`, `auth_time`, `acr` or `amr`. No `cnf` / DPoP binding.
- `connector_id` is a Dex-only extra required parameter.
- The resource-vs-audience check is limited: Dex does not verify that `resource` is governed by `audience`.
- Single resource only.
- No step-up, and no server-side `jti` tracking.
- `sub` is Dex's opaque encoding, which the Resource AS must map. Inference: this matters for Keycloak's user linking.

## 2. Resource AS requirements (draft-06 §4.4, RFC 7523)

- `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` (or `jwt-dpop` when bound), with `assertion` set to the ID-JAG.
- The client SHOULD be authenticated. With neither client auth nor a sender-constrained ID-JAG, reject with `invalid_client`.
- Validate:
  - `typ == oauth-id-jag+jwt`.
  - `iss` is a trusted IdP; keys come from its jwks_uri, and the alg must be allowed.
  - `aud` is exactly the Resource AS's own issuer.
  - `client_id` equals the authenticated client.
  - `exp`, plus `jti` replay tracking.
  - `tenant`, if the issuer is multi-tenant.
  - `cnf`, if present.
  - `resource` is governed by this AS.
- Failures return `invalid_grant`. A valid ID-JAG for an unauthorized user returns `access_denied`.
- Scopes may be narrowed. SHOULD NOT issue a refresh token.
- Metadata: `authorization_grant_profiles_supported` includes `urn:ietf:params:oauth:grant-profile:id-jag`.
- RS256 is MTI. ES256 SHOULD be supported.

### Keycloak as Resource AS

- Version: experimental receiver in 26.7.0 (release notes say "Keycloak provides partial experimental support... implements only the receiving authorization server role"). Enable with `--features=identity-assertion-jwt`.
- Setup:
  - Register Dex as an IdP with `jwtAuthorizationGrantEnabled=true`, `jwtAuthorizationGrantAssertionReuseAllowed=false` and `jwtAuthorizationGrantMaxAllowedAssertionExpiration=300`.
  - On the client, set `oauth2.jwt.authorization.grant.enabled=true` and `oauth2.jwt.authorization.grant.idp=<alias>`.
  - Pre-link users via a federated identity whose `userId` = the ID-JAG `sub`. There is no JIT provisioning; otherwise the error is "User not found".
- Code (`IDJWTAuthorizationGrantValidator`):
  - Branches on the typ header.
  - Requires the `client_id` claim to equal the authenticating client's clientId.
  - Requires `iat`.
  - Forces no reuse (jti).
  - Validates audience against the configured allowed audiences.
  - The client must be confidential.
- Demo implications (inference):
  - The Dex static client `id` must equal the Keycloak client `clientId`.
  - Dex `allowedAudiences` should be the Keycloak realm issuer URL.
  - Dex's default 5m TTL fits the 300s max.
- The guide still says it is based on draft-01. Still open: issuer side (#48818, PR #49998), the `authorization_grant_profiles_supported` metadata (#54677), and promotion to preview (#49464).

### Other OSS Resource AS options

- Nothing else I found has ID-JAG-aware validation (typ, client_id binding).
- Generic RFC 7523 grants (e.g. Ory Hydra's jwt-bearer trust, or Keycloak 26.6's JWT Authorization Grant) would accept the JWT but skip the ID-JAG-specific checks. That is inference; I did not test them.

### Should visado be the Resource AS / Txn-Token Service? (my opinion, no source)

- Don't make visado the Resource AS for the demo. The Resource AS is the SaaS app's own authorization server, and Keycloak 26.7+ already covers it. That keeps the trust boundary obvious: Dex in domain A, Keycloak in domain B.
- visado makes more sense as:
  - the ID-JAG client / requester (the agentgateway model), and/or
  - the PEP that checks Keycloak access tokens and then mints internal Txn-Tokens.
- A Txn-Token Service inside a gateway is a reasonable choice for a demo, but it merges the PEP and the token issuer. Pulling it out later costs little if it sits behind a narrow interface.

## 3. Other IdPs: ID-JAG issuance

- Keycloak: issuance is not released. Issue #48818 and PR #49998 (issuer at token exchange; audience = clientId of the Resource AS client; no `actor_token`/`resource`) are both open. Docs issue #54330 is open. Umbrella #43971 is milestoned 27.0.
- Casdoor: issuance is implemented.
  - #5996 closed 2026-10-29; commit 668c4d7b is included in v4.27.1+ (latest v4.29.0).
  - `typ oauth-id-jag+jwt`.
  - Claims: iss, sub, email, aud, client_id, resource, scope, jti, iat, exp (5m).
  - Policy is defined through Casdoor Permissions and is closed by default.
  - Not yet supported: SAML, discovery metadata, per-app TTL.
- Authentik: PR #26973 "providers/oauth2: add id-jag" is open. Issue #25542 is open; #27759 was closed and points to #26973. Not released.
- Zitadel: no ID-JAG issue or PR found. Token exchange issues exist (#7211, #13076).
- Ory Hydra: no ID-JAG issue found. RFC 8693 is still open (#1218).
- Authelia: no ID-JAG issue found. RFC 8693 is open (#2694).

## 4. SPIRE v1.16.0 WIT-SVID

- Enable: `experimental { enable_wit_svids = true }` in both the server and agent config.
  - Server options: `wit_issuer` (sets `iss`; omitted if empty), which goes inside the `experimental` block (v1.16.0 rejects it at the `server` level as unknown configuration), and `default_wit_svid_ttl` (1h).
  - Agent option: `wit_svid_cache_max_size` (1000).
  - Per-entry WIT TTL (#7302).
  - The `spire` UpstreamAuthority publishes WIT keys for nested setups.
  - When disabled, the WIT APIs return Unimplemented.
- Token:
  - Header: `typ: wit+jwt`, plus `kid`.
  - Claims: `sub` (SPIFFE ID), `exp`, `iat`, `cnf.jwk` (a public key with `alg`), and optional `iss`.
  - No `jti`. No `aud`; go-spiffe rejects a WIT that has one.
  - This matches draft-ietf-wimse-workload-creds-03: sub, exp and cnf are required; iss is RECOMMENDED; jti is optional.
- Workload API:
  - `FetchWITSVID(WITSVIDRequest{spiffe_id})` streams `WITSVID{spiffe_id, wit_svid (JWS), wit_svid_key (JWK private key), hint}`. The agent generates the key; the workload does not bring its own.
  - `FetchWITBundles` streams JWKS documents keyed by trust domain.
  - CLI: `spire-agent api fetch wit [-spiffeID]`. With `-output json` it prints the WIT-SVIDs and the bundles. The private key JWK and the bundle keys carry no `alg`; the key in the WIT's `cnf.jwk` does (`ES256` by default). Checked against v1.16.0 in `deploy/lab`.
  - Agent rate limits: `fetch_wit_svid`, `fetch_wit_bundles`.
- go-spiffe:
  - `exp/svid/witsvid` (parse/verify, typ check, cnf.jwk extraction), `exp/bundle/witbundle` and `workloadapi/witsource.go` exist on main.
  - PR #415 "Add exp/witwpt with WPT minting and policy helpers" is an open draft, last updated 2026-08-24, so visado has to verify WPTs (draft-ietf-wimse-wpt) itself for now.
