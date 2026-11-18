# Spec requirements checklist (as of 2026-11-18)

Target revisions, checked on datatracker: txn-tokens -11 (2026-07-30, awaiting WG write-up), AIMS -01 (2026-11-02, Informational, WG doc), ID-JAG -06 (2026-10-31), identity-chaining -17 (2026-07-19, RFC Ed Queue), AuthZEN Authorization API 1.0 Final (OIDF approval announcement dated 2026-01-12).

For txn-tokens, ID-JAG and chaining, I read the published draft text (-11, -06, -17) and confirmed it matches the latest revision on datatracker.

## 1. Transaction Tokens (draft-ietf-oauth-transaction-tokens-11)

### JWT format (§9)

- [ ] Header `typ` MUST be `txntoken+jwt` (§9.1). `kid` SHOULD be present
- [ ] REQUIRED claims: `iat`, `aud`, `exp`, `txn` (RFC 8417 §2.2), `sub`, `scope`, `req_wl` (§9.2)
  - `aud` MUST identify the Trust Domain. Other domains MUST NOT accept the token
  - `sub` MUST be unique within the aud domain. It is not tied to `iss`
- [ ] RECOMMENDED claims: `tctx` (immutable authorization details) and `rctx` (environment context, e.g. `req_ip`, `authn`, `transport`)
  - In -11 the claim is `rctx`. There is no `req_ctx` claim. The only remaining `req_` names are `req_wl` and the request parameters `request_context` / `request_details`
- [ ] `iss` is OPTIONAL. It identifies the issuer when the signing key is not known in advance (§13.16)
- [ ] Recipients MUST ignore claims they do not understand (§9.2)

### TTS request (§11.1), RFC 8693 profile

- [ ] Requests to a remote TTS over HTTP MUST use RFC 8693 (§5.1, §11)
- [ ] Required parameters:
  - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
  - `audience`: the Trust Domain name
  - `scope`: the purpose
  - `requested_token_type=urn:ietf:params:oauth:token-type:txn_token`
  - `subject_token` and `subject_token_type`
- [ ] RECOMMENDED parameters: `request_context` (JSON → `rctx`) and `request_details` (JSON → `tctx`), sent form-urlencoded
- [ ] `subject_token_type` (§11.2):
  - Any type from RFC 8693 §3 is allowed except refresh_token
  - `urn:ietf:params:oauth:token-type:self_signed` (§11.2.1): a JWT that MUST contain `iss` = requesting workload, `sub`, `aud` = TTS ID (the TTS SHALL check it), `iat`, `exp`
  - `urn:ietf:params:oauth:token-type:unsigned_json` (§11.2.2): `sub` MUST be present
  - Custom URNs are allowed
- [ ] Processing (§11.3), all MUST:
  - Client authn and authorization
  - Validation of the subject_token, including the signature if signed
  - Uniqueness of `sub`
  - Setting `iat`, `aud`, `exp`, `txn`
  - Evaluation of scope
- [ ] MUST NOT issue from an expired subject_token (§6)
- [ ] Response (§11.4): `token_type=N_A`, `access_token` = the Txn-Token, `issued_token_type=...:txn_token`. `refresh_token` MUST NOT be returned. Errors use the RFC 6749 §5.2 format
- [ ] Mutual authentication MUST be used (§11.5). Asymmetric methods (RFC 7523, RFC 8705, WIMSE mTLS, HTTP-sig, WPT) SHOULD be used
- [ ] Exactly one logical TTS per Trust Domain (MUST, §10)

### Propagation (§12)

- [ ] Header `Txn-Token:` (MUST), carrying exactly one token. The `Authorization` header MUST NOT be used
- [ ] The recipient MUST validate three things: the signature, that `aud` is its own domain, and that the token has not expired (§12.2)
- [ ] Outbound calls MUST carry the received token unmodified

### Security (§13)

- [ ] The lifetime MUST be short (§13.1). Replay is detected with `txn`. A single-use check is optional (§13.2)
- [ ] A Txn-Token MUST NOT embed an access token (§13.4)
- [ ] scope MUST NOT exceed the subject_token's scope (§13.6). If the subject_token's scope is unknown, the request MUST be rejected (§13.14)
- [ ] TTS configuration MUST come from a trusted source (§13.7). The TTS MUST be authenticated (§13.9)
- [ ] A Txn-Token MUST NOT be used as an authn credential (§13.12) or as an OAuth AT (§13.13)
- [ ] Replacement (§13.15), when a Txn-Token is passed as the subject_token:
  - Narrowing and adding values MAY happen. Broadening MUST NOT
  - `txn`, `sub`, `aud` MUST NOT change
  - An expired token MUST NOT be replaced
  - The lifetime MAY be extended. If it is, the number of replacements SHOULD be limited
  - The call chain MUST be preserved, but the method is out of scope
- [ ] A Txn-Token MUST NOT be logged in full (§15.2). Log a hash or the payload without the signature
- [ ] Identity-chaining SHOULD be used across domains (§14)

### Recent changes

- -11: history typo fix only
- -10: editorial changes to claim descriptions
- -09 (changes from -08):
  - Added a TTS issuance policy section
  - Added cross-domain guidance
  - Added token revocation (introspection) to the considerations
  - Removed the `rctx`-specific claim definitions and renamed the section to Request Context
  - "Clarified" how `req_wl` represents multiple workloads
  - Changed request parameters and body claims from OPTIONAL to RECOMMENDED
- -08: made `iss` always OPTIONAL
- Earlier:
  - Renamed `purpose` to `scope`
  - Renamed `azd` to `tctx`
  - Removed the replacement text from the body and consolidated it into §13.15

### Ambiguities

- In the §9.2 claim list, `tctx` points to §9.2.2 and `rctx` to §9.2.3, but the sections are the other way round
- `req_wl`:
  - The history says the multiple-workload representation was clarified, but the body only says "A string value"
  - The IANA registration (§16.2) lists only `tctx` and `rctx`, not `req_wl`
- The method for preserving the call chain on replacement is undefined. visado has to choose between concatenating `req_wl` and its own claim
- The `audience` parameter (Trust Domain) and the self-signed JWT `aud` (TTS ID) are different values
- How to compare scopes for "scope ≤ subject_token's scope" is undefined. §9.2.1 allows internal scopes to mean something different from external ones, which sits awkwardly with that rule
- No type URN exists for a WIT or WPT as the subject_token, so it would be a custom URN

## 2. AIMS (draft-ietf-wimse-aims-01, Informational)

### Components (§5)

- 8 layers: Identifier → Credentials → Provisioning → Authentication → Authorization → Observability/Remediation → Policy → Compliance
- A conceptual model, not a protocol
- Roles:
  - Agent (= workload, §4)
  - LLM
  - Tools/Services/Resources
  - User/System (+ other Agents)
  - IdP, AS/RS, TTS, external PDP (§10.4)
  - posture verifier (§8)
  - SSF receivers and monitoring systems (§11)

### Specs combined per flow

| AIMS § | flow | specs combined |
| --- | --- | --- |
| §6 | identifier | WIMSE ID. Exactly one per agent (MUST). May be a SPIFFE ID (MAY) |
| §7–8 | credential | WIT/WIC (WIMSE-CRED), X.509-SVID / JWT-SVID / WIT-SVID. Short-lived (SHOULD), `exp` required (MUST). LLM access to credentials MUST NOT be allowed |
| §9.1 / §9.2 | authentication | mTLS / WPT (`wth`) or WIMSE HTTP-sig (RFC 9421). Relay and replay considerations are MUST |
| §9.3 | long-running session | Re-validate on expiry. WPT per message |
| §10.2–10.5 | OAuth | authorization code and client credentials. Client authn via RFC 7523 / RFC 8705 / OAuth-SPIFFE. Users use a phishing-resistant method (SHOULD) |
| §10.4 | policy | AuthZEN. The token is one input to the decision. Sender-constrained (mTLS or DPoP) |
| §10.6 / §10.9 | internal propagation | Txn-Token and RFC 8693. Forwarding the AT is an anti-pattern |
| §10.7 | cross-domain | identity-chaining (SHOULD), ID-JAG, Txn-Token assertion grant |
| §10.8 | HITL | CIBA. A local UI confirmation alone MUST NOT count as authorization. Bind to the AS grant (MUST) |
| §10.11 | discovery | RFC 8414, RFC 9728, CIMD, RFC 7591 |
| §11 | monitoring and revocation | SSF / CAEP / RISC / WISE. Enforce on receiving a revocation (MUST). An invalidated cache MUST NOT be used |

### Normative-ish parts

- Uppercase MUST/SHOULD appear in §6, §7, §8, §9.2.3, §10.x, §11, §13
- §1–5, §9.1, §9.3, §14–16 are descriptive only
- The whole document is Informational, so it reads as a recommended architecture, not as conformance requirements

### Audit (§11)

- Audit log: durable and tamper-evident (MUST)
- Minimum fields (MUST):
  - authenticated agent ID
  - delegating subject
  - resource/tool
  - action and decision
  - timestamp and correlation ID
  - posture/risk state
  - remediation/revocation and its cause
- Reconstruction of the execution chain (SHOULD)
- Log tokens by ID or hash, not in full (§10.10)

### PR #176 (ietf-wg-wimse/draft-ietf-wimse-aims)

- Adds 5 paragraphs on "correlation and user identifiers in delegation chains" to §10.10 Privacy
- Status: open (created 2026-11-09, updated 11-17; reportedly to be settled at the 11-18 session)
- Points:
  - Claims transcription (chaining §2.5) may emit a different subject ID outside the domain
  - The mapping is kept in the audit record of the AS that did the transcription, not in the token
  - The subject ID is the same across all hops within a domain and may change only when crossing domains
- The PR says it adds "no new normative text", but it contains a MUST sentence (the same as an existing §10.10 sentence)
- Wording is not final

### What AIMS does not have

- It defines neither the `act` claim nor agent→agent delegation chains
- visado takes delegation chain validation from a separate draft (e.g. asor agent-delegation-chain)

### What the reference implementation should demonstrate (inference)

1. The agent ID is a single WIMSE/SPIFFE ID, verifiable via WIT+WPT, HTTP-sig or mTLS
2. An external AT or an ID-JAG-derived AT is exchanged for a Txn-Token and propagated downstream in the `Txn-Token` header (the AT is not forwarded)
3. scope only narrows, for both Txn-Token and chaining
4. The AuthZEN PDP is queried with subject=agent (the delegating user goes in properties or context), and a deny stops the request
5. Cross-domain uses ID-JAG / chaining
6. A tamper-evident audit record (e.g. a hash chain) holds the 7 items from §11, with `txn` as the correlation ID
7. (Optional) Caches are discarded on a CAEP revocation, and step-up uses CIBA

## 3. ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-06)

### Token exchange at the IdP (§4.3)

- [ ] `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`
- [ ] `audience`: the Resource AS issuer, exactly one (multiple → `invalid_request`, unknown → `invalid_target`, §4.3.3)
- [ ] `resource`: RECOMMENDED. If obtained from PRM, it MUST be sent unmodified
- [ ] `scope` and `authorization_details` are optional. scope has RS-side meaning, not OIDC scope meaning
- [ ] `subject_token`: the IdP MUST accept an ID Token (`...:id_token`) or SAML (`...:saml2`) and MAY accept an RT (`...:refresh_token`)
- [ ] `actor_token` is accepted, but no processing rules are defined (§9.10)
- [ ] IdP validation:
  - Client authn MUST succeed, otherwise `invalid_client`
  - The subject_token is actually of the stated type
  - The ID Token `aud` matches the client_id
  - Reject if `typ` is a different kind (e.g. `at+jwt`)
  - The granted resource / scope / authorization_details MUST go into claims
- [ ] Response: `issued_token_type=...:id-jag`, `token_type=N_A`. If scope differs from the request, return scope

### Claims (§3.1)

- Header `typ` MUST be `oauth-id-jag+jwt`
- REQUIRED: `iss`, `sub`, `aud` (the RS-AS issuer), `client_id` (the client ID at the RS-AS), `jti`, `exp`, `iat`
- OPTIONAL: `resource`, `scope`, `authorization_details`, `act`, `tenant`, `auth_time`, `acr`, `amr`, `aud_tenant`, `aud_sub`, `email`, `sub_id`, `cnf`
- A multi-tenant issuer MUST include `tenant` (§6.1)
- `sub` MUST be the same for the same RS-AS regardless of client (§5.2)

### JWT bearer grant at the RS-AS (§4.4)

- [ ] `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, or `...:jwt-dpop` when DPoP-bound
- [ ] `assertion` = the ID-JAG
- [ ] A request with neither client authn nor sender-constraint MUST be rejected with `invalid_client`
- [ ] Validation (§4.4.1), in addition to RFC 7521 §5.2:
  - `typ`
  - trusted `iss`
  - `aud` is its own issuer (if an array, exactly one element)
  - `client_id` MUST match the authenticated client
  - If multi-tenant, check `tenant`
  - If `cnf` is present, check PoP: DPoP uses `jkt`, mTLS uses `x5t#S256`. Reject if unsupported
  - `resource` is under its own jurisdiction
- [ ] Metadata:
  - RS-AS: list `urn:ietf:params:oauth:grant-profile:id-jag` in `authorization_grant_profiles_supported`, and then `grant_types_supported` MUST include jwt-bearer
  - IdP: list id-jag in `identity_chaining_requested_token_types_supported`. If `id_jag_signing_alg_values_supported` is published, it MUST include RS256
- [ ] The same ID-JAG MUST NOT be reused at a different downstream RS-AS (§9.4)
- [ ] Changes in -06: subject token validation errors changed from `invalid_grant` to `invalid_request`, and the draft explains why `access_denied` is used
- [ ] Changes in -05: added jwt-dpop, mTLS binding, single audience, `invalid_target`, and more

### MCP Enterprise-Managed Authorization

Extension `io.modelcontextprotocol/enterprise-managed-authorization`, spec 2026-07-28.

- It references ID-JAG -04
- Additional requirements:
  - `audience` MUST be the MCP AS issuer
  - If `resource` is included, it MUST be the MCP Server's RFC 9728 resource ID and MUST also go in the ID-JAG `resource` claim
  - The AT MUST be audience-restricted to the MCP Server
  - Discovery uses `authorization_grant_profiles_supported`
  - An unregistered client may use a CIMD URL as its client_id
  - The client declares the extension as a capability
  - The client must not redirect to the MCP AS authorization endpoint
- No mention of DPoP
- The -06 changes (error codes, jwt-dpop) are not reflected on the MCP side

## 4. Identity Chaining (draft-ietf-oauth-identity-chaining-17, RFC Ed Queue)

- [ ] Token exchange at the A-AS: either `resource` (the B-AS URI) or `audience` (a logical name) is REQUIRED. Unknown values, or values policy does not allow, MUST be rejected per RFC 8693 §2.2.2 (§2.3.1–2)
- [ ] The `aud` of the returned grant MUST identify the B-AS. A single aud is RECOMMENDED (§2.3.3)
- [ ] The B-AS MUST validate per RFC 7523 §3, §3.1, and MUST match aud against its token endpoint or issuer. If the subject cannot be identified, it MUST reject (§2.4.2)
- [ ] The B-AS SHOULD NOT issue RTs (§5.4)
- [ ] Replay mitigations to evaluate: short lifetimes, single use, client authn (§5.5)
- [ ] Metadata: `identity_chaining_requested_token_types_supported` (§3)
- [ ] Claims transcription (§2.5): either AS can add, change or remove claims. The representation format is undefined. No scope escalation

## 5. AuthZEN Authorization API 1.0 (Final)

- [ ] Evaluation `POST /access/v1/evaluation` (§6)
  - Request:
    - `subject{type,id}`: REQUIRED
    - `resource{type,id}`: REQUIRED
    - `action{name}`: REQUIRED
    - `properties` and `context`: optional
  - Response: `{decision:bool, context?}`
  - On `false`, the PEP MUST NOT proceed
  - A deny is HTTP 200, not an error
- [ ] Evaluations `/access/v1/evaluations` (§7)
  - Top-level values are defaults that item values override
  - `options.evaluations_semantic`: `execute_all` (default), `deny_on_first_deny`, `permit_on_first_permit`
  - Responses keep the request order. Per-item errors come back as decision=false with context
- [ ] Search `/access/v1/search/{subject|resource|action}` (§8)
  - Omit the `id` of the search target. If sent, it MUST be ignored
  - Pagination: `page.token` / `page.limit`
  - Requests for later pages MUST be the same as the previous one
  - The end is `next_token=""`
- [ ] Metadata `GET /.well-known/authzen-configuration` (§9)
  - REQUIRED: `policy_decision_point` and `access_evaluation_endpoint`
  - If `policy_decision_point` does not match the URL used to fetch it, the metadata MUST NOT be used
  - The endpoint values from metadata MUST be used
  - `signed_metadata` is optional
- [ ] Transport (§10, §11)
  - HTTPS POST, JSON object
  - `X-Request-ID` is RECOMMENDED, and the PDP MUST echo it
  - TLS MUST be used
  - PEP authentication SHOULD be used (mTLS / OAuth / API key)
  - Unknown fields MUST be ignored
  - Errors: 400 / 401 / 403 / 500

### Ambiguities (AuthZEN)

- How to carry agent delegation (user→agent) is undefined. The subject could be the agent or the user, and the delegation could go in `subject.properties` or `context`
  - The WG draft MCP Tool Authorization profile and AARP (adopted 2026-06) are worth following
- When `decision=true` comes with context the PEP does not understand, the PEP MAY deny. visado has to pick a behavior

## Cross-cutting open issues

- No type URN exists for a WIT/WPT or an ID-JAG-derived AT as a Txn-Token subject_token
- AIMS does not specify delegation chains (nested `act`)
- ID-JAG's `act` has no processing rules either
- Where to keep the subject mapping for audit is still under discussion in chaining transcription and AIMS PR #176
- MCP EMA (based on -04) and ID-JAG -06 diverge on error codes and DPoP handling
- AIMS Appendix A has history for -02 / -03, but datatracker only has -00 and -01 (presumably carried over from the predecessor klrc's history)

## Sources

- <https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/> (-11)
- <https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-01>
- <https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/> (-06)
- <https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/> (-17)
- <https://github.com/ietf-wg-wimse/draft-ietf-wimse-aims/pull/176>
- <https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization>
- <https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx>
- <https://openid.net/specs/authorization-api-1_0.html>
- <https://openid.net/authorization-api-1-0-final-specification-approved/>
