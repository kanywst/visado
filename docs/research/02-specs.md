# Spec requirements checklist (as of 2026-11-18)

Target revisions (checked on datatracker): txn-tokens **-11** (2026-07-30, awaiting WG write-up) / AIMS **-01** (2026-11-02, Informational, WG doc) / ID-JAG **-06** (2026-10-31) / identity-chaining **-17** (2026-07-19, RFC Ed Queue) / AuthZEN Authorization API **1.0 Final** (OIDF approval announcement dated 2026-01-12).

For txn-tokens, ID-JAG and chaining, the published draft text (-11 / -06 / -17) was read. It was confirmed to match the latest revision on datatracker.

## 1. Transaction Tokens (draft-ietf-oauth-transaction-tokens-11)

### JWT format (§9)

- [ ] The header `typ` MUST be `txntoken+jwt` (§9.1). `kid` is SHOULD
- [ ] REQUIRED claims: `iat`, `aud`, `exp`, `txn` (RFC 8417 §2.2), `sub`, `scope`, `req_wl` (§9.2)
  - `aud` identifies the Trust Domain (MUST). Other domains MUST NOT accept it
  - `sub` is unique within the aud domain (MUST). It is not tied to `iss`
- [ ] RECOMMENDED claims: `tctx` (immutable authorization details) and `rctx` (environment context, e.g. `req_ip`, `authn`, `transport`)
  - In -11 the name is **`rctx`**. There is no `req_ctx` claim. The only remaining `req_` items are `req_wl` and the request parameters `request_context` / `request_details`
- [ ] `iss` is OPTIONAL. Used for identification when the signing key is not known in advance (§13.16)
- [ ] Recipients MUST ignore claims they do not understand (§9.2)

### TTS request (§11.1), RFC 8693 profile

- [ ] When requesting from a remote TTS over HTTP, use of RFC 8693 is MUST (§5.1, §11)
- [ ] Required parameters:
  - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
  - `audience`: the Trust Domain name
  - `scope`: expresses the purpose
  - `requested_token_type=urn:ietf:params:oauth:token-type:txn_token`
  - `subject_token` and `subject_token_type`
- [ ] RECOMMENDED parameters: `request_context` (JSON → `rctx`) and `request_details` (JSON → `tctx`). Sent form-urlencoded
- [ ] `subject_token_type` (§11.2):
  - Any type from RFC 8693 §3 is allowed, **except refresh_token**
  - `urn:ietf:params:oauth:token-type:self_signed` (§11.2.1): a JWT. MUST contain `iss` = requesting workload, `sub`, `aud` = TTS ID (the TTS SHALL check it), `iat`, `exp`
  - `urn:ietf:params:oauth:token-type:unsigned_json` (§11.2.2): `sub` is MUST
  - Custom URNs are also allowed
- [ ] Processing (§11.3). All MUST:
  - Client authn and authorization
  - Validation of the subject_token (including the signature if signed)
  - Uniqueness of `sub`
  - Setting `iat`, `aud`, `exp`, `txn`
  - Evaluation of scope
- [ ] Do not issue from an expired subject_token (§6 MUST NOT)
- [ ] Response (§11.4): `token_type=N_A`, `access_token` = the Txn-Token, `issued_token_type=...:txn_token`. `refresh_token` is MUST NOT. Errors use the RFC 6749 §5.2 format
- [ ] Mutual authentication is MUST (§11.5). Asymmetric methods such as RFC 7523, RFC 8705, WIMSE mTLS, HTTP-sig, WPT are SHOULD
- [ ] Exactly one logical TTS per Trust Domain (MUST, §10)

### Propagation (§12)

- [ ] Header `Txn-Token:` (MUST). The value is exactly one token. Use of the `Authorization` header is MUST NOT
- [ ] Recipient validation is MUST on three points: signature, `aud` is its own domain, not expired (§12.2)
- [ ] Outbound calls carry the received token **unmodified** (MUST)

### Security (§13)

- [ ] Keep the lifetime short (MUST, §13.1). Detect replay with `txn`. A single-use check is optional (§13.2)
- [ ] Do not embed an access token in a Txn-Token (MUST NOT, §13.4)
- [ ] scope is at most the subject_token's scope (MUST, §13.6). If the subject_token's scope is unknown, reject (MUST, §13.14)
- [ ] Obtain TTS configuration from a trusted source (MUST, §13.7). Authenticate the TTS (MUST, §13.9)
- [ ] Do not use a Txn-Token as an authn credential (§13.12). Do not use it as an OAuth AT either (§13.13). Both MUST NOT
- [ ] **Replacement** (§13.15). When a Txn-Token is passed as the subject_token:
  - Narrowing changes and adding values are MAY. Broadening is MUST NOT
  - Changing `txn`, `sub`, `aud` is MUST NOT
  - Replacing an expired token is MUST NOT
  - Extending the lifetime is MAY. If extended, the number of replacements SHOULD be limited
  - **Preserving the call chain is MUST, but the method is out of scope**
- [ ] Do not log a Txn-Token in full (MUST NOT, §15.2). Log a hash or the payload with the signature removed
- [ ] When crossing domains, identity-chaining is SHOULD (§14)

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
  - Removed the replacement-related body text and consolidated it into consideration §13.15

### Ambiguities

- In the §9.2 claim list, `tctx` references §9.2.2 and `rctx` references §9.2.3, but the actual section contents are the other way round (swapped cross-references)
- `req_wl`:
  - The history says "clarified the representation of multiple workloads", but the body text only says "A string value"
  - The IANA registration (§16.2) does not include `req_wl` either (only `tctx` and `rctx`)
- The method for preserving the call chain on replacement is undefined. visado has to decide for itself whether to concatenate `req_wl` or use its own claim
- The `audience` parameter (Trust Domain) and the self-signed JWT `aud` (TTS ID) are different values
- The comparison method for judging "scope ≤ subject_token's scope" is undefined. Internal scopes may have different semantics from external scopes (§9.2.1), which is somewhat contradictory
- No type URN is defined for using a WIT or WPT as the subject_token (treated as a custom URN)

## 2. AIMS (draft-ietf-wimse-aims-01, Informational)

### Components (§5)

- 8 layers: Identifier → Credentials → Provisioning → Authentication → Authorization → Observability/Remediation → Policy → Compliance
- This is a conceptual model, not a protocol
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
| §7–8 | credential | WIT/WIC (WIMSE-CRED), X.509-SVID / JWT-SVID / WIT-SVID. Short-lived (SHOULD), `exp` is MUST. LLM access to credentials is MUST NOT |
| §9.1 / §9.2 | authentication | mTLS / WPT (`wth`) or WIMSE HTTP-sig (RFC 9421). Relay and replay considerations are MUST |
| §9.3 | long-running session | Re-validate on expiry. WPT per message |
| §10.2–10.5 | OAuth | authorization code and client credentials. Client authn via RFC 7523 / RFC 8705 / OAuth-SPIFFE. Users use a phishing-resistant method (SHOULD) |
| §10.4 | policy | AuthZEN. The token is one of the inputs to the decision. Sender-constrained (mTLS or DPoP) |
| §10.6 / §10.9 | internal propagation | Txn-Token and RFC 8693. Forwarding the AT is an anti-pattern |
| §10.7 | cross-domain | identity-chaining (SHOULD), ID-JAG, Txn-Token assertion grant |
| §10.8 | HITL | CIBA. Treating only a local UI confirmation as authorization is MUST NOT. Bind to the AS grant (MUST) |
| §10.11 | discovery | RFC 8414, RFC 9728, CIMD, RFC 7591 |
| §11 | monitoring and revocation | SSF / CAEP / RISC / WISE. Enforce on receiving a revocation (MUST). Using an invalidated cache is MUST NOT |

### Normative-ish parts

- Uppercase MUST/SHOULD appear in §6, §7, §8, §9.2.3, §10.x, §11, §13
- §1–5, §9.1, §9.3, §14–16 are descriptive only
- However, since the whole document is Informational, it should be read as a "recommended architecture", not as conformance requirements

### Audit (§11)

- Audit log: durable and tamper-evident (MUST)
- Minimum fields to record (MUST):
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

- Content: adds 5 paragraphs on "correlation and user identifiers in delegation chains" to §10.10 Privacy
- Status: **open** (created 2026-11-09, updated 11-17; reportedly to be settled at the 11-18 session)
- Points:
  - Claims transcription (chaining §2.5) may emit a different subject ID toward outside the domain
  - The mapping is kept in **the audit record of the AS that performed the transcription**, not in the token
  - The subject ID is the same across all hops within a domain and may change only when crossing domains
- It is described as having "no new normative text", but it contains a MUST sentence (the same as an existing §10.10 sentence)
- Wording is not final

### What AIMS does not have

- It defines neither the `act` claim nor agent→agent delegation chains
- Delegation chain validation is a part visado brings in from a separate draft (e.g. asor agent-delegation-chain)

### What the reference implementation should demonstrate (inference)

1. The agent ID is a single WIMSE/SPIFFE ID, verifiable via any of WIT+WPT, HTTP-sig, or mTLS
2. An external AT or an ID-JAG-derived AT is exchanged for a Txn-Token and propagated downstream with the `Txn-Token` header (the AT is not forwarded)
3. scope only narrows (for both Txn-Token and chaining)
4. Query the AuthZEN PDP with subject=agent (the delegating user goes in properties or context), and stop on deny
5. Cross-domain is done with ID-JAG / chaining
6. A tamper-evident audit record (e.g. a hash chain) containing the 7 items from §11, using `txn` as the correlation ID
7. (Optional) Discard caches on receiving a CAEP revocation, step-up via CIBA

## 3. ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-06)

### Token exchange at the IdP (§4.3)

- [ ] `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`
- [ ] `audience`: the Resource AS issuer. **Exactly one** (multiple → `invalid_request`, unknown → `invalid_target`, §4.3.3)
- [ ] `resource`: RECOMMENDED. If obtained from PRM, send it unmodified (MUST)
- [ ] `scope` and `authorization_details` are optional. scope has RS-side meaning, not OIDC scope meaning
- [ ] `subject_token`: accepting an ID Token (`...:id_token`) or SAML (`...:saml2`) is MUST. Accepting an RT (`...:refresh_token`) is MAY
- [ ] `actor_token` is accepted, but there are no processing rules (§9.10)
- [ ] IdP validation:
  - Client authn is MUST. Without it, `invalid_client`
  - The subject_token is really of the stated type
  - The ID Token `aud` matches the client_id
  - Reject if `typ` is a different kind (e.g. `at+jwt`)
  - The granted resource / scope / authorization_details go into claims (MUST)
- [ ] Response: `issued_token_type=...:id-jag`, `token_type=N_A`. If scope differs from the request, return scope

### Claims (§3.1)

- The header `typ` MUST be `oauth-id-jag+jwt`
- REQUIRED: `iss`, `sub`, `aud` (the RS-AS issuer), `client_id` (the client ID **at the RS-AS**), `jti`, `exp`, `iat`
- OPTIONAL: `resource`, `scope`, `authorization_details`, `act`, `tenant`, `auth_time`, `acr`, `amr`, `aud_tenant`, `aud_sub`, `email`, `sub_id`, `cnf`
- For a multi-tenant issuer, `tenant` is MUST (§6.1)
- `sub` is the same for the same RS-AS regardless of client (MUST, §5.2)

### JWT bearer grant at the RS-AS (§4.4)

- [ ] `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. When DPoP-bound, `...:jwt-dpop`
- [ ] `assertion` = the ID-JAG
- [ ] A request with neither client authn nor sender-constraint is rejected with `invalid_client` (MUST)
- [ ] Validation (§4.4.1): in addition to RFC 7521 §5.2
  - `typ`
  - trusted `iss`
  - `aud` is its own issuer (if an array, exactly one element)
  - `client_id` matches the authenticated client (MUST)
  - If multi-tenant, check `tenant`
  - If `cnf` is present, PoP. DPoP uses `jkt`, mTLS uses `x5t#S256`. Reject if unsupported
  - `resource` is under its own jurisdiction
- [ ] Metadata:
  - RS-AS: list `urn:ietf:params:oauth:grant-profile:id-jag` in `authorization_grant_profiles_supported` (in that case including jwt-bearer in `grant_types_supported` is MUST)
  - IdP: list id-jag in `identity_chaining_requested_token_types_supported`. If `id_jag_signing_alg_values_supported` is published, it includes RS256 (MUST)
- [ ] Do not reuse the same ID-JAG at a different downstream RS-AS (MUST NOT, §9.4)
- [ ] Changes in -06: subject token validation errors changed from `invalid_grant` to `invalid_request`. Explains the reason for using `access_denied`
- [ ] Changes in -05: added jwt-dpop, mTLS binding, single audience, `invalid_target`, and more

### MCP Enterprise-Managed Authorization

Extension `io.modelcontextprotocol/enterprise-managed-authorization`, spec 2026-07-28.

- It references **ID-JAG -04**
- Additional requirements:
  - `audience` = the MCP AS issuer (MUST)
  - If `resource` is included, it is the MCP Server's RFC 9728 resource ID (MUST), and it is then also put in the ID-JAG `resource` claim (MUST)
  - The AT is audience-restricted to the MCP Server (MUST)
  - Discovery uses `authorization_grant_profiles_supported`
  - An unregistered client may use a CIMD URL as its client_id
  - The client declares the extension as a capability
  - Must not redirect to the MCP AS authorization endpoint
- No mention of DPoP
- Note: the differences from -06 (error codes, jwt-dpop) are not reflected on the MCP side

## 4. Identity Chaining (draft-ietf-oauth-identity-chaining-17, RFC Ed Queue)

- [ ] Token exchange at the A-AS: either `resource` (the B-AS URI) or `audience` (a logical name) is REQUIRED. Unknown values or values not allowed by policy are rejected per RFC 8693 §2.2.2 (MUST, §2.3.1–2)
- [ ] The `aud` of the returned grant identifies the B-AS (MUST). A single aud is RECOMMENDED (§2.3.3)
- [ ] The B-AS validates per RFC 7523 §3, §3.1 (MUST). aud is matched against the token endpoint or issuer (MUST). If the subject cannot be identified, reject (MUST, §2.4.2)
- [ ] The B-AS does not issue RTs (SHOULD NOT, §5.4)
- [ ] Evaluate replay mitigations: short lifetimes, single use, client authn (§5.5)
- [ ] Metadata: `identity_chaining_requested_token_types_supported` (§3)
- [ ] Claims transcription (§2.5): either AS can add, change, or remove claims. The representation format is undefined. No scope escalation

## 5. AuthZEN Authorization API 1.0 (Final)

- [ ] **Evaluation** `POST /access/v1/evaluation` (§6)
  - Request:
    - `subject{type,id}`: REQUIRED
    - `resource{type,id}`: REQUIRED
    - `action{name}`: REQUIRED
    - `properties` and `context`: optional
  - Response: `{decision:bool, context?}`
  - On `false`, must not proceed (MUST NOT)
  - deny is HTTP 200, not an error
- [ ] **Evaluations** `/access/v1/evaluations` (§7)
  - Top-level values are defaults, and item values override them
  - `options.evaluations_semantic`: `execute_all` (default), `deny_on_first_deny`, `permit_on_first_permit`
  - Responses are in the same order as the request. Per-item errors are returned as decision=false with context
- [ ] **Search** `/access/v1/search/{subject|resource|action}` (§8)
  - Omit the `id` of the search target. If sent, ignore it (MUST)
  - Pagination: `page.token` / `page.limit`
  - When fetching subsequent pages, the request must be the same as the previous one (MUST)
  - End is `next_token=""`
- [ ] **Metadata** `GET /.well-known/authzen-configuration` (§9)
  - REQUIRED: `policy_decision_point` and `access_evaluation_endpoint`
  - If `policy_decision_point` does not match the URL used to fetch it, do not use it (MUST)
  - Use the endpoint values from metadata (MUST)
  - `signed_metadata` is optional
- [ ] **Transport** (§10, §11)
  - HTTPS POST, JSON object
  - `X-Request-ID` is RECOMMENDED. The PDP echoes it (MUST)
  - TLS is MUST
  - PEP authentication is SHOULD (mTLS / OAuth / API key)
  - Ignore unknown fields (MUST)
  - Errors: 400 / 401 / 403 / 500

### Ambiguities (AuthZEN)

- How to carry agent delegation (user→agent) is undefined. You have to decide whether subject is the agent or the user, and whether to use `subject.properties` or `context`
  - Worth following the WG draft MCP Tool Authorization profile and AARP (adopted 2026-06)
- When `decision=true` comes with context the PEP does not understand, the PEP may deny (MAY). The behavior needs to be decided

## Cross-cutting open issues

- There is no type URN for accepting a WIT/WPT or an ID-JAG-derived AT as a Txn-Token subject_token
- AIMS does not specify delegation chains (nested `act`)
- ID-JAG's `act` also has no processing rules
- Where to keep the subject mapping for audit is still under discussion in chaining transcription and AIMS PR #176
- MCP EMA (-04 based) and ID-JAG -06 diverge on error codes and DPoP handling
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
