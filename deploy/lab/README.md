# Lab

Envoy and [agentgateway](https://agentgateway.dev/) call visado through ext_authz. visado asks [OPA with the AuthZEN plugin](https://github.com/kanywst/opa-authzen-plugin) (or [Cerbos](#a-second-pdp-cerbos)), and allowed requests reach an echo server that returns the headers it received. [SPIRE](https://spiffe.io/) v1.16.0 issues the workloads' WITs, X.509-SVIDs and JWT-SVIDs. [Keycloak](https://www.keycloak.org/) 26.8.2, the resource authorization server, issues OAuth access tokens, bearer and DPoP-bound, and redeems ID-JAGs that [Casdoor](https://casdoor.org/) v4.26.0 issues for the user.

Envoy listens on two ports: `10000` (plain HTTP) and `10443` (mTLS). agentgateway v1.7.0 listens on `10001` (plain HTTP) in front of the same upstream, and in front of a real MCP server on `/mcp`.

## Running it

From a clean checkout, with Docker and the Compose plugin and nothing else:

```bash
cd deploy/lab
docker compose up -d --build
docker compose run --rm --no-deps demo
```

`docker compose run --rm --no-deps demo` builds the `demo` image (the testkit examples that make the requests, `curl`, `jq`, `openssl` and the SPIRE agent CLI), runs every scenario below and the [attack demos](attacks/README.md), and exits non-zero if any outcome differs. `docker compose run --rm --no-deps demo attacks/3-recruited-admin.sh` runs one attack. `--no-deps` keeps the running lab as it is: recreating the SPIRE agent would fail, since its join token is single-use. The container shares the SPIRE agent's PID namespace and socket, so each workload fetches its own SVIDs as its own Unix user, and it reads the lab's logs through the Docker API. It does not get the Docker socket: whoever can call the Docker API is root on the host, and mounting the socket read-only does not restrict the calls. Only `docker-proxy` ([docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) v0.5.0, pinned by digest) mounts it, on an internal network shared with the demo container alone, and lets through GET and HEAD under `/containers` (inspect, list, logs). Anything else, such as `POST /containers/create` or `GET /images/json`, gets 403; demo.sh checks both, and that the logs still read. The proxy cannot narrow `/containers` further, so the demo container can still read any container's logs, inspected configuration (environment included) and files (`GET /containers/<id>/archive`). CI runs the same two commands.

`./demo.sh` also runs from the host if it has `cargo`, `curl`, `jq`, `openssl` and `docker`.

`docker compose down -v` removes the lab, its SPIRE state included.

## A second PDP: Cerbos

`compose.cerbos.yaml` swaps the PDP for [Cerbos](https://www.cerbos.dev/) 0.57.0, which serves AuthZEN 1.0 itself. `demo.sh` runs unchanged and expects the same results:

```bash
docker compose -f compose.yaml -f compose.cerbos.yaml up -d --build
docker compose -f compose.yaml -f compose.cerbos.yaml run --rm --no-deps demo
```

visado then reads `visado.cerbos.toml`, which is `visado.toml` with another `[pdp]` table. Cerbos maps the AuthZEN subject to the principal (`subject.type` becomes the role, `subject.properties` the attributes), the resource to a resource of kind `http_resource` and the action name to the action. It does not pass `context` to the policy, so `[pdp] context_in_subject = true` copies the context, the scope and principal included, into `subject.properties`. Both files reach the PDP over plain `http` on the compose network, so both set `[pdp] allow_insecure_http = true`; visado logs a warning for it at startup.

The policy is ported to `cerbos/http_resource.yaml`, with the same rule as the Rego. `cerbos/http_resource_test.yaml` holds its tests; run them with:

```bash
docker compose -f compose.yaml -f compose.cerbos.yaml run --rm --no-deps cerbos compile /policies
```

CI runs `demo.sh` against OPA, then restarts visado against Cerbos and runs it again.

## SPIRE

SPIRE v1.16.0 issues WIT-SVIDs as an experimental feature, turned on with `experimental { enable_wit_svids = true }` in `spire/server.conf` and `spire/agent.conf`. The server sets the WIT `iss` to `https://spire.td.example` (`wit_issuer`).

- `spire-setup` registers `spiffe://td.example/agent-a`, `agent-b`, `agent-z` and `gateway`, and writes a join token for the agent. It also writes the X.509 CA (`x509-bundle.pem`) and the bundle in SPIFFE format (`spiffe-bundle.json`) for visado's `[mtls]` and `[jwt_svid]`. The SPIFFE format marks each key's `use`; the JWT bundle from the Workload API leaves `use` out, and visado takes only keys marked `jwt-svid`.
- The agent attests with the join token. Each lab workload is a Unix user in the agent container (uid 1001, 1002, 1003), and the `unix` workload attestor tells them apart by uid.
- `wit-config` runs before visado. It fetches the `td.example` WIT bundle (a JWKS) from the Workload API and writes it to a shared volume. `visado.toml` trusts it with `jwks_file` and expects the SPIRE `iss`. visado reads the bundle at startup, so restart it after SPIRE rotates the WIT key.
- `gateway-svid` runs before Envoy. It fetches the `gateway` X.509-SVID (with the DNS name `tools.td.example`), its key and the X.509 bundle from the Workload API. Envoy serves the SVID on the mTLS listener and validates client certificates against the bundle. Envoy reads the files once: the SVID expires after an hour and the CA after a day, so restart the lab after that. A deployment would have Envoy fetch them over SDS.
- `demo.sh` runs `spire-agent api fetch wit` as each user and gets the WIT-SVID and its private key. The agent generates the key; the WIT binds it in `cnf.jwk` (ES256). The demo signs each WPT, the AAT holder proofs and the HTTP message signatures with that key. It also fetches agent-a's X.509-SVID (`fetch x509`) for mTLS and two JWT-SVIDs (`fetch jwt`), one for visado's audience `http://tools.td.example` and one for another.

SPIRE's private key JWK and its bundle keys carry no `alg`. The demo takes it from the WIT's `cnf.jwk`; visado gives a P-256 bundle key `ES256`, the only algorithm that key type allows.

User tokens, the first DPoP-bound access token and the AAT root are still signed with the fixed demo keys in `../local/keys`. The DPoP proof key is a fixed testkit key.

## Keycloak

Keycloak 26.8.2 (`start-dev`) imports the `lab` realm from `keycloak/realm.json`. The confidential client `agent-a` gets access tokens with `client_credentials`: audience `http://tools.td.example` (an audience mapper), `tickets.read` by default and `roles.write` on request. `KC_HOSTNAME` fixes the issuer to `http://keycloak.td.example:8180/realms/lab`; the port is published on the host's loopback address, and `demo.sh` reaches it with `curl --resolve`. Keycloak is on the default network only, not on `authz`.

- `keycloak-jwks` runs before visado. It waits for the realm, fetches its JWKS and keeps the `sig` keys (Keycloak also lists an `RSA-OAEP` encryption key). `visado.toml` trusts them as a second `[[oauth_issuers]]` entry; with two issuers each has a `subject_prefix` (`idp:`, `keycloak:`). visado reads the keys at startup, so restart it after Keycloak rotates its key.
- A token request with a `DPoP` header gets a DPoP-bound token (`token_type` `DPoP`). `lab_methods token-proof` makes the proof for the token endpoint with a fixed ES256 key, and `lab_methods dpop-with` the proof for the request to Envoy with the same key. Keycloak writes `cnf` as `{"jkt": ..., "kc-jkt-type": "DPoP"}`; visado accepts that `kc-jkt-type` next to `jkt`.
- `agent-a` may also use the JWT authorization grant (RFC 7523) with assertions from the identity provider `casdoor`, which Keycloak 26.8 checks as an ID-JAG when the assertion's `typ` is `oauth-id-jag+jwt` (the experimental feature `identity-assertion-jwt`, turned on in `compose.yaml`). Keycloak refuses an ID-JAG it has already redeemed.
- The client secret, the admin password and the realm are demo values. `start-dev` keeps the realm in a database inside the container: a new container imports it again, a restarted one keeps it.

## Casdoor and ID-JAG

Casdoor v4.26.0 is bob's identity provider. It issues ID-JAGs (draft-ietf-oauth-identity-assertion-authz-grant) by token exchange: `requested_token_type` `urn:ietf:params:oauth:token-type:id-jag`, an ID token as the subject token, and the Keycloak issuer as the `audience`. Casdoor v4.27.0 and later issue ID-JAGs only with a commercial edition license, hence v4.26.0.

- `casdoor/init_data.json` creates the organization `lab`, the application `agent-a` (password and token exchange grants), an application `keycloak-lab` whose client ID is the Keycloak issuer (Casdoor only issues ID-JAGs for an audience it knows as an application), the users bob and eve, and a permission that lets bob, not eve, get ID-JAGs for `keycloak-lab`. The issuer is `origin`, `http://casdoor.td.example:8190`.
- The ID-JAG carries `typ` `oauth-id-jag+jwt`, `iss`, `sub` (bob's Casdoor ID), `aud` (the Keycloak issuer), `client_id` `agent-a`, `jti`, `iat` and `exp` (300 s). Keycloak checks `client_id` against the client that redeems it and finds the user by `sub` among the users linked to `casdoor`.
- Casdoor gives each user a random ID when it imports them, so `casdoor-link` makes the link once both are up: it signs bob in at Casdoor, reads `sub` from the ID token, and adds it to Keycloak's bob as a federated identity through the admin API. Recreate `keycloak` and `casdoor` together; a link to an old Casdoor ID fails the job.
- `demo.sh` signs bob in (password grant), exchanges the ID token for an ID-JAG as agent-a, and redeems it at Keycloak with a DPoP proof. The access token names Keycloak's bob as `sub` and agent-a as `azp`, bound to agent-a's DPoP key.

### Not in the lab yet

- Dex issuing ID-JAGs: implemented on Dex's `master` ([dexidp/dex#4611](https://github.com/dexidp/dex/pull/4611)), not in a release (v2.46.1 is the latest). Casdoor plays that role until a Dex release has it.
- RFC 8693 `act` chains from Keycloak: Keycloak 26.8 adds `act` in token exchange only with the preview feature `token-exchange-delegation`, which needs a `may_act` claim in the subject token from a user's consent to a delegation scope and fine-grained admin permissions. The lab does not set that up.

`visado.toml` sets `[dpop] require_nonce = true`, so every DPoP proof must carry a nonce visado issued (RFC 9449 §9). The lab runs one visado, so the nonce key is made at startup.

## Scenarios

`demo.sh` checks each response status and, where the table names one, visado's error code:

| Scenario | Expected |
| --- | --- |
| No credentials | 401 `credential.missing` |
| Encoded `/` in the path | 400 from Envoy (`path_with_escaped_slashes_action: REJECT_REQUEST`) |
| `..;` in the path, which Tomcat and Jetty read as `..` | 400 `request.unnormalized_path` from visado |
| agent-a reads tickets for bob (`tickets.read`) | 200; the upstream sees `Txn-Token` and no user token |
| agent-b forwards bob's transaction to the admin API | 403 `pdp.deny`: the token still carries `tickets.read` |
| agent-b forwards bob's transaction to tickets | 200 with the same `Txn-Token` |
| A workload not in `internal_callers` forwards the transaction | 403 `txn.untrusted_hop` |
| A user token without `roles.write` on the admin API | 403 `pdp.deny` |
| carol with `roles.write` through agent-a | 200 |
| AAT: agent-b reads `/data/report.pdf`, which agent-a delegated to it | 200 |
| AAT: agent-b reads `/etc/passwd` | 403 `aat.invocation_denied`, outside the delegated constraint |
| AAT: agent-b calls `delete_file`, which agent-a kept | 403 `aat.invocation_denied` |
| AAT: agent-z presents agent-b's chain | 403 `aat.bad_signature`, the proof is not signed by the holder |
| agent-a POSTs a ticket with an HTTP message signature instead of a WPT | 200 |
| The same signed request again | 400 `httpsig.invalid`: the nonce was seen |
| A signed request whose body differs from the covered `Content-Digest` | 400 `httpsig.invalid` |
| mTLS: agent-a's X.509-SVID | 200 |
| mTLS: agent-a's X.509-SVID with an `X-User-Token` | 401 `credential.unbound_user_token`: nothing binds the token to the certificate |
| mTLS: a certificate for agent-a's SPIFFE ID from another CA | No response: Envoy refuses the handshake (curl reports `000`) |
| agent-a's JWT-SVID as `Authorization: Bearer` | 200 |
| A JWT-SVID for another audience | 401 `jwt_svid.invalid` |
| An OAuth client's access token as `Authorization: Bearer` | 200 |
| The same kind of token, expired | 401 `token.expired` |
| bob's access token, DPoP-bound, with a proof without a nonce | 401 `dpop.nonce_missing`, with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a `DPoP-Nonce` header |
| The same request with a new proof carrying that nonce | 200, with the next `DPoP-Nonce` |
| A proof with a nonce visado did not issue | 401 `dpop.nonce_invalid` |
| The same token as `Bearer`, without the proof | 401 `token.dpop_bound` |
| Keycloak: agent-a's bearer token (`tickets.read`) on tickets | 200 |
| Keycloak: the same token on the admin API | 403 from the PDP: no `roles.write` |
| Keycloak: a token with `roles.write` on the admin API | 200 |
| Keycloak: agent-a's DPoP-bound token with its proof | 200 |
| Keycloak: the DPoP-bound token as `Bearer` | 401 `token.dpop_bound` |
| Keycloak: the DPoP-bound token with a proof by another key | 401 `dpop.binding` |
| Casdoor: token exchange of bob's ID token for an ID-JAG for Keycloak | An ID-JAG (`typ` `oauth-id-jag+jwt`) |
| Casdoor: the same for eve, who has no permission | `invalid_target` |
| Keycloak: the ID-JAG redeemed a second time | `invalid_grant` |
| ID-JAG: bob's Keycloak token through agent-a, with its DPoP proof and visado's nonce | 200 |
| ID-JAG: the same token on the admin API | 403 from the PDP: no `roles.write` |
| ID-JAG: the same token as `Bearer` | 401 `token.dpop_bound` |

## agentgateway

agentgateway's `extAuthz` policy (`agentgateway.yaml`) calls visado over gRPC with the body as raw bytes, like Envoy's filter. It sends the authority as `host`, the path with its query, the method, the scheme and the headers (pseudo-headers included, repeated values joined with commas). It sends no peer certificate, only the verified SPIFFE ID as `source.principal`, which visado does not use, so the mTLS scenarios run through Envoy only. It does not normalize the path either: visado rejects `%2F` itself.

`demo.sh` runs a subset of the scenarios through it:

| Scenario | Expected |
| --- | --- |
| No credentials | 401 `credential.missing` |
| Encoded `/` in the path | 400 `request.unnormalized_path` from visado |
| `..;` in the path | 400 `request.unnormalized_path` from visado |
| agent-a reads tickets for bob | 200; the upstream sees `Txn-Token` and no user token |
| A user token without `roles.write` on the admin API | 403 `pdp.deny` |
| AAT: agent-b reads `/data/report.pdf`, which agent-a delegated to it | 200 |
| AAT: agent-b reads `/etc/passwd` | 403 `aat.invocation_denied` |
| agent-a POSTs a ticket with an HTTP message signature | 200 |
| A signed request whose body differs from the covered `Content-Digest` | 400 `httpsig.invalid` |
| bob's access token, DPoP-bound, with a proof without a nonce | 401 `dpop.nonce_missing`, with `use_dpop_nonce` and a `DPoP-Nonce` header |
| The same request with a new proof carrying that nonce | 200, with the next `DPoP-Nonce` |

On agentgateway, `/mcp` is an MCP route (below); the `/mcp` scenarios through Envoy reach the echo server.

The AAT chains are bound to the keys SPIRE issued: agent-a's WIT key holds the root and signs the delegation to agent-b's WIT key.

The signed requests need the body: the ext_authz filters set `with_request_body` with `pack_as_bytes: true`. The mTLS listener's filter sets `include_peer_certificate: true`. visado's gRPC port listens only on its address on `authz`, an internal network that only Envoy and agentgateway share, so `visado.toml` sets the top-level `grpc_reachable_only_by_proxy = true` and the proxies connect without TLS: no other container can send a check request with someone else's certificate or get a Transaction Token. visado logs a warning for it at startup. A deployment without such a network sets `[grpc_tls]` with a `client_ca_file` instead. `demo.sh` checks that another container cannot connect to the port.

Envoy also normalizes `%2e%2e` and `//` before visado sees the path; visado rejects any that still arrive.

Each decision is also a `visado.authorize` span in Jaeger at <http://127.0.0.1:16686>.

The chain view at <http://127.0.0.1:8080/chain> draws each recent decision: principal, delegation hops (verified or declared), caller, PDP decision and the deny reason. It shows caller and principal identities, so the port is published to the host's loopback address only.

The policy is in `policy/visado.rego` (and `cerbos/http_resource.yaml` for Cerbos): `/admin/` needs `roles.write`, everything else `tickets.read`.

The demo keys are public. Do not reuse them.

## MCP backend

agentgateway routes `/mcp` to its MCP backend (`statefulMode: stateless`, `prefixMode: never`), which serves the tools of `mcp/server.py`: a small MCP server over Streamable HTTP, written against the Python standard library and run in the pinned `python:3.13.18-alpine` image, with `read_file` and `delete_file` on an in-memory file store. The route has the same `extAuthz` policy as the others, so visado sees each MCP message before agentgateway handles it. For a `tools/call`, the tool name and arguments are what the caller's AAT chain must permit ([bindings](../../docs/bindings.md#aat)); with an asor chain, the tool name is the action's scope.

| Scenario | Expected |
| --- | --- |
| agent-b lists the tools (`tools/list`, no chain) | 200 with `read_file` and `delete_file` from the MCP server |
| agent-b calls `read_file` on `/data/report.pdf`, which agent-a delegated to it | 200 with the file's text from the MCP server |
| agent-b calls `delete_file`, which agent-a kept | 403 `aat.invocation_denied`; the call never reaches the MCP server |

The MCP server logs each `tools/call` it receives; the attack demos use that log to show which calls got through.

## Audit record

visado writes one audit record per decision to its log (`docker compose logs visado`), in the schema of [docs/audit.md](../../docs/audit.md). `demo.sh` finds the record of the first allowed request by its `txn` and checks each member, checks a 401's record, checks that every record has every member, recomputes the hash chain over the run's records, and checks that there are as many records as decisions in the chain view.

## Attack demos

[attacks/README.md](attacks/README.md): a prompt-injected agent widening its delegation, a stolen chain replayed by another workload, a ticket that recruits the admin agent (all three stopped), and exfiltration within granted scope (not stopped).
