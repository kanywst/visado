# Lab

Envoy and [agentgateway](https://agentgateway.dev/) call visado through ext_authz. visado asks [OPA with the AuthZEN plugin](https://github.com/kanywst/opa-authzen-plugin), and allowed requests reach an echo server that returns the headers it received. [SPIRE](https://spiffe.io/) v1.16.0 issues the workloads' WITs, X.509-SVIDs and JWT-SVIDs.

Envoy listens on two ports: `10000` (plain HTTP) and `10443` (mTLS). agentgateway v1.7.0 listens on `10001` (plain HTTP) in front of the same upstream.

```bash
docker compose up -d --build
./demo.sh
```

## SPIRE

SPIRE v1.16.0 issues WIT-SVIDs as an experimental feature, turned on with `experimental { enable_wit_svids = true }` in `spire/server.conf` and `spire/agent.conf`. The server sets the WIT `iss` to `https://spire.td.example` (`wit_issuer`).

- `spire-setup` registers `spiffe://td.example/agent-a`, `agent-b`, `agent-z` and `gateway`, and writes a join token for the agent. It also writes the X.509 CA (`x509-bundle.pem`) and the bundle in SPIFFE format (`spiffe-bundle.json`) for visado's `[mtls]` and `[jwt_svid]`. The SPIFFE format marks each key's `use`; the JWT bundle from the Workload API leaves `use` out, and visado takes only keys marked `jwt-svid`.
- The agent attests with the join token. Each lab workload is a Unix user in the agent container (uid 1001, 1002, 1003), and the `unix` workload attestor tells them apart by uid.
- `wit-config` runs before visado. It fetches the `td.example` WIT bundle (a JWKS) from the Workload API and writes it to a shared volume. `visado.toml` trusts it with `jwks_file` and expects the SPIRE `iss`. visado reads the bundle at startup, so restart it after SPIRE rotates the WIT key.
- `gateway-svid` runs before Envoy. It fetches the `gateway` X.509-SVID (with the DNS name `tools.td.example`), its key and the X.509 bundle from the Workload API. Envoy serves the SVID on the mTLS listener and validates client certificates against the bundle. Envoy reads the files once: the SVID expires after an hour and the CA after a day, so restart the lab after that. A deployment would have Envoy fetch them over SDS.
- `demo.sh` runs `spire-agent api fetch wit` as each user and gets the WIT-SVID and its private key. The agent generates the key; the WIT binds it in `cnf.jwk` (ES256). The demo signs each WPT, the AAT holder proofs and the HTTP message signatures with that key. It also fetches agent-a's X.509-SVID (`fetch x509`) for mTLS and two JWT-SVIDs (`fetch jwt`), one for visado's audience `http://tools.td.example` and one for another.

SPIRE's private key JWK and its bundle keys carry no `alg`. The demo takes it from the WIT's `cnf.jwk`; visado gives a P-256 bundle key `ES256`, the only algorithm that key type allows.

User tokens, the DPoP-bound access token and the AAT root are still signed with the fixed demo keys in `../local/keys`. The DPoP proof key is a fixed testkit key.

## Scenarios

`demo.sh` checks each response status and, where the table names one, visado's error code:

| Scenario | Expected |
| --- | --- |
| No credentials | 401 |
| Encoded `/` in the path | 400 from Envoy (`path_with_escaped_slashes_action: REJECT_REQUEST`) |
| agent-a reads tickets for bob (`tickets.read`) | 200; the upstream sees `Txn-Token` and no user token |
| agent-b forwards bob's transaction to the admin API | 403 from the PDP: the token still carries `tickets.read` |
| agent-b forwards bob's transaction to tickets | 200 with the same `Txn-Token` |
| A workload not in `internal_callers` forwards the transaction | 403 |
| A user token without `roles.write` on the admin API | 403 |
| carol with `roles.write` through agent-a | 200 |
| AAT: agent-b reads `/data/report.pdf`, which agent-a delegated to it | 200 |
| AAT: agent-b reads `/etc/passwd` | 403, outside the delegated constraint |
| AAT: agent-b calls `delete_file`, which agent-a kept | 403 |
| AAT: agent-z presents agent-b's chain | 403, the proof is not signed by the holder |
| agent-a POSTs a ticket with an HTTP message signature instead of a WPT | 200 |
| The same signed request again | 400 `httpsig.invalid`: the nonce was seen |
| A signed request whose body differs from the covered `Content-Digest` | 400 `httpsig.invalid` |
| mTLS: agent-a's X.509-SVID | 200 |
| mTLS: agent-a's X.509-SVID with an `X-User-Token` | 401 `credential.unbound_user_token`: nothing binds the token to the certificate |
| mTLS: a certificate for agent-a's SPIFFE ID from another CA | No response: Envoy refuses the handshake (curl reports `000`) |
| agent-a's JWT-SVID as `Authorization: Bearer` | 200 |
| A JWT-SVID for another audience | 401 `jwt_svid.invalid` |
| bob's access token, DPoP-bound, with its proof | 200 |
| The same token as `Bearer`, without the proof | 401 `token.dpop_bound` |

## agentgateway

agentgateway's `extAuthz` policy (`agentgateway.yaml`) calls visado over gRPC with the body as raw bytes, like Envoy's filter. It sends the authority as `host`, the path with its query, the method, the scheme and the headers (pseudo-headers included, repeated values joined with commas). It sends no peer certificate, only the verified SPIFFE ID as `source.principal`, which visado does not use, so the mTLS scenarios run through Envoy only. It does not normalize the path either: visado rejects `%2F` itself.

`demo.sh` runs a subset of the scenarios through it:

| Scenario | Expected |
| --- | --- |
| No credentials | 401 `credential.missing` |
| Encoded `/` in the path | 400 `request.unnormalized_path` from visado |
| agent-a reads tickets for bob | 200; the upstream sees `Txn-Token` and no user token |
| A user token without `roles.write` on the admin API | 403 |
| AAT: agent-b reads `/data/report.pdf`, which agent-a delegated to it | 200 |
| AAT: agent-b reads `/etc/passwd` | 403 |
| agent-a POSTs a ticket with an HTTP message signature | 200 |
| A signed request whose body differs from the covered `Content-Digest` | 400 `httpsig.invalid` |
| bob's access token, DPoP-bound, with its proof | 200 |

The `/mcp` scenarios use a plain HTTP route to the echo server, not agentgateway's MCP backend.

The AAT chains are bound to the keys SPIRE issued: agent-a's WIT key holds the root and signs the delegation to agent-b's WIT key.

The signed requests need the body: the ext_authz filters set `with_request_body` with `pack_as_bytes: true`. The mTLS listener's filter sets `include_peer_certificate: true`. visado's gRPC port listens only on its address on `authz`, an internal network that only Envoy and agentgateway share, so `visado.toml` can set `grpc_reachable_only_by_proxy = true`: no other container can send a check request with someone else's certificate. `demo.sh` checks that another container cannot connect to the port.

Envoy also normalizes `%2e%2e` and `//` before visado sees the path; visado rejects any that still arrive.

Each decision is also a `visado.authorize` span in Jaeger at <http://127.0.0.1:16686>.

The chain view at <http://127.0.0.1:8080/chain> draws each recent decision: principal, delegation hops (verified or declared), caller, PDP decision and the deny reason. It shows caller and principal identities, so the port is published to the host's loopback address only.

The policy is in `policy/visado.rego`: `/admin/` needs `roles.write`, everything else `tickets.read`.

The demo keys are public. Do not reuse them.
