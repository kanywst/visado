# Lab

Envoy calls visado through ext_authz. visado asks [OPA with the AuthZEN plugin](https://github.com/kanywst/opa-authzen-plugin), and allowed requests reach an echo server that returns the headers it received. [SPIRE](https://spiffe.io/) v1.16.0 issues the workloads' WITs.

```bash
docker compose up -d --build
./demo.sh
```

## SPIRE

SPIRE v1.16.0 issues WIT-SVIDs as an experimental feature, turned on with `experimental { enable_wit_svids = true }` in `spire/server.conf` and `spire/agent.conf`. The server sets the WIT `iss` to `https://spire.td.example` (`wit_issuer`).

- `spire-setup` registers `spiffe://td.example/agent-a`, `agent-b` and `agent-z`, and writes a join token for the agent.
- The agent attests with the join token. Each lab workload is a Unix user in the agent container (uid 1001, 1002, 1003), and the `unix` workload attestor tells them apart by uid.
- `wit-config` runs before visado. It fetches the `td.example` WIT bundle (a JWKS) from the Workload API and writes it to a shared volume. `visado.toml` trusts it with `jwks_file` and expects the SPIRE `iss`. visado reads the bundle at startup, so restart it after SPIRE rotates the WIT key.
- `demo.sh` runs `spire-agent api fetch wit` as each user and gets the WIT-SVID and its private key. The agent generates the key; the WIT binds it in `cnf.jwk` (ES256). The demo signs each WPT, and the AAT holder proofs, with that key.

SPIRE's private key JWK and its bundle keys carry no `alg`. The demo takes it from the WIT's `cnf.jwk`; visado gives a P-256 bundle key `ES256`, the only algorithm that key type allows.

User tokens and the AAT root are still signed with the fixed demo keys in `../local/keys`.

## Scenarios

`demo.sh` checks each response status:

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

The AAT chains are bound to the keys SPIRE issued: agent-a's WIT key holds the root and signs the delegation to agent-b's WIT key.

Envoy also normalizes `%2e%2e` and `//` before visado sees the path; visado rejects any that still arrive.

Each decision is also a `visado.authorize` span in Jaeger at <http://127.0.0.1:16686>.

The policy is in `policy/visado.rego`: `/admin/` needs `roles.write`, everything else `tickets.read`.

The demo keys are public. Do not reuse them.
