# Lab

Envoy calls visado through ext_authz. visado asks [OPA with the AuthZEN plugin](https://github.com/kanywst/opa-authzen-plugin), and allowed requests reach an echo server that returns the headers it received.

```bash
docker compose up -d --build
./demo.sh
```

`demo.sh` signs WITs, WPTs and user tokens with the fixed demo keys in `../local/keys` and checks each response status:

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

Envoy also normalizes `%2e%2e` and `//` before visado sees the path; visado rejects any that still arrive.

The policy is in `policy/visado.rego`: `/admin/` needs `roles.write`, everything else `tickets.read`.

The demo keys are public. Do not reuse them.
