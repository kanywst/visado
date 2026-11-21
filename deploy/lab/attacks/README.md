# Attack demos

Four attacks on AI agent traffic, each run through the lab's real gateways (Envoy on `10000`, agentgateway on `10001`) by `demo.sh`. visado stops three. It does not stop the fourth, and the write-up says what would.

```bash
docker compose up -d --build
docker compose run --rm --no-deps demo                # every scenario, attacks included
docker compose run --rm --no-deps demo attacks/2-stolen-chain.sh  # one attack
```

Each script prints an `ok` or `FAIL` line per step with the status and visado's reason code, then finds the decision's audit record (see [docs/audit.md](../../../docs/audit.md)) in visado's log. The chain view at <http://127.0.0.1:8080/chain> draws each decision. CI runs all four and fails if any outcome changes.

The cast: bob is a user who may read tickets (`tickets.read`). agent-a is a triage agent; agent-b manages files and roles; agent-z is another workload on the same network. SPIRE issues all three their WIT-SVIDs. An AAT chain rooted at the lab's AAT anchor grants agent-a tools, and agent-a delegates some of them to agent-b. The MCP server behind agentgateway (`mcp/server.py`) has `read_file` and `delete_file`.

## 1. A prompt-injected agent widens its delegation

`1-widened-delegation.sh`. Stopped: `403 aat.not_attenuated`.

The root grants agent-a `read_file` on `/data/report.pdf` and nothing else. A poisoned prompt makes agent-a delegate more than that to agent-b: `read_file` on any path and `delete_file`. agent-a holds its own key, so it can sign the child token. agent-b then reads `/etc/passwd` and deletes the report through agentgateway's MCP route.

| Step | Outcome |
| --- | --- |
| Control: agent-a delegates exactly what it holds; agent-b reads the report | 200, served by the MCP server |
| Widened chain: agent-b calls `read_file` on `/etc/passwd` | 403 `aat.not_attenuated` |
| Widened chain: agent-b calls `delete_file` | 403 `aat.not_attenuated`; the MCP server's log has no `delete_file` |

Why it fails: visado verifies the whole chain, not only the leaf. Every hop's grants must be within its parent's (AAT §8 step 4p), so a hop cannot hand on authority it never had, whoever signed it. The control step shows the same tool call passes when the delegation is honest.

## 2. A stolen chain, replayed by another workload

`2-stolen-chain.sh`. Stopped: `401 wpt.replay` and `403 chain.holder_mismatch`.

agent-z captures agent-b's requests from somewhere they leak: a debug log, a tracing span with headers, a misbehaving proxy. Each request carries agent-b's WIT, its WPT, the AAT chain and the AAT proof of possession. Modelled on the Salesloft Drift breach (2025), where stolen bearer tokens were replayed from attacker infrastructure.

| Step | Outcome |
| --- | --- |
| agent-b sends its delegated `read_file` call | 200 |
| agent-z replays that request byte for byte | 401 `wpt.replay`: the WPT's `jti` was seen |
| agent-z takes a request agent-b has not sent yet, keeps the chain and its proof, and authenticates with its own WIT | 403 `chain.holder_mismatch`; the audit record names agent-z |

Why it fails: nothing in the request is a bearer secret. The WPT is single use and bound to agent-b's WIT; signing a new one needs agent-b's private key, which never leaves agent-b. The chain's leaf names the key it was delegated to, and visado requires that key to be the one the caller proved possession of.

## 3. A ticket recruits the admin agent

`3-recruited-admin.sh`. Stopped: `403 pdp.deny`.

Modelled on the ServiceNow Now Assist agent-to-agent attack (AppOmni, November 2025): a low-privilege user's ticket hijacked a triage agent, which recruited a more privileged agent that then acted with the privileges of the user who started the interaction. Here bob asks agent-a to triage tickets. One ticket says to give mallory the admin role. agent-a forwards bob's transaction to agent-b, which can manage roles, and agent-b posts the role change.

| Step | Outcome |
| --- | --- |
| agent-a reads tickets for bob | 200; visado mints a Transaction Token with bob's `tickets.read` |
| agent-b posts `{"user":"mallory","role":"admin"}` to `/admin/roles` with bob's Transaction Token | 403 `pdp.deny` |
| agent-b drops bob's transaction and posts as itself | 403 `pdp.deny` |
| The audit record | agent-b, principal bob, bob's `txn`, `/admin/roles`, `pdp.deny` |

Why it fails: the transaction carries bob's scope, not the recruited agent's, and a replacement token never widens it. agent-b's own standing scope does not cover `/admin/` either, so there is no ambient privilege to fall back on. The audit record ties agent-b's call to the transaction bob started, so the trail leads back to the ticket. It does not name mallory, who never authenticated: the attacker's text is not an identity.

## 4. Exfiltration within granted scope: not stopped

`4-exfiltration-in-scope.sh`. Not stopped: both calls are 200.

agent-b may read `/data/report.pdf`. The report carries hidden instructions: post this file to a public ticket. agent-b reads the report through the MCP route, which is allowed, and posts its text to `/tickets`, which agent-b may also do. Modelled on the GitHub MCP incident (Invariant Labs, May 2025), where a public issue made an agent copy private repository data into a public pull request using a credential that legitimately covered both.

| Step | Outcome |
| --- | --- |
| agent-b calls `read_file` on the report | 200; the report's text comes back in the MCP response |
| agent-b posts that text to `/tickets` | 200; the upstream receives the report |
| The audit records | Both, `allow`, with agent-b and the tool |

Why it works: every request is authenticated, within the delegation and allowed by policy. visado decides on requests; the data leaves in a response body visado never sees and comes back in a request it has no reason to refuse. Delegation chains say who may call what, not where the data read in one call may go next. The audit record shows what happened, after the fact.

What would stop it:

- A narrower grant. If the delegation for "summarize the report" carried only `read_file` and the transaction pinned it to that one task, the post would have no grant. AAT constraints and a PDP rule over the Transaction Token's `tctx` can express that; this lab's policy allows any `tickets.read` caller to post.
- A PDP that looks at the arguments, for example one that refuses to post text to a public ticket on behalf of an agent that read an internal file in the same transaction. That needs the PDP to know what the transaction read, which visado does not track.
- Inspecting the data: a DLP filter on responses and egress, or the MCP server labelling what it returns, so a guardrail can refuse to send it on.
- A human approving writes that leave the trust boundary.
