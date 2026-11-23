# Audit record

visado writes one audit record per decision, allowed or denied, to stdout as a JSON log line whose `target` is `visado::audit`. The record is the line's `fields` object:

```json
{"timestamp":"2026-11-22T09:14:03.120Z","level":"INFO","target":"visado::audit","fields":{"audit_version":1,"seq":41,"prev":"9f2c…","id":"0b7e…","txn":"0b7e…","time":1795338843,"agent":"spiffe://td.example/agent-b","auth_method":"wit-wpt","sender_constrained":true,"principal":"bob","chain_profile":"aat-02","chain_issuer":"https://aat.td.example","chain_hops":2,"chain_actors":"[\"Lm1…\",\"q9X…\"]","depth_semantics":"aat-holder-cap","resource":"http://tools.td.example/mcp","tool":"delete_file","action":"POST","decision":"deny","status":403,"reason":"aat.invocation_denied","detail":"","pdp":"not_asked","remediation":"refused","hash":"5d01…"}}
```

The chain view (`/chain`) is a debugging aid kept in memory. This log is the audit trail.

## Members

The order below is the schema order, which the hash uses. Every member is always present; a value that is not known is the empty string, `0` or `"[]"`.

| Member | Type | Meaning |
| --- | --- | --- |
| `audit_version` | integer | `1`. Changes only when a member changes meaning; members are only ever added |
| `seq` | integer | Position in this process's chain, from 0 |
| `prev` | string | `hash` of the previous record; empty for `seq` 0 |
| `id` | string | This check's identifier, unique per decision |
| `txn` | string | The transaction the request belongs to: the newly minted one, or the one of a forwarded Transaction Token. Empty when the gate stopped before it was known (an authentication failure) |
| `time` | integer | When the gate decided, in seconds since the Unix epoch |
| `agent` | string | The authenticated caller, such as a SPIFFE ID or an OAuth `client_id`. Empty if authentication failed |
| `auth_method` | string | `wit-wpt`, `wit-httpsig`, `mtls`, `jwt-svid`, `bearer` or `oauth-dpop` |
| `sender_constrained` | boolean | Whether the caller proved possession of a key for this request (WPT, HTTP signature, mTLS, DPoP) rather than presenting a bearer credential |
| `principal` | string | On whose behalf: the user token's or forwarded transaction's `sub`, or the caller itself |
| `chain_profile` | string | The verified delegation chain's format (`aat-02`, `asor-03`, `rfc8693-act`); empty without one |
| `chain_issuer` | string | The chain's trust anchor |
| `chain_hops` | integer | Hops in the chain; 0 without one. At most 32: the invariant engine refuses a longer chain |
| `chain_actors` | string | The actor of every hop, first hop first, as a JSON array of strings (key thumbprints, names or subjects); it has `chain_hops` elements |
| `depth_semantics` | string | How the chain's depth bound was read: `aat-holder-cap`, `asor-strict` or `uncapped`; empty without a chain |
| `resource` | string | `scheme://authority/path`, without the query |
| `tool` | string | `params.name` of a JSON-RPC `tools/call` body; otherwise empty |
| `action` | string | The HTTP method |
| `decision` | string | `allow` or `deny` |
| `status` | integer | The HTTP status: 200 for an allow |
| `reason` | string | The stable reason code, `ok` for an allow |
| `detail` | string | Why, in words, for some denials. Identifiers only: a claim that does not parse is described (`a claim is malformed`, ``missing claim `exp` ``), never quoted |
| `pdp` | string | `allow`, `deny`, `error:<code>`, or `not_asked` when the gate stopped first |
| `remediation` | string | `none` (allowed), `reauthenticate` (401: answer the `WWW-Authenticate` challenge), `retry_later` (503), or `refused` |
| `hash` | string | SHA-256 of the record without `hash`, lowercase hex |

## The AIMS minimum

draft-ietf-wimse-aims §11 asks for these items. Each maps to members:

| AIMS item | Members |
| --- | --- |
| Agent id | `agent` |
| Delegating subject | `principal`, and the delegation in `chain_profile`, `chain_issuer`, `chain_hops`, `chain_actors`, `depth_semantics` |
| Resource or tool | `resource`, `tool` |
| Action and decision | `action`, `decision`, `status` |
| Timestamp and correlation id | `time`, `txn` (also `id`) |
| Posture or risk input | `auth_method`, `sender_constrained`, the `chain_*` members, `pdp` |
| Remediation and its cause | `remediation`, caused by `reason` and `detail` |

## Hash chain

`hash` is SHA-256 over the record serialized as JSON with the members in the order of the table above, `hash` left out, and no whitespace. Each record's `prev` is the previous record's `hash` and its `seq` is one more. A record changed, removed or inserted inside the log breaks the chain. `visado_extauthz::audit::verify_chain` checks a run of records deserialized into `AuditRecord`.

The chain lives in the process: a restart starts a new chain at `seq` 0 with an empty `prev`, which shows in the log. The chain detects edits, removals and insertions inside a copy of the log. It does not detect records cut from the end, or everything after a restart dropped, and it does not stop someone who can rewrite the whole log from writing a new chain. Ship the records off the host as they are written if that matters.

## What is never recorded

No token, proof, signature, digest, header value or body is copied into the record. Some members still carry text the request chose: the path in `resource`, the tool name in `tool`, the method in `action`, a token's `sub` or `act` in `principal` and `chain_actors`. In every text member (`id`, `txn`, `agent`, `principal`, `chain_issuer`, each element of `chain_actors`, `resource`, `tool`, `action`, `detail`), any JWS-looking text (`eyJ` and the base64url and dots after it) is replaced by `[token]`, before the request is authenticated as after. The resource path is recorded as received otherwise, without the query. Each of those members is then cut to 256 characters, so a request cannot make one record arbitrarily large; scrubbing comes first, so a cut cannot leave the start of a token too short to be recognized.
