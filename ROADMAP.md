# Roadmap

The North Star is a vendor-neutral, conformance-tested reference implementation of the WIMSE AIMS composition at the enforcement point, in a neutral home (CNCF Sandbox). Each phase has a gate that must be green before the next one starts. Re-check every **Status** line against the code whenever this file is reviewed.

Dates target IETF 128 (Kuala Lumpur, 2027-03-06 to 03-12; hackathon dates not yet confirmed) and KubeCon + CloudNativeCon Europe (Barcelona, 2027-03-15 to 03-18).

## Phase 0: Foundation

- Cargo workspace, Apache-2.0, governance files, CI (fmt, clippy `-D warnings`, test, cargo-deny, DCO), OpenSSF Scorecard, `SPEC-MAP.md` with pinned draft revisions.
- **Gate:** CI green; every hygiene file in place.
- **Status:** met.

## Phase 1: Transaction Tokens (`txn-token`)

- Mint, verify and replace Txn-Tokens per draft-ietf-oauth-transaction-tokens-11. Conformance vectors with negative cases.
- **Gate:** vectors pass, and replacement rules (`txn`/`sub`/`aud` fixed, scope never widens, expired tokens refused) fail closed.
- **Status:** met. `visado-txn-token` with 5 valid and 22 negative vectors in `conformance/txn-token/`.

## Phase 2: ext_authz and caller authentication

- `tonic` ext_authz server. Credential verifiers for WIT+WPT, WIT+HTTP-sig and mTLS (via `wimsey`), JWT-SVID, and OAuth access tokens (RS256/ES256, DPoP).
- **Gate:** Envoy integration test admits valid callers, rejects each negative case with its reason code, and injects a Txn-Token.
- **Status:** met. The ext_authz service and caller authentication by WIT+WPT, WIT+HTTP signature, mTLS with an X.509-SVID, JWT-SVID and OAuth access tokens (EdDSA, RS256 and ES256), bearer or DPoP-bound (RFC 9449, with optional resource server nonces), are in, with tests against the gate and the gRPC handler. `deploy/lab` runs them behind a real Envoy in CI: it admits a caller of every method (WIT+WPT, WIT+HTTP signature, mTLS and JWT-SVIDs issued by SPIRE, a bearer access token, and a DPoP-bound one after the `use_dpop_nonce` retry), checks visado's reason code on every denial visado decides, and checks that the upstream receives the minted Txn-Token, which the next hop forwards.

## Phase 3: Delegation chains

- `NormalizedChain`, the invariant engine and the authority algebra. AAT-02 decoder, then asor-03, then the RFC 8693 `act` adapter.
- **Gate:** all 229 published AAT vectors and the 36 asor-03 vectors pass.
- **Status:** met. `visado-chain` (the normalized model, the format-neutral invariant engine and the `AuthorityAlgebra` registry), `visado-chain-aat` (§8 verification, 229/229 AAT vectors at the expected step), `visado-chain-asor` (§6 verification with DPoP and Token Status Lists, 36/36 asor-03 vectors with the expected outcome and 27 own status list vectors) and `visado-chain-act` (the RFC 8693 `act` claim of a verified access token, with the current actor bound to the caller; 20 own vectors) are in, each format crate with the authority algebra of its type. The ext_authz gate enforces all three formats and runs every chain through the engine after the format's checks; the engine agrees with every AAT, asor and act vector and has 39 own vectors in `conformance/chain-invariants/`.

## Phase 4: AuthZEN

- AuthZEN 1.0 client, the agent-and-principal profile, discovery, fail-closed handling.
- **Gate:** end to end against OPA with the AuthZEN plugin and one other PDP.
- **Status:** met. The client and the agent profile run end to end in `deploy/lab` against OPA with the AuthZEN plugin and against Cerbos, which serves AuthZEN 1.0 itself; CI runs the lab's checks against both. Cerbos does not pass `context` to the policy, so the Cerbos lab sets `[pdp] context_in_subject`.

## Phase 5: Lab, visibility and demos

- `deploy/aims-lab`: Dex (ID-JAG), Keycloak (Resource AS), SPIRE (WIT-SVID), Envoy and agentgateway, two agents and an MCP server.
- Chain view UI, OpenTelemetry spans, and the audit record.
- Four attack demos: three that visado stops and one that it does not.
- **Gate:** `docker compose up` reproduces every demo from a clean checkout.
- **Status:** started. `deploy/lab` (Envoy with a plain and an mTLS listener, agentgateway, visado, OPA with the AuthZEN plugin or Cerbos as the PDP, an echo upstream, SPIRE issuing WIT-SVIDs, X.509-SVIDs and JWT-SVIDs, Jaeger for the OpenTelemetry spans) runs forty-four checks in CI, once with each PDP. agentgateway v1.7.0 is a second front proxy that calls visado over ext_authz gRPC; a subset of the scenarios runs through it, over a plain HTTP route rather than its MCP backend. The chain view (`[chain_view]`, `/chain`) shows recent decisions and their delegation chains; the lab serves it on the host's loopback address. Not yet: Dex, Keycloak, and an agentgateway MCP backend route.

## Phase 6: Interop and launch

- Interop at the IETF 128 hackathon (Transaction Tokens, delegation chains).
- Implementation Status entries in the drafts visado implements.
- Research write-up, then the release announcement.
- **Gate:** at least one cross-implementation interop result published.
- **Status:** not started.

## Phase 7: CNCF Sandbox

- A maintainer from a second organization, adopters listed, OpenSSF Best Practices badge, Security Insights file. Then apply.
- **Gate:** CLOMonitor checks pass, and the maintainer list spans more than one organization.
- **Status:** not started.
