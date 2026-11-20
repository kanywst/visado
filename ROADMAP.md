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
- **Status:** partly met. The ext_authz service and caller authentication by WIT+WPT, WIT+HTTP signature, mTLS with an X.509-SVID, JWT-SVID and OAuth access tokens, bearer or DPoP-bound (RFC 9449, without server nonces), are in, with tests against the gate and the gRPC handler. Runs behind a real Envoy in `deploy/lab`, which CI exercises with every method: WIT+WPT, WIT+HTTP signature, mTLS and JWT-SVIDs issued by SPIRE, and bearer and DPoP-bound access tokens.

## Phase 3: Delegation chains

- `NormalizedChain`, the invariant engine and the authority algebra. AAT-02 decoder, then asor-03, then the RFC 8693 `act` adapter.
- **Gate:** all 229 published AAT vectors and the 36 asor-03 vectors pass.
- **Status:** partly met. `visado-chain` (the normalized model), `visado-chain-aat` (§8 verification, 229/229 AAT vectors at the expected step), `visado-chain-asor` (§6 verification with DPoP and Token Status Lists, 36/36 asor-03 vectors with the expected outcome and 27 own status list vectors) and `visado-chain-act` (the RFC 8693 `act` claim of a verified access token, with the current actor bound to the caller; 20 own vectors) are in, and the ext_authz gate enforces all three formats. Not yet: the separate invariant engine and authority algebra.

## Phase 4: AuthZEN

- AuthZEN 1.0 client, the agent-and-principal profile, discovery, fail-closed handling.
- **Gate:** end to end against OPA with the AuthZEN plugin and one other PDP.
- **Status:** partly met. The client and the agent profile are in and run against OPA with the AuthZEN plugin in `deploy/lab`. Not yet run against a second PDP.

## Phase 5: Lab, visibility and demos

- `deploy/aims-lab`: Dex (ID-JAG), Keycloak (Resource AS), SPIRE (WIT-SVID), Envoy and agentgateway, two agents and an MCP server.
- Chain view UI, OpenTelemetry spans, and the audit record.
- Four attack demos: three that visado stops and one that it does not.
- **Gate:** `docker compose up` reproduces every demo from a clean checkout.
- **Status:** started. `deploy/lab` (Envoy with a plain and an mTLS listener, visado, OPA with the AuthZEN plugin, an echo upstream, SPIRE issuing WIT-SVIDs, X.509-SVIDs and JWT-SVIDs, Jaeger for the OpenTelemetry spans) runs twenty-three checks in CI. The chain view (`[chain_view]`, `/chain`) shows recent decisions and their delegation chains; the lab serves it on the host's loopback address. Not yet: Dex, Keycloak and agentgateway.

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
