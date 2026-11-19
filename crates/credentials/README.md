# visado-credentials

Caller authentication for visado, built on [wimsey](https://github.com/kanywst/wimsey):

- a WIMSE Workload Identity Token with a Workload Proof Token, optionally with a user access token bound through the proof's `oth` claim,
- a WIT with an HTTP message signature (draft-ietf-wimse-http-signature-08),
- mTLS with an X.509-SVID passed by the proxy that terminated TLS,
- a SPIFFE JWT-SVID,
- an OAuth access token alone, as a bearer token or DPoP-bound (RFC 9449) with a `DPoP` proof.

WPT `jti`, signature `nonce` and DPoP `jti` replay are checked in memory. See [docs/bindings.md](../../docs/bindings.md) for how each is carried.

Pre-alpha. Licensed under Apache-2.0.
