# visado-chain

The format-neutral model of a delegation chain: `NormalizedChain`, `Hop`, how each hop's signer and link were checked, and the `ChainDecoder` trait that each chain format implements.

Decoders:

- [`visado-chain-aat`](https://github.com/kanywst/visado/tree/main/crates/chain-aat): draft-niyikiza-oauth-attenuating-agent-tokens-02
- [`visado-chain-asor`](https://github.com/kanywst/visado/tree/main/crates/chain-asor): draft-asor-wimse-agent-delegation-chain-03
- [`visado-chain-act`](https://github.com/kanywst/visado/tree/main/crates/chain-act): the RFC 8693 `act` claim of an access token

Pre-alpha. Licensed under Apache-2.0.
