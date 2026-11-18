# visado-extauthz

The visado decision pipeline and its Envoy ext_authz v3 gRPC service: authenticate the caller, ask an AuthZEN PDP, mint or forward a Transaction Token, and strip the inbound credentials before the request goes upstream.

Pre-alpha. Licensed under Apache-2.0.
