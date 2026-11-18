# visado

**See and verify every hop of an AI agent's delegation chain, and hand it downstream as an IETF Transaction Token.**

*visado* is Spanish for "visa'd": checked and allowed through.

> **Pre-design.** Nothing is implemented yet. This repository holds the research, scope and design. See [ROADMAP.md](ROADMAP.md).

## The problem

An agent calls another agent, which calls a tool. By the last hop, the service receiving the call usually knows a bearer token and little else. It cannot tell who the request is really for, which agents it passed through, or whether any of them widened the authority they were given. This is the confused deputy problem, and multi-agent systems make it routine.

The standards to fix it now exist in pieces:

- IETF WIMSE says who a workload is.
- Agent delegation tokens say who acted for whom.
- OAuth Transaction Tokens carry the verified context through a call chain.
- ID-JAG starts the chain at the user's identity provider.
- OpenID AuthZEN asks a policy engine for the decision.

No open-source component puts them together where the call is enforced.

## What visado does

At each enforcement point (Envoy, Istio or agentgateway, through ext_authz), visado:

1. verifies the caller's workload credential (WIMSE WIT with WPT, HTTP signatures or mTLS; SPIFFE SVIDs; OAuth access tokens),
2. verifies the delegation chain and checks that authority only narrows at each hop,
3. asks any AuthZEN 1.0 policy decision point whether the call is allowed,
4. mints a Transaction Token carrying the verified chain for the services behind it,
5. records the decision as an audit record and an OpenTelemetry span, and shows the chain per request.

It does not issue identities, log users in, evaluate policy or route traffic. See [docs/scope.md](docs/scope.md).

## Documents

- [docs/scope.md](docs/scope.md): what visado is and is not
- [docs/design.md](docs/design.md): the request pipeline, plugins and the reference lab
- [docs/research/](docs/research/): the research behind both
- [ROADMAP.md](ROADMAP.md): phases toward a CNCF Sandbox application

## License

[Apache-2.0](LICENSE)
