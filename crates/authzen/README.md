# visado-authzen

Client for the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) access evaluation endpoint.

Every failure is an error, never an allow: transport errors, non-200 responses, a `decision` that is not a JSON boolean, or a mismatched `X-Request-ID` echo. `EvaluationRequest::for_agent` puts the agent in `subject` and the user it acts for in `context.principal`.

Pre-alpha. Licensed under Apache-2.0.
