# SPIRE v1.16.0 binaries on Alpine, so the setup steps can use a shell.
FROM ghcr.io/spiffe/spire-server:1.16.0@sha256:ff546f4c62dafc479a0cd79eae9a7b6df2975754d75efd31706098e0d7548837 AS server
FROM ghcr.io/spiffe/spire-agent:1.16.0@sha256:ab3a8ce70435374cc5d84c81eabf0278dc046ddbc0a736d59694ba9e5975b1b6 AS agent

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache jq \
 && adduser -D -u 1001 agent-a \
 && adduser -D -u 1002 agent-b \
 && adduser -D -u 1003 agent-z \
 && adduser -D -u 1004 gateway
COPY --from=server /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY --from=agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
