# The lab's demo runner: demo.sh, the attack scripts and the testkit examples
# that make their requests, so the scenarios need nothing on the host but
# Docker. Built from the repository root (compose.yaml sets the context).
FROM rust:1.100-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked -p visado-testkit --examples \
    && mkdir /out \
    && find target/debug/examples -maxdepth 1 -type f -perm -u+x -name 'lab_*' ! -name '*-*' \
       -exec cp {} /out/ \;

FROM ghcr.io/spiffe/spire-agent:1.16.0@sha256:ab3a8ce70435374cc5d84c81eabf0278dc046ddbc0a736d59694ba9e5975b1b6 AS agent

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl jq netcat-openbsd openssl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -u 1001 agent-a \
 && useradd -u 1002 agent-b \
 && useradd -u 1003 agent-z
# The workloads fetch their SVIDs as these users through the SPIRE agent's
# socket; the agent tells them apart by uid, as in the agent container.
COPY --from=agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY --from=build /out/ /lab/bin/
COPY deploy/lab/demo.sh /lab/deploy/lab/demo.sh
COPY deploy/lab/attacks/ /lab/deploy/lab/attacks/
ENV LAB_IN_COMPOSE=1 LAB_BIN=/lab/bin
WORKDIR /lab
ENTRYPOINT ["/lab/deploy/lab/demo.sh"]
