FROM rust:1.100-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS build
WORKDIR /src
COPY . .
# The registry and target caches persist between local builds, so a rebuild
# compiles only the crates that changed. The binary is copied out because a
# cache mount is not part of the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p visado \
    && cp target/release/visado /visado

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /visado /usr/local/bin/visado
USER nonroot
ENTRYPOINT ["/usr/local/bin/visado"]
CMD ["/etc/visado/visado.toml"]
