FROM rust:1.91-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p visado

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/visado /usr/local/bin/visado
USER nonroot
ENTRYPOINT ["/usr/local/bin/visado"]
CMD ["/etc/visado/visado.toml"]
