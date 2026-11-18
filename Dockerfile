# syntax=docker/dockerfile:1
FROM rust:1.91-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p visado

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/visado /usr/local/bin/visado
USER nonroot
ENTRYPOINT ["/usr/local/bin/visado"]
CMD ["/etc/visado/visado.toml"]
