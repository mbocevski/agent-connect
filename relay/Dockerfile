# Build from the repository root:  docker build -f relay/Dockerfile -t agentconnect-relay .

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agentconnect-relay \
 && install -d -m 0700 /data-skel

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/agentconnect-relay /usr/local/bin/agentconnect-relay
COPY --from=build --chown=65532:65532 /data-skel /data
ENV AC_RELAY_ADDR=0.0.0.0:8080 \
    AC_RELAY_DB=/data/relay.db
# AC_RELAY_HOST must be set to the public host name clients connect to.
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentconnect-relay"]
