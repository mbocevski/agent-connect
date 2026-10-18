# Build from the repository root:  docker build -f relay/Dockerfile -t agentconnect-relay .

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agentconnect-relay \
 && install -d -m 0700 /data-skel \
 && d="lib/$(gcc -dumpmachine)" \
 && mkdir -p "/out/$d" \
 && cp -L "$(gcc -print-file-name=libgcc_s.so.1)" "/out/$d/"

# base-nossl: glibc and the CA bundle, no libssl3. The binary links no system
# OpenSSL (SQLCipher uses a vendored, static one); libgcc_s comes from the build stage.
FROM gcr.io/distroless/base-nossl-debian12:nonroot@sha256:be40c00dfabd86576d92666e87e406714d5618342de1a0c213ad232de255172e
COPY --from=build /out/ /
COPY --from=build /src/target/release/agentconnect-relay /usr/local/bin/agentconnect-relay
COPY --from=build --chown=65532:65532 /data-skel /data
ENV AC_RELAY_ADDR=0.0.0.0:8080 \
    AC_RELAY_DB=/data/relay.db
# AC_RELAY_HOST must be set to the public host name clients connect to.
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentconnect-relay"]
