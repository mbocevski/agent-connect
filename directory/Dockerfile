# Build from the repository root:  docker build -f directory/Dockerfile -t agentconnect-directory .

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agentconnect-directory \
 && d="lib/$(gcc -dumpmachine)" \
 && mkdir -p "/out/$d" \
 && cp -L "$(gcc -print-file-name=libgcc_s.so.1)" "/out/$d/"

# base-nossl: glibc and the CA bundle the owner-file fetch verifies against, no
# libssl3 (TLS is rustls). libgcc_s comes from the build stage.
FROM gcr.io/distroless/base-nossl-debian12:nonroot@sha256:be40c00dfabd86576d92666e87e406714d5618342de1a0c213ad232de255172e
COPY --from=build /out/ /
COPY --from=build /src/target/release/agentconnect-directory /usr/local/bin/agentconnect-directory
ENV AC_DIRECTORY_ADDR=0.0.0.0:8090
# AC_DIRECTORY_DB (a postgres:// URL), AC_DIRECTORY_HOST, AC_DIRECTORY_RELAYS (for example relay.example.org)
# and AC_DIRECTORY_TOKEN_KEYS are required. Set AC_DIRECTORY_CLIENT_IP_HEADER with
# AC_DIRECTORY_TRUSTED_PROXIES behind a proxy.
EXPOSE 8090
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentconnect-directory"]
