# Build from the repository root:  docker build -f directory/Dockerfile -t agentconnect-directory .

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agentconnect-directory

# The distroless base ships the CA bundle the owner-file fetch verifies against.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/agentconnect-directory /usr/local/bin/agentconnect-directory
ENV AC_DIRECTORY_ADDR=0.0.0.0:8090
# AC_DIRECTORY_DB (a postgres:// URL) and AC_DIRECTORY_TOKEN_KEYS are required;
# set AC_DIRECTORY_HOST and AC_DIRECTORY_RELAYS for a real deployment.
EXPOSE 8090
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentconnect-directory"]
