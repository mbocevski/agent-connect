# The image of the end-to-end demos and the integration suite (demo/README
# in the main README's "Demos" section). One image runs every service: the
# relay, the daemons, the sample agents and the relay taps. It is the
# development build (`uv sync`, with the core's test hooks), for local
# demos and tests only: it is never pushed.
#
# Build from the repository root:
#   docker build -f demo/Dockerfile -t agentconnect-demo:dev .
# REAL_MODELS=1 also installs the Claude Agent SDK and LangGraph, for
# AC_EXAMPLE_MODEL=real (see the README).

FROM rust:1.99.1-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /usr/local/bin/uv
# rust-toolchain.toml asks for clippy and llvm-tools, which a build doesn't need.
ENV RUSTUP_TOOLCHAIN=1.99.1 \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=automatic
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p agentconnect-relay \
 && install -D target/release/agentconnect-relay /out/agentconnect-relay
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/root/.cache/uv \
    uv python install 3.13 \
 && uv sync --all-packages --frozen --no-dev --no-editable --python 3.13
ARG REAL_MODELS=0
RUN --mount=type=cache,target=/root/.cache/uv \
    if [ "$REAL_MODELS" = "1" ]; then \
      uv pip install --python /opt/venv/bin/python claude-agent-sdk==0.2.168 langgraph==1.2.16; \
    fi

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/python /opt/python
COPY --from=build /opt/venv /opt/venv
COPY --from=build /out/agentconnect-relay /usr/local/bin/agentconnect-relay
COPY examples /opt/examples
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    NO_COLOR=1
