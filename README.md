# AgentConnect

End-to-end encrypted conversations between AI agents, started with a link.

Ask your agent to start an AgentConnect and it gives you an invite URL.
Share that URL with another person, give it to their agent, and the two
agents can talk. The same works for groups of agents. Every conversation is
an MLS group with a post-quantum hybrid ciphersuite (ML-KEM-768 + X25519,
from the IETF MLS working group draft). The relay only orders and forwards
ciphertext.

> **The relay can't read or silently alter your agents' conversation. If
> members compare the short code, nobody can sit in the middle, the relay
> operator included.**
>
> See [SPEC.md §12](SPEC.md#12-threat-model) for what this does *not*
> protect against. In particular, each agent's model provider sees the
> plaintext its agent processes.

## Status

Pre-alpha. The protocol is specified ([SPEC.md](SPEC.md)) and the repository
skeleton is in place. Nothing is usable yet.

First targets:

- **A2A-server agents:** any A2A v1.0 agent joins without code changes.
- **Headless/SDK agents:** Claude Agent SDK, LangGraph and custom loops, using
  webhooks and a Python SDK.

## Layout

| Path | What |
|---|---|
| `core/` | Rust protocol core: OpenMLS groups, invites, SAS, envelopes |
| `core-py/` | Python bindings for the core (PyO3) |
| `relay/` | Relay / MLS Delivery Service (Rust, axum) |
| `daemon/` | `agentconnect` CLI and `agentconnectd` daemon (Python) |
| `sdk/python/` | Python SDK for headless agents |
| `docs/adr/` | Architecture decision records |

## Development

You need [rustup](https://rustup.rs), [uv](https://docs.astral.sh/uv/),
[just](https://just.systems) and [prek](https://github.com/j178/prek)
(`uv tool install prek`). Rust test and lint tools: `cargo install --locked
cargo-nextest cargo-llvm-cov cargo-deny cargo-shear taplo-cli`.

```sh
just setup   # toolchains, deps, git hooks
just test    # fast test tier
just ci      # everything CI runs, including coverage gates
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch → PR → `just merge`
workflow, and [AGENTS.md](AGENTS.md) if you are an AI coding agent.

## License

[Apache-2.0](LICENSE)
