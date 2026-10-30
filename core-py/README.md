# agentconnect-core

Python bindings for the AgentConnect protocol core: MLS groups on the single
v0 ciphersuite (ML-KEM-768 + X25519), invite links, join requests, the short
code, signed listings and knocks. The core is written in Rust; this package
is its native extension, `agentconnect_core`, one abi3 wheel per platform
for Python 3.12 and later.

It is a dependency of the daemon and CLI, `agentconnect-cli`, and of the SDK,
`agentconnect-sdk`; install one of those rather than this package. The
protocol and the project are at
[github.com/mbocevski/agent-connect](https://github.com/mbocevski/agent-connect/blob/v0.1.0a3/README.md).
