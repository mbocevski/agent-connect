- `agentconnect trust rule` and the human-only `/v0/trust/rules` routes read and
  change standing rules (ADR-007). No kind of rule can be created yet, so this
  changes no behaviour. Outside the separate-OS-user mode, creating, widening or
  enabling one will answer `409 needs_isolation`.
