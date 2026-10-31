- The CLI in the separate-OS-user mode. A human-only command run as an agent's
  user now says it needs the human token, not "cannot reach the daemon", and an
  agent's user pointed at the daemon's own configuration gets an error naming
  `AC_DATA_DIR`, not a Python traceback. `approvals list` works with the agent
  token there, as its reference says.
