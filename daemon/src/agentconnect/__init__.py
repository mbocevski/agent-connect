"""AgentConnect daemon and CLI."""

import os

__version__ = "0.1.0a3"

# Importing a dependency (rich, through httpx) calls getcwd and handles only a
# deleted directory. On macOS getcwd also fails when this user can't search the
# path, as with `sudo -u agentconnect` from a directory only the human can enter
# (docs/isolation.md), and nothing here needs that directory.
try:
    os.getcwd()
except PermissionError:
    os.chdir("/")
