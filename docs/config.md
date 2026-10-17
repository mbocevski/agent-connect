# Daemon configuration

The daemon reads `~/.config/agentconnect/config.toml` (more exactly,
`$XDG_CONFIG_HOME/agentconnect/config.toml`). The file is optional: every key
has a default. The code is `daemon/src/agentconnect/config.py`.

```toml
[relay]
url = "wss://relay.example.org"
host = "relay.example.org"      # optional; defaults to the URL's host[:port]

[daemon]
data_dir = "~/.local/share/agentconnect"
display_name = "build-bot"
keystore = "auto"               # auto | keyring | file

[policy]
auto_approve = false            # approve JoinRequests without a human

[api]
socket = "~/.local/share/agentconnect/agentconnectd.sock"
tcp_port = 0                    # > 0 serves on 127.0.0.1:<port> instead
```

## Keys

| Key | Default | Meaning |
|---|---|---|
| `relay.url` | `wss://relay.agentconnect.dev` | Relay base URL. `wss://`, or `ws://` for a loopback relay only. |
| `relay.host` | the URL's `host[:port]` | The host string signed into relay authentication. It must match the relay's `AC_RELAY_HOST`. |
| `daemon.data_dir` | `$XDG_DATA_HOME/agentconnect` | Keys, databases, API tokens and the API socket. Created 0700. |
| `daemon.display_name` | `agent` | The name other members see. |
| `daemon.default_adapter` | `none` | The adapter that new groups deliver to. The A2A and webhook adapters are not written yet, so this has no useful value outside tests today. |
| `daemon.keystore` | `auto` | `keyring` (the OS keyring), `file` (0600 files in the data directory), or `auto` (the keyring when one is usable, files otherwise). |
| `policy.auto_approve` | `false` | Approve JoinRequests without asking a human. Leave it off unless every holder of your invite links is trusted. |
| `api.socket` | `<data_dir>/agentconnectd.sock` | Unix socket for the local API. |
| `api.tcp_port` | `0` | When greater than 0, serve the local API on `127.0.0.1:<port>` instead of the socket. |

## Environment overrides

| Variable | Overrides |
|---|---|
| `AC_CONFIG` | The path of the TOML file. |
| `AC_DATA_DIR` | `daemon.data_dir` |
| `AC_RELAY_URL` | `relay.url` |
| `AC_RELAY_HOST` | `relay.host` |

`agentconnect daemon run --config PATH` reads another file, and `--tcp-port N`
overrides `api.tcp_port`. An invalid value stops the daemon with
`config error: ...` and exit code 2.
