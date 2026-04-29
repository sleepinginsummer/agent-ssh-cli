# agent-ssh-cli

This project references the SSH operation design from [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) and rewrites it as an independent CLI. Thanks to the original project for the ideas and capability foundation.

[中文](README.md) | [English](README_EN.md)

## Navigation

- [AI One-Click Installation](#ai-one-click-installation)
- [Manual Installation](#manual-installation)
- [Uninstall and Cleanup](#uninstall-and-cleanup)
- [License](#license)
- [Friendly Links](#friendly-links)

## AI One-Click Installation

```text
Please read https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/AI_INSTALL.md, follow the instructions to install the CLI, and add `SKILL.md`.
```

## Manual Installation

### Requirements

- Node.js `>= 18`
- npm `>= 8`
- Local network access to the target SSH server
- SSH service enabled on the target server
- If private key authentication is used, the private key file must be readable by the current user
- The connection cache for `agentsshcli exec/upload/download` only supports macOS/Linux

### Installation Steps

1. Install globally:

```bash
npm install -g github:sleepinginsummer/agent-ssh-cli
agentsshcli --help
```

2. Initialize the configuration. The format is compatible with ssh-mcp-server:

```bash
mkdir -p ~/.agent-ssh-cli
```

Edit `~/.agent-ssh-cli/config.json` and fill in the real connection information. The default configuration file path can also be overridden with an environment variable:

```bash
AGENT_SSH_CONFIG=/path/to/config.json
```

The configuration file is an array, and each item represents one server:

- `name`: Connection name, must be unique
- `host`: SSH host address
- `username`: SSH username
- `password` / `privateKey` / `agent`: Authentication method; exactly one of the three must be configured
- `port`: SSH port, defaults to `22`
- `passphrase`: Private key passphrase, only used with `privateKey`
- `pty`: Whether to allocate a pseudo-terminal, defaults to `true`
- `allowedLocalPaths`: Extra local paths allowed for upload or download writes
- `commandWhitelist`: Command whitelist regular expression array
- `commandBlacklist`: Command blacklist regular expression array

`commandWhitelist` and `commandBlacklist` use JavaScript `RegExp` syntax, not POSIX regular expressions. Write whitespace as `\\s`; do not use `[:space:]`.

See the full example in [example.config.json](example.config.json). Store real connection information in `~/.agent-ssh-cli/config.json`.

```json
[
  {
    "name": "password-server",
    "host": "192.0.2.10",
    "port": 22,
    "username": "root",
    "password": "******",
    "commandBlacklist": [
      "(^|[;&|()\\s])rm(\\s|$)",
      "(^|[;&|()\\s])shutdown(\\s|$)",
      "(^|[;&|()\\s])reboot(\\s|$)"
    ]
  },
  {
    "name": "key-server",
    "host": "198.51.100.10",
    "port": 22,
    "username": "deploy",
    "privateKey": "/path/to/id_rsa",
    "passphrase": "******",
    "pty": false,
    "allowedLocalPaths": [
      "./tmp",
      "./dist"
    ],
    "commandWhitelist": [
      "^pwd$",
      "^ls(\\s|$)",
      "^cat\\s+/var/log/app\\.log$"
    ],
    "commandBlacklist": [
      "(^|[;&|()\\s])rm(\\s|$)",
      "(^|[;&|()\\s])shutdown(\\s|$)",
      "(^|[;&|()\\s])reboot(\\s|$)"
    ]
  }
]
```

3. Add `SKILL.md` to the agent.

Test command:

```bash
agentsshcli list
```

Installation is complete.

## Uninstall and Cleanup

```bash
npm uninstall -g agent-ssh-cli
npm cache clean --force
# Delete the configuration file
rm -rf ~/.agent-ssh-cli
```

## License

[MIT](LICENSE)

## Friendly Links

- [LINUX DO - A New Ideal Community](https://linux.do/)
