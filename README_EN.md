<div align="center">

# agent-ssh-cli

A CLI-based SSH agent tool that maps ssh-mcp-server capabilities into remote operations callable by agents.

Remote exec · File upload · File download · Connection config · Command whitelist · Command blacklist · Agent Skill integration

<p>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli"><img src="https://img.shields.io/badge/CLI-agentsshcli-2ea44f" alt="CLI agentsshcli"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="License MIT"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-%3E%3D18-339933?logo=node.js&logoColor=white" alt="Node.js >=18"></a>
  <a href="https://www.npmjs.com/"><img src="https://img.shields.io/badge/npm-%3E%3D8-CB3837?logo=npm&logoColor=white" alt="npm >=8"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli"><img src="https://img.shields.io/badge/Windows-macOS-Linux-0078D6?labelColor=0078D6&color=C0C0C0" alt="Windows/macOS/Linux"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/releases"><img src="https://img.shields.io/badge/release-v0.2.1-blue" alt="release v0.2.1"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome"></a>
</p>

[AI One-Click Installation](#ai-one-click-installation) · [Manual Installation](#manual-installation) · [Configuration](#configuration) · [Uninstall and Cleanup](#uninstall-and-cleanup) · [License](#license) · [Friendly Links](#friendly-links)

[中文](README.md) | English

</div>

## Introduction
This project references the SSH operation design from [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) and rewrites it as an independent CLI. Thanks to the original project for the ideas and capability foundation.

#### What it can do:
- Free your hands and automate server operations
- Deploy code and update Docker deployments
- Configure nginx and certificates
- Do anything SSH can do

#### Its capabilities:
- List SSH server connections from local configuration
- Execute commands on a specified remote server
- Upload local files to a remote server
- Download files from a remote server to local
- Restrict executable commands through command allowlists and blocklists
- Restrict upload and download access scopes through a local path allowlist

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
- The runtime has been migrated to Rust while npm remains the installation entry
- `agentsshcli exec/upload/download` use the Rust daemon connection cache by default, and can still run directly with `--no-cache`
- Prebuilt platform packages support macOS arm64/x64, Linux x64/arm64, and Windows x64

### Installation Steps

1. Install globally:

```bash
npm install -g agent-ssh-cli
agentsshcli --help
```

2. Import SKILL.md:

Open [SKILL.md](SKILL.md) and add it to the agent.

### Local development build

The package keeps the npm command entry, while the actual runtime uses a Rust native binary. When installing from source, build the native binary first:

```bash
npm run build:native
npm run build:native-bin
npm run build:native-package
npm test
```

Execution path:

```text
agentsshcli command
  -> bin/agentsshcli.js
  -> native/target/release/agentsshcli-native
```

Implemented in Rust:

- `agentsshcli list`
- `agentsshcli init-config`
- `agentsshcli exec ...` / `agentsshcli exec --no-cache ...`
- `agentsshcli upload ...` / `agentsshcli upload --no-cache ...`
- `agentsshcli download ...` / `agentsshcli download --no-cache ...`
- Rust daemon connection cache and `--cache-ttl`

Before publishing the npm package, generate the prebuilt binary and platform package for the target platform, then inspect the package contents:

```bash
npm run build:native-package
npm pack --dry-run
(cd npm/darwin-arm64 && npm pack --dry-run)
```

The publish layout is the main `agent-ssh-cli` package plus optional platform packages: `@agent-ssh-cli/darwin-arm64`, `@agent-ssh-cli/darwin-x64`, `@agent-ssh-cli/linux-x64`, `@agent-ssh-cli/linux-arm64`, and `@agent-ssh-cli/win32-x64`. Prebuilt binaries use this layout: `native-bin/<platform>-<arch>/agentsshcli-native`; Windows uses `agentsshcli-native.exe`.

## Configuration

Initialize the configuration. The format parameters are compatible with ssh-mcp-server:

```bash
mkdir -p ~/.agent-ssh-cli
```

Edit `~/.agent-ssh-cli/config.json` and fill in the real connection information. The default configuration file path can also be overridden with an environment variable:

You can change the configuration location with the following environment variable:
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

Reference configuration

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

Test command

```bash
agentsshcli list
agentsshcli exec --no-cache password-server "pwd"
```

Installation is complete.

## Uninstall and Cleanup

Update to the latest version:

```bash
npm install -g agent-ssh-cli@latest
```

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
