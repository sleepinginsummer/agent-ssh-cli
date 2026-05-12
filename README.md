<div align="center">

# agent-ssh-cli

基于 CLI 的 SSH 代理工具，按 ssh-mcp-server 的能力映射为 Agent 可调用的远端操作能力。

远程执行 · 文件上传 · 文件下载 · 连接配置 · 命令白名单 · 命令黑名单 · Agent Skill 集成

<p>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli"><img src="https://img.shields.io/badge/CLI-agentsshcli-2ea44f" alt="CLI agentsshcli"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="License MIT"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-%3E%3D18-339933?logo=node.js&logoColor=white" alt="Node.js >=18"></a>
  <a href="https://www.npmjs.com/"><img src="https://img.shields.io/badge/npm-%3E%3D8-CB3837?logo=npm&logoColor=white" alt="npm >=8"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli"><img src="https://img.shields.io/badge/Windows-macOS-Linux-0078D6?labelColor=0078D6&color=C0C0C0" alt="Windows/macOS/Linux"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/releases"><img src="https://img.shields.io/badge/release-v0.2.1-blue" alt="release v0.2.1"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome"></a>
</p>

[AI 一键安装](#ai-一键安装) · [手动安装](#手动安装) · [配置](#配置) · [卸载和清理](#卸载和清理) · [许可证](#许可证) · [友情链接](#友情链接)

中文 | [English](README_EN.md)

</div>

## 简介
本项目参考 [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) 的 SSH 操作能力设计，改写为独立 CLI 形式。感谢原项目提供的思路和能力基础。

#### 他能做的事：
- 解放双手，自动运维服务器
- 部署代码，更新部署docker
- 配置nginx,配置证书
- 所有ssh能做到的事情
#### 他的能力：
- 列出本地配置中的 SSH 服务器连接
- 在指定远端服务器上执行命令
- 上传本地文件到远端服务器
- 从远端服务器下载文件到本地
- 通过命令黑白名单限制可执行命令
- 通过本地路径白名单限制上传和下载访问范围

## AI 一键安装

```
安装请阅读 https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/AI_INSTALL.md，按说明安装 CLI 并添加 `SKILL.md`。
```

## 手动安装
### 环境要求

- Node.js `>= 18`
- npm `>= 8`
- 本机网络可访问目标 SSH 服务器
- 目标服务器已开启 SSH 服务
- 如使用私钥认证，私钥文件需对当前用户可读
- 当前版本内部执行器已迁移到 Rust，npm 仍作为安装入口
- `agentsshcli exec/upload/download` 默认使用 Rust daemon 连接缓存，也可以通过 `--no-cache` 直连
- 预编译平台包支持 macOS arm64/x64、Linux x64/arm64、Windows x64

### 安装步骤

1. 全局安装：

```bash
npm install -g agent-ssh-cli
agentsshcli --help
```

2. 导入 SKILL.md:

打开 [SKILL.md](SKILL.md)，将其添加到 agent 中。

### 本地开发构建

当前仓库保留 npm 安装入口，实际执行逻辑由 Rust 原生二进制完成。开发或源码安装时需要先构建原生二进制：

```bash
npm run build:native
npm run build:native-bin
npm run build:native-package
npm test
```

执行链路：

```text
agentsshcli 命令
  -> bin/agentsshcli.js
  -> native/target/release/agentsshcli-native
```

已由 Rust 实现：

- `agentsshcli list`
- `agentsshcli init-config`
- `agentsshcli exec ...` / `agentsshcli exec --no-cache ...`
- `agentsshcli upload ...` / `agentsshcli upload --no-cache ...`
- `agentsshcli download ...` / `agentsshcli download --no-cache ...`
- Rust daemon 连接缓存与 `--cache-ttl`

发布 npm 包前先生成对应平台的预编译产物和平台子包，并检查包内容：

```bash
npm run build:native-package
npm pack --dry-run
(cd npm/darwin-arm64 && npm pack --dry-run)
```

发布形态为主包 `agent-ssh-cli` 加平台 optional 子包：`@agent-ssh-cli/darwin-arm64`、`@agent-ssh-cli/darwin-x64`、`@agent-ssh-cli/linux-x64`、`@agent-ssh-cli/linux-arm64`、`@agent-ssh-cli/win32-x64`。预编译产物目录格式：`native-bin/<platform>-<arch>/agentsshcli-native`，Windows 文件名为 `agentsshcli-native.exe`。

## 配置

初始化配置（格式参数和ssh-mcp-server一致）：

```bash
mkdir -p ~/.agent-ssh-cli
```

编辑 `~/.agent-ssh-cli/config.json`，填写真实连接信息。默认配置文件也可以通过环境变量覆盖：

可以通过以下环境变量修改配置地点
```bash
AGENT_SSH_CONFIG=/path/to/config.json
```

配置文件是数组，每一项是一台服务器：

- `name`: 连接名，必须唯一
- `host`: SSH 主机地址
- `username`: SSH 用户名
- `password` / `privateKey` / `agent`: 认证方式，三者必须且只能配置一个
- `port`: SSH 端口，默认 `22`
- `passphrase`: 私钥口令，仅配合 `privateKey` 使用
- `pty`: 是否分配伪终端，默认 `true`
- `allowedLocalPaths`: 额外允许上传或下载写入的本地路径
- `commandWhitelist`: 命令白名单正则数组
- `commandBlacklist`: 命令黑名单正则数组

`commandWhitelist` 和 `commandBlacklist` 使用 JavaScript `RegExp` 语法，不是 POSIX 正则；空白字符请写成 `\\s`，不要写 `[:space:]`。

完整示例见 [example.config.json](example.config.json)。`~/.agent-ssh-cli/config.json` 保存真实连接信息。

参考配置

```json
[
  {
    "name": "密码服务器",
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
    "name": "密钥服务器",
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



测试命令

```bash
agentsshcli list
agentsshcli exec --no-cache 密码服务器 "pwd"
```

完成安装!

## 卸载和清理

更新到最新版：

```bash
npm install -g agent-ssh-cli@latest
```

```bash
npm uninstall -g agent-ssh-cli
npm cache clean --force
#删除配置文件
rm -rf ~/.agent-ssh-cli
```

## 许可证

[MIT](LICENSE)

## 友情链接

- [LINUX DO - 新的理想型社区](https://linux.do/)
