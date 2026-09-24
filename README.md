<div align="center">

# agent-ssh-cli

基于 CLI 的 SSH 代理工具，按 ssh-mcp-server 的能力映射为 Agent 可调用的远端操作能力。

远程执行 · 文件上传 · 文件下载 · 连接配置 · 命令白名单 · 命令黑名单 · Agent Skill 集成

<p>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli"><img src="https://img.shields.io/badge/CLI-agentsshcli-2ea44f" alt="CLI agentsshcli"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="License MIT"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-%3E%3D18-339933?logo=node.js&logoColor=white" alt="Node.js >=18"></a>
  <a href="https://www.npmjs.com/"><img src="https://img.shields.io/badge/npm-%3E%3D8-CB3837?logo=npm&logoColor=white" alt="npm >=8"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli"><img src="https://img.shields.io/badge/sys-win%2Fmac%2Flinux-0078D6" alt="sys win/mac/linux"></a>
  <a href="https://github.com/sleepinginsummer/agent-ssh-cli/releases"><img src="https://img.shields.io/badge/release-v0.6.1-blue" alt="release v0.6.1"></a>
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
- 上传本地文件到远端服务器，支持临时文件、断点续传和失败重试
- 从远端服务器下载文件到本地
- 通过命令黑白名单限制可执行命令

## 上传稳定性

上传会先写入远端 `<remotePath>.part` 临时文件，并写入 `<remotePath>.part.meta` 续传元数据；完成后校验大小，再 rename 为正式目标文件。上传中断后，下次上传同一个本地文件到同一个远端路径会从已有 `.part` 大小继续。

`--no-cache` 上传可用 `Ctrl+C` 停止当前进程；daemon 模式可用 `agentsshcli stop-daemon` 停止连接池进程，但它会影响同一 daemon 内其它任务，不是精确取消单个上传。

## AI 一键安装

```
安装请阅读 https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/AI_INSTALL.md，按说明安装 CLI 并添加 `SKILL.md`。
```

## 手动安装
### 环境要求

- Node.js `>= 18`
- npm `>= 8`
- 系统支持 Windows / macOS / Linux
- 本机网络可访问目标 SSH 服务器
- 如使用私钥认证，私钥文件需对当前用户可读
- 预编译平台包支持 macOS arm64/x64、Linux x64/arm64、Windows x64

### 常用参数

- `exec --timeout <ms>`: 单次命令超时，默认 `30000`
- `upload` / `download --timeout <ms>`: 传输总超时，默认不限制（大文件允许长时间运行）
- `upload` / `download --recursive`: 递归传输目录，保持相对路径；符号链接不跟随，指向目录的链接跳过、指向文件的链接上传其内容
- `upload` 单文件上传不创建远端目录：目标目录不存在（或同名路径是文件）时报「远端目录不存在或不可访问」，请先创建目录，或改用 `--recursive` 上传整个目录
- 下载支持断点续传：中断后本地保留 `.part` 文件，下次自动从断点继续
- `exec` / `upload` / `download --json`: 输出结构化 JSON（`exitCode`/`stdout`/`stderr`），`exitCode` 为远端命令真实退出码，便于脚本和 AI 解析
- `agentsshcli init-config`: 生成默认配置文件到 `~/.agent-ssh-cli/config.json`
- `agentsshcli edit-config [--config <path>]`: 启动仅监听 `127.0.0.1` 的可视化配置编辑器并打开浏览器
- `agentsshcli stop-editor [--config <path>]`: 停止当前配置对应的编辑器服务
- `agentsshcli stop-daemon`: 停止当前配置对应的 SSH 缓存进程
- 远端会话异常终止时提示 `[remote] 会话异常终止（无退出状态）`，不会静默返回成功

### 安装步骤

1. 全局安装：

```bash
npm install -g agent-ssh-cli
agentsshcli --help
```

2. 导入 SKILL.md:

打开 [SKILL.md](SKILL.md)，将其添加到 agent 中。


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
- `password` / `passwordRef` / `privateKey`: 认证方式，密码、密码引用、私钥三类认证只能保留一种
- `port`: SSH 端口，默认 `22`
- `passphrase`: 私钥口令，仅配合 `privateKey` 使用
- `socksProxy`: SOCKS5 代理地址，例如 `socks5://127.0.0.1:1080`；也可省略协议写成 `127.0.0.1:1080`
- `jumpHost`: 跳板机连接名，填写配置文件中另一台机器的 `name`
- `pty`: 是否分配伪终端，默认 `false`，也可通过 `exec --pty` 临时开启
- `privilegeEnabled`: 是否允许该连接使用 `exec --sudo/--su`，默认 `false`
- `sudoUser`: sudo 目标用户，默认 `root`；`sudoPassword`/`sudoPasswordRef` 保存当前 SSH 用户的 sudo 密码，未配置时可复用 SSH 密码
- `suUser`: su 目标用户，默认 `root`；`suPassword`/`suPasswordRef` 必须独立配置目标用户密码
- `allowedLocalPaths`: 兼容旧配置字段，当前不限制本地路径
- `commandWhitelist`: 命令白名单正则数组
- `commandBlacklist`: 命令黑名单正则数组

`commandWhitelist` 和 `commandBlacklist` 使用 JavaScript `RegExp` 语法，不是 POSIX 正则；空白字符请写成 `\\s`，不要写 `[:space:]`。

完整示例见 [example.config.json](example.config.json)。`~/.agent-ssh-cli/config.json` 保存真实连接信息。

SSH 建连（含编辑器测试、跳板机、执行命令和文件传输）会按配置中的 `host` 与 `port` 核对本机 `~/.ssh/known_hosts`。未知或变化的服务器公钥会在发送 SSH 凭据前被拒绝，程序不会自动登记。首次连接前请通过可信渠道核实服务器公钥指纹，再将对应主机名和端口的公钥加入 `known_hosts`；非 22 端口需使用 `[host]:port` 格式。

推荐使用可视化配置编辑器管理连接和替换密码：运行 `agentsshcli edit-config`，在浏览器中修改后保存。新密码会加密写入配置目录下的 `secrets.json`，`config.json` 只保留 `passwordRef`。页面查看已保存密码时，明文由本机后端解密，只在页面短暂显示并于 15 秒后清除。

为兼容旧配置，CLI 仍支持明文凭据的被动迁移：首次写入 `password` 后，执行 `exec`、`upload` 或 `download` 连接该服务器时，会生成本地 `secret.key`，把密码加密保存到 `secrets.json`，并将配置中的明文字段替换为 `passwordRef`。sudo/su 明文凭据采用相同规则，但只在首次使用对应 flag 时迁移，密文 key 分别为 `agentsshcli:<name>:sudo` 和 `agentsshcli:<name>:su`。提权必须显式设置 `privilegeEnabled: true`。

### 可视化配置编辑器

启动默认配置对应的编辑器：

```bash
agentsshcli edit-config
```

指定配置文件：

```bash
agentsshcli edit-config --config /path/to/config.json
```

停止对应配置文件的编辑器服务：

```bash
agentsshcli stop-editor --config /path/to/config.json
```

编辑器行为：

- HTTP 服务只监听 `127.0.0.1`，启动后自动打开浏览器；访问 URL 的 fragment 中包含临时 token，不要复制到日志、工单或发给其他人。
- 同一配置文件只启动一个编辑器服务；再次运行 `edit-config` 会打开现有页面。
- 连续 10 分钟没有经过认证的有效 API 或真实页面输入时，服务自动退出并清理状态文件；旧 URL 随即失效。
- 后端负责最终配置校验和并发 hash 检查；配置被其他进程修改时保存返回冲突，需要重新载入后再编辑。
- JSON 面板支持“全局 / 当前连接”以及“预览 / 源码”；源码应用前仍会经过与表单一致的配置校验。
- “测试连接”使用当前连接及其跳板机的页面草稿（含未保存的临时密码），验证 SSH 建连和认证后立即断开；不会保存配置或执行远端命令。单次最长等待 15 秒，同一时刻只运行一个测试。
- 替换密码时只持久化加密后的 secret 和 `passwordRef`；复制连接不会复制密码引用或解密值。
- 编辑器不提供连接级 PTY 开关，但会保留旧配置中的 `pty`；临时控制继续使用 `exec --pty` / `--no-pty`。
- `stop-editor` 只停止本地配置编辑器，不会停止 SSH daemon、连接缓存或远端会话。

参考配置

```json
[
  {
    "name": "密码服务器",
    "host": "192.0.2.10",
    "port": 22,
    "username": "root",
    "password": "",
    "passwordRef": "agentsshcli:密码服务器",
    "jumpHost": "jump-server",
    "commandBlacklist": [
      "(^|[;&|()\\s])rm(\\s|$)",
      "(^|[;&|()\\s])shutdown(\\s|$)",
      "(^|[;&|()\\s])reboot(\\s|$)"
    ]
  },
  {
    "name": "jump-server",
    "host": "198.51.100.20",
    "port": 22,
    "username": "ubuntu",
    "privateKey": "/path/to/jump_key",
    "passphrase": "******",
    "socksProxy": "socks5://127.0.0.1:1080"
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

提权连接示例（需要使用时将开关设为 `true`）：

```json
{
  "name": "业务服务器",
  "host": "192.0.2.20",
  "username": "operator",
  "privateKey": "/path/to/id_rsa",
  "privilegeEnabled": true,
  "sudoUser": "root",
  "sudoPassword": "当前 SSH 用户的 sudo 密码",
  "suUser": "oracle",
  "suPassword": "oracle 用户密码"
}
```

```bash
agentsshcli exec --sudo 业务服务器 "systemctl status app"
agentsshcli exec --su 业务服务器 "id && pwd"
```

`--sudo` 和 `--su` 互斥。两种模式都只支持非交互命令，密码发送后会关闭远端 stdin；目标命令不能继续读取 stdin。sudo 会优先使用独立 sudo 凭据，缺失时复用 SSH 密码；私钥登录无法复用密码，必须配置独立 sudo 凭据。

测试命令

```bash
agentsshcli list
agentsshcli exec --no-cache 密码服务器 "pwd"
agentsshcli exec --pty 密码服务器 "tty"
agentsshcli exec 密码服务器 --command-file ./script.sh --timeout 60000
```
完成安装!

## 卸载和清理

更新到最新版：

```bash
npm install -g agent-ssh-cli@latest
```

卸载:

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
