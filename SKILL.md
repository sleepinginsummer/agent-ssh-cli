---
name: agent-ssh-cli
description: 使用基于 SSH 的 CLI 安全操作远端服务器并管理本地连接配置。适用于列出连接、远程执行命令、上传下载文件、启动或停止可视化配置编辑器，以及确认参数、返回值、配置路径和环境校验步骤的场景。
---

# agent-ssh-cli 使用说明

`agentsshcli` 是一个通过 npm 安装、由 Rust 原生执行器完成 SSH 操作的命令行工具，用于让 AI 或用户通过本地配置安全地操作远端服务器。

它能做的事：

- 列出本地配置中的 SSH 服务器连接
- 在指定远端服务器上执行命令
- 上传本地文件到远端服务器
- 从远端服务器下载文件到本地
- 通过命令黑白名单限制可执行命令
- 通过 Rust daemon 短时间缓存 SSH 连接，减少连续操作时的重复连接开销
- 通过仅监听本机回环地址的可视化编辑器管理连接、凭据引用和安全策略
- npm 安装会按当前系统自动拉取对应平台的 optional 预编译包，当前支持 macOS arm64/x64、Linux x64/arm64、Windows x64

它不做的事：

- 不输出明文密码、私钥等敏感认证信息；密码可按配置加密保存到本机 `secrets.json`，仅通过 SSH channel stdin 发送
- 不扫描网络或发现服务器，只使用配置文件中的连接
- 不绕过配置中的命令限制

命令黑白名单使用 JavaScript `RegExp` 语法，不是 POSIX 正则。空白字符要写成 `\\s`，不要写 `[:space:]`。例如：

```json
{
  "commandBlacklist": [
    "(^|[;&|()\\s])rm(\\s|$)",
    "(^|[;&|()\\s])shutdown(\\s|$)",
    "(^|[;&|()\\s])reboot(\\s|$)"
  ]
}
```

## 安全确认

执行危险操作前必须先向用户确认，不能直接执行。

危险操作包括：

- 删除、清空、覆盖文件或目录，例如 `rm`、`truncate`、重定向覆盖、批量删除
- 清理缓存、日志、临时目录或业务数据
- 重启、关机、停止服务或杀进程，例如 `reboot`、`shutdown`、`systemctl stop`、`kill`
- 修改权限、所有者、系统配置或启动项，例如 `chmod`、`chown`、编辑 `/etc` 下文件
- 上传文件覆盖远端已有文件
- 下载文件覆盖本地已有文件
- 任何不可逆、影响线上服务、影响数据完整性的操作

确认时必须说明目标连接名、命令或文件路径、可能影响，并等待用户明确同意后再执行。

## 环境校验

调用前优先检查 CLI 本身是否可用：

```bash
agentsshcli --help
```

如果上面的命令失败，再向下检查基础环境：

```bash
node --version
npm --version
```

如果 `node` 或 `npm` 不存在，提示用户先安装 Node.js `>= 18` 和 npm `>= 8`。

CLI 可用后，再检查配置文件是否存在：

```bash
test -f "${AGENT_SSH_CONFIG:-$HOME/.agent-ssh-cli/config.json}"
```

如果配置文件不存在，提示用户创建配置文件，不继续执行 SSH 命令：

```bash
mkdir -p ~/.agent-ssh-cli
# 然后让用户编辑 ~/.agent-ssh-cli/config.json，填入真实服务器配置
```

默认配置文件：

```text
~/.agent-ssh-cli/config.json
```

所有 SSH 建连（含跳板机与编辑器“测试连接”）都会按配置中的主机名和端口校验 `~/.ssh/known_hosts`。未登记或公钥变更时不得绕过校验或自动信任；先通过可信渠道核实服务器公钥指纹，再登记对应主机（非 22 端口为 `[host]:port`）。

推荐通过 `agentsshcli edit-config` 替换密码：编辑器保存时会把新密码加密写入 `secrets.json`，配置文件只保留 `passwordRef`。旧配置仍支持被动迁移：若连接包含非空明文 `password`，下一次执行 `exec`、`upload` 或 `download` 时会生成 `secret.key`、加密保存密码，并把明文字段替换为引用。不要在对话、日志或命令输出中展示明文密码。

## edit-config / stop-editor

使用本机可视化编辑器管理 SSH 连接：

```bash
agentsshcli edit-config [--config <path>]
agentsshcli stop-editor [--config <path>]
```

调用规则：

- 用户要求打开、编辑或可视化管理 SSH 配置时，直接运行 `edit-config`；不要自行调用内部 `__editor` 子命令或拼装 HTTP API。
- 编辑器只监听 `127.0.0.1`，启动后自动打开浏览器。同一配置路径只运行一个实例；重复执行会打开已有实例。
- CLI 输出的本地 URL fragment 含临时 token，应按凭据处理，不写入日志、工单或对外消息；只有用户明确需要手动访问地址时才在当前本地会话中提供。
- 连续 10 分钟没有经过认证的有效 API 或真实 `pointerdown`、`keydown`、`input` 时，编辑器自动退出并删除状态文件。页面失效后重新运行 `edit-config`。
- `stop-editor` 只停止该配置对应的本地编辑器，不会停止 SSH daemon、缓存连接或远端任务。
- 不要在用户可能仍有未保存页面修改时自行执行 `stop-editor`；仅在用户明确要求停止或已确认可以放弃未保存内容时调用。
- `edit-config` / `stop-editor` 支持 `--config`、`--help` 和 `--version`，不接受 `--no-cache`、`--cache-ttl` 或位置参数。
- 配置文件可能被其它进程修改；保存返回冲突时先重新载入，不得绕过 hash 检查或直接覆盖。
- JSON 面板支持“全局 / 当前连接”和“预览 / 源码”；后端校验是最终配置契约，前端提示不能替代保存结果。
- 页面“测试连接”用当前草稿与相关跳板机进行一次 SSH 建连和认证（包括未保存的密码草稿），完成后断开，不保存配置、不执行命令；同时只能进行一次测试。
- 查看密码会由本机后端解密，明文只在页面短暂显示并于 15 秒后清除；不要通过终端、脚本或 HTTP 调试接口提取密码。
- 替换密码应使用页面的替换操作；保存后 `config.json` 只保留 `passwordRef`，密文写入同目录的 `secrets.json`。复制连接不会复制密码引用。
- 编辑器不显示连接级 PTY 控件，但会透传已有 `pty`；执行命令时继续使用 `exec --pty` / `--no-pty` 临时覆盖。

返回行为：

- `edit-config` 成功时 stdout 输出 `配置编辑器已打开: <local-url>`，退出码为 `0`。浏览器打开失败时错误信息包含可手动访问的本地 URL。
- `stop-editor` 成功时 stdout 输出 `配置编辑器已停止`；没有对应服务时返回 `配置编辑器未运行`，退出码为 `1`。
- 编辑器保存冲突、配置校验失败或凭据引用不完整时，不应改写原配置；根据页面或 stderr 的具体错误处理。

隐藏后的密码配置示例：

```json
{
  "name": "server",
  "host": "192.0.2.10",
  "port": 22,
  "username": "root",
  "password": "",
  "passwordRef": "agentsshcli:server"
}
```

配置文件完整字段（每项是 `name` 唯一的一台服务器）：

- `name`: 连接名，必须唯一
- `host` / `port` / `username`: SSH 主机、端口（默认 22）、用户名
- `password` / `passwordRef` / `privateKey`: 认证方式，三者只能保留一种；`passphrase` 仅配合 `privateKey` 使用
- `jumpHost`: 跳板机连接名，填写配置文件中另一台机器的 `name`；连接时先建立到跳板机的 SSH，再通过直连通道到达目标机
- `socksProxy`: SOCKS5 代理地址，例如 `socks5://127.0.0.1:1080`；也可省略协议写成 `127.0.0.1:1080`
- `pty`: 是否默认分配伪终端，`exec --pty` / `--no-pty` 可临时覆盖
- `privilegeEnabled`: 是否允许 `exec --sudo/--su`，默认 `false`
- `sudoUser`: sudo 目标用户，默认 `root`；`sudoPassword`/`sudoPasswordRef` 保存当前 SSH 用户的 sudo 密码，缺失时可复用 SSH 密码
- `suUser`: su 目标用户，默认 `root`；`suPassword`/`suPasswordRef` 必须保存目标用户密码
- `commandWhitelist` / `commandBlacklist`: 命令白/黑名单正则数组

跳板机示例：

```json
[
  {
    "name": "目标机",
    "host": "10.0.0.5",
    "username": "root",
    "passwordRef": "agentsshcli:目标机",
    "jumpHost": "跳板机"
  },
  {
    "name": "跳板机",
    "host": "203.0.113.10",
    "port": 22,
    "username": "ubuntu",
    "privateKey": "/path/to/jump_key"
  }
]
```

指定其它配置文件：

```bash
AGENT_SSH_CONFIG=/path/to/config.json agentsshcli list
```

如果 CLI 不可用但 Node/npm 正常，提示用户安装：

```bash
npm install -g agent-ssh-cli
agentsshcli --help
```

从源码开发或本地调试时，需要先构建 Rust 原生执行器：

```bash
npm run build:native
npm test
```

## 全局参数

- `--config <path>`: 指定配置文件路径，优先级高于默认配置
- `--help`, `-h`: 输出帮助
- `--version`, `-v`: 输出版本

`exec`、`upload`、`download` 默认使用 Rust daemon 连接缓存，用于减少连续操作时重复 SSH 握手和认证的开销；只有传入 `--no-cache` 时才会跳过缓存并直连。缓存相关参数如下：

- `--no-cache`: 跳过 Rust daemon 连接缓存，本次命令独立建立并关闭连接，即直连模式
- `--cache-ttl <ms>`: 设置 Rust daemon 连接缓存空闲毫秒数，默认 `180000`
- `--json`: `exec`、`upload`、`download` 输出结构化 JSON（字段 `exitCode`/`stdout`/`stderr`），便于脚本和 AI 解析

所有参数（`--no-cache`、`--cache-ttl`、`--json`、`--timeout`、`--pty` 等）必须放在连接名（第一个位置参数）之前，相互之间可任意顺序混排；放在连接名之后会被当作命令内容的一部分而报「不支持的参数」，命令请用引号包裹。

## init-config

生成默认配置文件到 `~/.agent-ssh-cli/config.json`（已存在时不覆盖）：

```bash
agentsshcli init-config
```

## list

列出配置中的服务器。

```bash
agentsshcli list
agentsshcli list --json
```

参数：

- `--json`: 输出 JSON 格式。当前默认输出也是 JSON。
- `--config <path>`: 指定配置文件

返回值：

- 成功时 stdout 输出服务器数组，只包含 `name`、`host`、`port`、`username`
- 不输出密码、私钥、passphrase、黑白名单等敏感或控制字段
- 退出码为 `0`

示例输出：

```json
[
  {
    "name": "服务器",
    "host": "192.0.2.10",
    "port": 22,
    "username": "root"
  }
]
```

## exec

在远端执行命令。

位置参数形式：

```bash
agentsshcli exec "<connectionName>" "<command>"
agentsshcli exec --no-cache "<connectionName>" "<command>"
agentsshcli exec --cache-ttl 60000 "<connectionName>" "<command>"
agentsshcli exec --pty "<connectionName>" "<command>"
agentsshcli exec --no-pty "<connectionName>" "<command>"
agentsshcli exec --sudo "<connectionName>" "systemctl status app"
agentsshcli exec --su "<connectionName>" "id && pwd"
```

### sudo/su 提权规则

当用户要求通过现有非 root 连接使用 sudo、su、root 身份或切换目标用户执行命令时，必须使用 CLI 顶层参数 `--sudo` 或 `--su`，不得自行改用远端交互命令。

- `--sudo`/`--su` 必须放在连接名或 `--connection` 之前。
- 禁止把 `sudo`、`sudo -S`、`sudo -n`、`su` 或 `su -c` 拼入 `<command>`；这种写法绕过 CLI 的提权密码通道，可能等待交互输入或错误判断为工具不支持密码。
- 不得因为普通 `su -c` 超时就判断 `agentsshcli` 无法响应密码提示；`agentsshcli 0.5.0+` 会通过 SSH channel stdin 自动发送配置中的加密凭据。
- `--su --json` 成功时，`stderr` 可能仍包含远端 `Password:` 提示文字；该提示不包含真实密码，也不代表认证失败。必须结合 JSON `exitCode` 和 `stdout` 中的 `whoami`/`id -u` 判断结果。
- 使用前确认连接配置 `privilegeEnabled: true`，sudo/su 目标用户和凭据字段已配置。

正确写法：

```bash
agentsshcli exec --json --sudo "<connectionName>" "whoami; id -u"
agentsshcli exec --json --su "<connectionName>" "whoami; id -u"
agentsshcli exec --no-cache --json --su "<connectionName>" "id"
```

错误写法：

```bash
agentsshcli exec "<connectionName>" "su -c 'id'"
agentsshcli exec "<connectionName>" "sudo -S id"
agentsshcli exec "<connectionName>" "sudo -n id"
```

命名参数形式：

```bash
agentsshcli exec --connection "<connectionName>" --command "<command>" --directory "/root" --timeout 5000
agentsshcli exec --connection "<connectionName>" --command-file "./script.sh" --timeout 5000
agentsshcli exec --no-cache --connection "<connectionName>" --command "<command>"
```

参数：

- `<connectionName>`: 连接名
- `<command>`: 远端命令
- `--connection <name>`, `-c <name>`: 连接名
- `--command <command>`: 远端命令
- `--command-file <path>`: 从本地 UTF-8 文件读取内容作为远端命令执行（不是先上传再执行），适合执行多行脚本；文件必须使用 LF 换行，不能使用 Windows CRLF 换行；不能和 `--command` 或位置参数 `<command>` 同时使用
- `--directory <dir>`, `-d <dir>`: 远端工作目录
- `--timeout <ms>`, `-t <ms>`: 超时毫秒值，默认 `30000`
- `--pty`: 本次命令分配伪终端，优先级高于配置文件
- `--no-pty`: 本次命令不分配伪终端，优先级高于配置文件
- `--sudo`: 使用 sudo 提权执行，要求连接配置 `privilegeEnabled: true`
- `--su`: 使用 su 切换用户执行，要求连接配置 `privilegeEnabled: true`；与 `--sudo` 互斥
- `--json`: 输出结构化 JSON（`exitCode`/`stdout`/`stderr`）
- `--no-cache`: 不复用连接，必须放在连接名或 `--connection` 前
- `--cache-ttl <ms>`: 连接缓存空闲毫秒数，必须放在连接名或 `--connection` 前

提权模式只支持非交互命令：CLI 通过 SSH channel stdin 发送密码后关闭 stdin，目标命令不能继续读取输入。sudo 独立凭据缺失时可复用 SSH 密码；私钥登录必须配置 `sudoPassword`/`sudoPasswordRef`。su 始终要求独立的目标用户密码。

使用 `--command-file` 时，必须确保脚本文件是 LF 换行。CRLF 文件会把 `\r` 传到远端 bash，可能导致 `$'xxx\r': command not found`。

macOS/Linux 推荐写法：

```bash
cat > /tmp/remote-command.sh <<'EOF'
pwd
EOF
agentsshcli exec --connection "<connectionName>" --command-file /tmp/remote-command.sh
```

Windows PowerShell 推荐显式写 LF：

```powershell
[System.IO.File]::WriteAllText("$env:TEMP\remote-command.sh", "pwd`n", [System.Text.UTF8Encoding]::new($false))
agentsshcli exec --connection "<connectionName>" --command-file "$env:TEMP\remote-command.sh"
```

返回值：

- 成功且有 stdout 时，stdout 输出远端命令结果
- 成功但无 stdout 时不输出内容
- 退出码为 `0`
- 远端命令非零退出、超时、命中黑名单、未命中白名单或连接失败时，stderr 输出错误信息，退出码为 `1`
- `--json` 模式下输出 JSON，`exitCode` 为远端命令**真实退出码**（非零表示命令失败），`stdout`/`stderr` 如实返回远端输出；命令失败时进程退出码仍为 `1`

注意事项：

- 命令里使用 `pkill -f` / `pgrep -f` 时，匹配串会命中**执行该命令的远端 shell 自身**（命令行包含该字符串），导致 shell 被杀、命令中断且无输出。需要排除自身时用正则技巧，如 `pkill -f 'name[.]log'`。
- 远端会话被异常终止（shell 被杀等）时，会报 `[remote] 会话异常终止（无退出状态）`，不会静默返回成功。
- 命令末尾启动后台进程且不重定向 stdout 时，远端不会关闭通道，命令会等到总超时；如需后台运行请把 stdout/stderr 重定向到文件（如 `> /tmp/x.log 2>&1 < /dev/null &`）。
- **命令请用引号包裹**（如 `--command "<command>"` 或位置参数 `"<command>"`）：命令内容里独立的 `--json`、`--timeout` 等 token 会被当作 CLI 参数解析，未加引号时可能被误吞或报错。

## upload

上传本地文件到远端。

位置参数形式：

```bash
agentsshcli upload "<connectionName>" "<localPath>" "<remotePath>"
agentsshcli upload --no-cache "<connectionName>" "<localPath>" "<remotePath>"
```

命名参数形式：

```bash
agentsshcli upload --connection "<connectionName>" --local "./tmp/upload.txt" --remote "/usr/local/test/upload.txt"
agentsshcli upload --no-cache --connection "<connectionName>" --local "./tmp/upload.txt" --remote "/usr/local/test/upload.txt"
```

参数：

- `<connectionName>`: 连接名
- `<localPath>`: 本地文件路径
- `<remotePath>`: 远端目标文件路径
- `--connection <name>`, `-c <name>`: 连接名
- `--local <path>`, `-l <path>`: 本地文件路径
- `--remote <path>`, `-r <path>`: 远端目标文件路径
- `--timeout <ms>`: 总超时毫秒值，默认不限制（大文件允许长时间运行），与 `exec` 的默认 30s 不同
- `--recursive`: 递归上传目录，保持相对路径；符号链接不跟随——指向目录的链接跳过（防循环），指向文件的链接上传其内容
- `--json`: 输出结构化 JSON
- `--no-cache`: 不复用连接，必须放在连接名或 `--connection` 前
- `--cache-ttl <ms>`: 连接缓存空闲毫秒数，必须放在连接名或 `--connection` 前

上传稳定性：

- 上传会先写入远端 `<remotePath>.part` 临时文件，完成校验后再 rename 为正式目标文件。
- 同时写入 `<remotePath>.part.meta` 续传元数据；本地文件大小、修改时间或分块大小变化时，会删除旧临时文件并重传，避免错误拼接。
- 如果上传中断，下次上传同一个本地文件到同一个远端路径时，会从 `.part` 已有大小处断点续传。
- `--no-cache` 模式可用 `Ctrl+C` 停止当前上传；daemon 模式可用 `stop-daemon` 粗暴停止连接池，但它会影响同一 daemon 内其它任务，不是精确取消单个上传。

返回值：

- 成功时 stdout 输出 `File uploaded successfully`
- 退出码为 `0`
- 单文件上传不会创建远端目录：目标目录不存在（或同名路径是文件）时直接报 `远端目录不存在或不可访问: <dir>`，需先创建目录，或改用 `--recursive` 上传整个目录（递归模式会自动建目录）
- 本地文件不存在、远端写入失败或连接失败时，stderr 输出错误信息，退出码为 `1`
- `--json` 模式下成功时 stdout 为 `{"exitCode":0,"stdout":"File uploaded successfully","stderr":""}`，失败时 `exitCode` 为 `1`

## download

下载远端文件到本地。

位置参数形式：

```bash
agentsshcli download "<connectionName>" "<remotePath>" "<localPath>"
agentsshcli download --no-cache "<connectionName>" "<remotePath>" "<localPath>"
```

命名参数形式：

```bash
agentsshcli download --connection "<connectionName>" --remote "/usr/local/test/upload.txt" --local "./tmp/download.txt"
agentsshcli download --no-cache --connection "<connectionName>" --remote "/usr/local/test/upload.txt" --local "./tmp/download.txt"
```

- `<connectionName>`: 连接名
- `<remotePath>`: 远端文件路径
- `<localPath>`: 本地目标文件路径
- `--connection <name>`, `-c <name>`: 连接名
- `--remote <path>`, `-r <path>`: 远端文件路径
- `--local <path>`, `-l <path>`: 本地目标文件路径
- `--timeout <ms>`: 总超时毫秒值，默认不限制（大文件允许长时间运行），与 `exec` 的默认 30s 不同
- `--recursive`: 递归下载目录，保持相对路径；远端符号链接跳过
- `--json`: 输出结构化 JSON
- `--no-cache`: 不复用连接，必须放在连接名或 `--connection` 前
- `--cache-ttl <ms>`: 连接缓存空闲毫秒数，必须放在连接名或 `--connection` 前

下载稳定性：

- 下载会先写入本地 `<localPath>.part` 临时文件，并写入 `<localPath>.part.meta` 续传元数据；完成后校验大小再 rename 为正式目标文件。
- 下载中断后，下次下载同一个远端文件到同一个本地路径会从已有 `.part` 大小继续；远端文件特征变化时自动删除旧 `.part` 重新下载。

返回值：

- 成功时 stdout 输出 `File downloaded successfully`
- 退出码为 `0`
- 本地写入失败、远端读取失败或连接失败时，stderr 输出错误信息，退出码为 `1`
- `--json` 模式下成功时 stdout 为 `{"exitCode":0,"stdout":"File downloaded successfully","stderr":""}`，失败时 `exitCode` 为 `1`

## stop-daemon

停止当前配置文件对应的 SSH 缓存进程（连接池）。它是连接池维护命令，不是精确取消单个上传任务，会影响同一 daemon 内其它任务：

```bash
agentsshcli stop-daemon [--config <path>]
```

## help/version
```bash
agentsshcli --help
agentsshcli help list
agentsshcli help exec
agentsshcli help upload
agentsshcli help download
agentsshcli help edit-config
agentsshcli help stop-editor
agentsshcli --version
```

返回值：

- help 成功时 stdout 输出帮助文本，退出码为 `0`
- version 成功时 stdout 输出版本号，退出码为 `0`

## 错误规则

- 参数重复时失败
- 命名参数和位置参数不能混用同一字段
- `--no-cache` 和 `--cache-ttl` 必须放在 `exec`、`upload`、`download` 后、连接名或 `--connection` 前
- `timeout` 和 `cache-ttl` 必须是正整数毫秒值
- `list` 不接受位置参数
- `edit-config` / `stop-editor` 不接受 `--no-cache`、`--cache-ttl` 或位置参数；选择配置文件只使用 `--config <path>`
- 编辑器 URL token 只用于当前本机页面，不得作为普通文本记录或发送到外部系统
- `upload` / `download` 的本地路径按传入路径解析，不再限制在当前工作目录、项目目录或 `allowedLocalPaths` 内
- 出现 `启动 SSH 缓存进程失败` 通常表示本地 Rust daemon 或其 socket 启动/握手失败；如需绕过缓存验证远端命令，应在子命令后添加 `--no-cache`
- 所有失败统一在 stderr 输出错误信息，退出码为 `1`
