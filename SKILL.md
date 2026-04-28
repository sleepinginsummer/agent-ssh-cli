---
name: agent-ssh-cli
description: 使用基于 SSH 的 CLI 安全操作已配置的远端服务器。适用于需要列出连接、远程执行命令、上传文件、下载文件，以及确认参数、返回值、配置文件位置和环境校验步骤的场景。
---

# agent-ssh-cli 使用说明

`agentsshcli` 是一个基于 SSH 的命令行工具，用于让 AI 或用户通过本地配置安全地操作远端服务器。

它能做的事：

- 列出本地配置中的 SSH 服务器连接
- 在指定远端服务器上执行命令
- 上传本地文件到远端服务器
- 从远端服务器下载文件到本地
- 通过命令黑白名单限制可执行命令
- 通过本地路径白名单限制上传和下载访问范围
- 短时间缓存 SSH 连接，减少连续操作时的重复连接开销

它不做的事：

- 不保存或输出密码、私钥等敏感认证信息
- 不扫描网络或发现服务器，只使用配置文件中的连接
- 不绕过配置中的命令限制和本地路径限制


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

如果 `node` 或 `npm` 不存在，提示用户先安装 Node.js `>= 20` 和 npm `>= 10`。

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

指定其它配置文件：

```bash
AGENT_SSH_CONFIG=/path/to/config.json agentsshcli list
```

如果 CLI 不可用但 Node/npm 正常，提示用户安装：

```bash
npm install -g github:sleepinginsummer/agent-ssh-cli
agentsshcli --help
```

当前项目未发布到 npm registry，不要使用 `npm install -g agent-ssh-cli`。

## 全局参数

- `--config <path>`: 指定配置文件路径，优先级高于默认配置
- `--help`, `-h`: 输出帮助
- `--version`, `-v`: 输出版本

`exec`、`upload`、`download` 支持连接缓存参数：

- `--no-cache`: 跳过 SSH 连接缓存，本次命令独立建立并关闭连接
- `--cache-ttl <ms>`: 设置连接缓存空闲毫秒数，默认 `180000`

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
- 不输出密码、私钥、agent、黑白名单等敏感或控制字段
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
```

命名参数形式：

```bash
agentsshcli exec --connection "<connectionName>" --command "<command>" --directory "/root" --timeout 5000
```

参数：

- `<connectionName>`: 连接名
- `<command>`: 远端命令
- `--connection <name>`, `-c <name>`: 连接名
- `--command <command>`: 远端命令
- `--directory <dir>`, `-d <dir>`: 远端工作目录
- `--timeout <ms>`, `-t <ms>`: 超时毫秒值，默认 `30000`
- `--no-cache`: 不复用连接
- `--cache-ttl <ms>`: 连接缓存空闲毫秒数

返回值：

- 成功且有 stdout 时，stdout 输出远端命令结果
- 成功但无 stdout 时不输出内容
- 退出码为 `0`
- 远端命令非零退出、超时、命中黑名单、未命中白名单或连接失败时，stderr 输出错误信息，退出码为 `1`

## upload

上传本地文件到远端。

位置参数形式：

```bash
agentsshcli upload "<connectionName>" "<localPath>" "<remotePath>"
```

命名参数形式：

```bash
agentsshcli upload --connection "<connectionName>" --local "./tmp/upload.txt" --remote "/usr/local/test/upload.txt"
```

参数：

- `<connectionName>`: 连接名
- `<localPath>`: 本地文件路径
- `<remotePath>`: 远端目标文件路径
- `--connection <name>`, `-c <name>`: 连接名
- `--local <path>`, `-l <path>`: 本地文件路径
- `--remote <path>`, `-r <path>`: 远端目标文件路径
- `--no-cache`: 不复用连接
- `--cache-ttl <ms>`: 连接缓存空闲毫秒数

返回值：

- 成功时 stdout 输出 `File uploaded successfully`
- 退出码为 `0`
- 本地路径不在允许范围、远端写入失败或连接失败时，stderr 输出错误信息，退出码为 `1`

## download

下载远端文件到本地。

位置参数形式：

```bash
agentsshcli download "<connectionName>" "<remotePath>" "<localPath>"
```

命名参数形式：

```bash
agentsshcli download --connection "<connectionName>" --remote "/usr/local/test/upload.txt" --local "./tmp/download.txt"
```

参数：

- `<connectionName>`: 连接名
- `<remotePath>`: 远端文件路径
- `<localPath>`: 本地目标文件路径
- `--connection <name>`, `-c <name>`: 连接名
- `--remote <path>`, `-r <path>`: 远端文件路径
- `--local <path>`, `-l <path>`: 本地目标文件路径
- `--no-cache`: 不复用连接
- `--cache-ttl <ms>`: 连接缓存空闲毫秒数

返回值：

- 成功时 stdout 输出 `File downloaded successfully`
- 退出码为 `0`
- 本地路径不在允许范围、远端读取失败或连接失败时，stderr 输出错误信息，退出码为 `1`

## help/version

```bash
agentsshcli --help
agentsshcli help list
agentsshcli help exec
agentsshcli help upload
agentsshcli help download
agentsshcli --version
```

返回值：

- help 成功时 stdout 输出帮助文本，退出码为 `0`
- version 成功时 stdout 输出版本号，退出码为 `0`

## 错误规则

- 参数重复时失败
- 命名参数和位置参数不能混用同一字段
- `timeout` 和 `cache-ttl` 必须是正整数毫秒值
- `list` 不接受位置参数
- `upload` / `download` 的本地路径必须位于当前工作目录、项目目录或 `allowedLocalPaths` 内
- 所有失败统一在 stderr 输出错误信息，退出码为 `1`
