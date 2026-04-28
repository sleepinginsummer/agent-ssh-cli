# agent-ssh-cli

本项目参考 [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) 的 SSH 操作能力设计，改写为独立 CLI 形式。感谢原项目提供的思路和能力基础。


## 把这句丢给ai一键安装

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
- `agentsshcli exec/upload/download` 的连接缓存仅支持 macOS/Linux

### 安装步骤

1. 全局安装：

```bash
npm install -g github:sleepinginsummer/agent-ssh-cli
agentsshcli --help
```


2. 初始化配置（格式和 ssh-mcp-server 一致）：

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

完整示例见 [example.config.json](example.config.json)。`~/.agent-ssh-cli/config.json` 保存真实连接信息。

```json
[
  {
    "name": "密码服务器",
    "host": "192.0.2.10",
    "port": 22,
    "username": "root",
    "password": "******",
    "commandBlacklist": [
      "(^|[;&|()[:space:]])rm([[:space:]]|$)",
      "(^|[;&|()[:space:]])shutdown([[:space:]]|$)",
      "(^|[;&|()[:space:]])reboot([[:space:]]|$)"
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
      "(^|[;&|()[:space:]])rm([[:space:]]|$)",
      "(^|[;&|()[:space:]])shutdown([[:space:]]|$)",
      "(^|[;&|()[:space:]])reboot([[:space:]]|$)"
    ]
  }
]
```

3. 将 `SKILL.md` 添加到 agent 中

测试命令

```bash
agentsshcli list
```

完成安装!

# 卸载和清理：

```bash
npm uninstall -g agent-ssh-cli
npm cache clean --force
#删除配置文件
rm -rf ~/.agent-ssh-cli
```
