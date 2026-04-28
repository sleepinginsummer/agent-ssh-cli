# AI 安装说明

使用本工具时，先按下面步骤安装 CLI 和 skill。

## 1. 安装 CLI

```bash
npm install -g github:sleepinginsummer/agent-ssh-cli
agentsshcli --help
```

如果 `agentsshcli --help` 失败，先检查：

```bash
node --version
npm --version
```

需要 Node.js `>= 20` 和 npm `>= 10`。

## 2. 初始化配置目录

```bash
mkdir -p ~/.agent-ssh-cli
```

然后创建并编辑：

```text
~/.agent-ssh-cli/config.json
```

配置内容可参考项目中的 `https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/example.config.json`。配置文件保存真实服务器连接信息，不要公开。可以询问用户如何配置或者告知用户配置目录。

## 3. 安装 skill

将本仓库根目录的 `https://github.com/sleepinginsummer/agent-ssh-cli/blob/main/SKILL.md` 安装到 agent 的 skills 目录。

Codex 默认目录示例：

```bash
mkdir -p ~/.codex/skills/agent-ssh-cli
cp SKILL.md ~/.codex/skills/agent-ssh-cli/SKILL.md
```

如果 AI 使用其它 skills 目录，将 `SKILL.md` 复制到对应的 `agent-ssh-cli/SKILL.md`。

## 4. 验证

```bash
agentsshcli --help
test -f ~/.agent-ssh-cli/config.json
```

配置完成后，测试执行：

```bash
agentsshcli list
```

拿到连接名后，再执行 `exec`、`upload` 或 `download`。
