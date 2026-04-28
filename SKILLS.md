# Skills

推荐通过 GitHub + npx 使用本 CLI，不再依赖自包含压缩包。

统一命令入口：

```bash
npx -y github:sleepinginsummer/agent-ssh-cli agentsshcli --help
```

默认配置文件：

```text
~/.agent-ssh-cli/config.json
```

可通过环境变量覆盖：

```bash
AGENT_SSH_CONFIG=/path/to/config.json npx -y github:sleepinginsummer/agent-ssh-cli agentsshcli list
```

常用命令：

```bash
npx -y github:sleepinginsummer/agent-ssh-cli agentsshcli list
npx -y github:sleepinginsummer/agent-ssh-cli agentsshcli exec "<connectionName>" "pwd"
npx -y github:sleepinginsummer/agent-ssh-cli agentsshcli upload "<connectionName>" ./tmp/upload.txt /usr/local/test/upload.txt
npx -y github:sleepinginsummer/agent-ssh-cli agentsshcli download "<connectionName>" /usr/local/test/upload.txt ./tmp/download.txt
```
