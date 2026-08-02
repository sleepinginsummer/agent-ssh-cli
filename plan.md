# agent-ssh-cli 改造计划

> 基于 2026-08-01 真实使用（多服务器排查、19MB 大文件传输、跳板管理）的实战反馈整理。
> 当前版本：v0.4.1，Rust 主程序单文件 `native/src/main.rs`（~105KB）。
> 状态：P0/P1 已实施完成（2026-08-01），见文末「实施记录」。

## 优先级总览

| 级别 | 项 | 一句话 |
|---|---|---|
| P0 | 传输超时可配 | 大文件 upload/download 实测被 30s 超时杀掉 |
| P0 | stdout 可靠性 | 后台进程/复杂引号命令出现"exit 0 但无输出" |
| P1 | --json 结构化输出 | AI/脚本消费需要结构化结果 |
| P1 | --command-file 语义 | heredoc 内容被破坏 + stdout 静默回传（根因已定位为 P0-2） |
| P1 | 文档同步 | SKILL.md 缺 jumpHost/socksProxy 等已实现能力 |
| P2 | 目录传输 | upload/download 缺 -r 递归 |
| P2 | 危险操作确认 | 黑名单硬拦之外加交互确认层 |
| P3 | 架构拆分 | 105KB 单文件按模块拆分 |

---

## P0-1 传输超时可配（upload/download）

### 现象

- 19MB 文件 upload/download 实测报 `操作超时: 30000 ms`（daemon 与 --no-cache 模式都出现），无法传完，被迫分片 base64 绕行。
- task.md 记录 v0.3.7 已"去掉 upload 的固定 30 秒总超时"，但实测 30s 仍存在。
- 代码中 `native/src/main.rs:1543` 存在硬编码 `inactivity_timeout: Some(Duration::from_secs(30))`，疑似来源；`TransferArgs`（227 行）无 `timeout_ms` 字段，upload/download 不接受超时参数。

### 改造

1. `TransferArgs` 增加 `timeout_ms: u64`，upload/download 支持 `--timeout <ms>`（位置：子命令后、连接名前，与 exec 对齐）。
2. 排查并消除 30s 超时来源：
   - `inactivity_timeout` 改为可配置或提高默认值（大文件 + 慢网络场景）。
   - 确认 daemon 侧 transfer 请求是否另有超时；若有，改为跟随 `--timeout` 或默认不设上限。
3. 续传机制已具备（`.part` + `.part.meta`），超时后重传应能续传——补一条验收用例。

### 验收

- 30MB 文件在 `--timeout 120000` 下完整传输成功；不传 `--timeout` 时行为不回归（默认值合理）。
- 传输中断后重试可从 `.part` 续传。

---

## P0-2 stdout 可靠性

### 现象

多次出现"命令执行了但无输出"：

- 命令含后台进程/重定向（`nohup ... &`、`setsid ... & disown`）时 exit 0 但 stdout 为空，实际命令已执行（文件已写入）。
- 分步重试、拆散命令后才拿到输出，排查效率受损。
- 对 AI 调用尤其致命：`有输出 vs 无输出` 直接决定下一步判断。

### 定位方向

- stdout 收集在 `main.rs:1691-1716`（daemon `ChannelMsg::Data` 聚合），疑似后台进程使远端 shell 提前返回、channel 未读到 EOF 就收尾。
- 也可能是 daemon 侧只读取一次 channel 数据、或 `trim_end` 处理把输出吞掉。

### 改造

1. 复现用例：`exec conn "setsid sleep 1 & echo hi"` 类命令，锁定丢输出环节（远端 shell / daemon 管道 / 客户端聚合）。
2. 修复：等待 channel 完整 EOF 后再组装输出；后台进程场景确保远端 shell 不因 SIGHUP 提前退出（必要时 `setsid`/`nohup` 语义由 CLI 保证）。
3. 补充回归测试：后台进程、多行命令、`&` + 重定向组合。

### 验收

- 上述复现用例稳定输出 `hi`，exit 0。
- 现有 `npm test` 全绿。

---

## P1-1 --json 结构化输出

### 现状

exec 输出为纯文本 stdout，错误统一 stderr + exit 1；AI/脚本解析依赖约定，无法拿到结构化结果。

### 改造

- `exec`、`upload`、`download` 增加 `--json`：
  ```json
  {"exitCode": 0, "stdout": "...", "stderr": ""}
  ```
- 保持默认文本输出不变（向后兼容）；`--json` 时 stdout/stderr 都进 JSON。
- daemon 响应结构已有 `{stdout, stderr, exit_code}`（`main.rs:2428` 附近），客户端侧做序列化即可，改动面小。

### 验收

- `exec --json conn "echo hi"` 输出合法 JSON 且字段齐全。
- 远端非零退出时 `exitCode` 正确反映。

---

## P1-2 --command-file 语义与可靠性

### 现象

- 首次用 `--command-file` 执行脚本：远端实际执行了（文件写入成功），但 stdout 完全没回传，误判为"没执行"。
- 经 `--command` 内嵌 heredoc 传 JSON 时内容被破坏（远端 xray 报 `invalid character 'l'`），怀疑引号/转义处理在传输中被改写。

### 改造

1. 明确 `--command-file` 语义：本地文件内容作为命令执行（非上传后执行），文档写清楚 stdout/exit 行为。
2. 排查 heredoc/引号内容传输的转义链路（客户端参数解析 → daemon 请求 → 远端 shell），保证内容逐字节透传。
3. 补充测试：含单双引号、heredoc、多行 JSON 的脚本内容往返一致。

### 验收

- `--command-file` 执行脚本 stdout 完整回传；脚本内容含引号/heredoc 时远端收到的字节与本地一致。

---

## P1-3 文档同步

### 现象

- SKILL.md 未提及 `jumpHost`、`socksProxy`、`init-config`、`stop-daemon` 等已实现能力，靠 README 兜底，用户/AI 盲区。
- SKILL.md（11.3K）与 README（6.8K）内容有重复与不一致。

### 改造

- 以 README 为准，SKILL.md 补齐：jumpHost/socksProxy 配置示例、init-config/stop-daemon 用法、错误码与 FAQ（含"启动 SSH 缓存进程失败"绕过方式）。
- 建立"发版时同步文档"检查项（可在 RELEASE_NOTES 模板里加）。

---

## P2-1 目录传输

- `upload`/`download` 增加 `-r` 递归目录支持（SFTP 已有，需补目录遍历与相对路径保持）。
- 复用现有 `.part` 续传与重试机制，按文件粒度续传。
- 验收：含子目录与中文文件名的目录往返一致。

## P2-2 危险操作确认

- 现有 `commandBlacklist` 是硬拦；对 AI 场景，加 `--confirm` 交互确认层（命中危险模式时打印命令并等待 y/N）。
- 仅交互终端启用，非 TTY 场景默认拒绝或跳过，不影响脚本化。

## P3-1 架构拆分（低风险增量）

- `native/src/main.rs` 105KB 单文件已到维护拐点，按功能拆模块：
  - `args.rs`（参数解析 + help）
  - `config.rs`（配置/密码迁移/secrets）
  - `ssh.rs`（连接/跳板/代理）
  - `transfer.rs`（上传/下载/续传）
  - `daemon.rs`（daemon 协议/缓存）
  - `cmd.rs`（exec/upload/download 命令编排）
- 拆分只搬代码不改行为，每拆一个模块跑一次 `npm test` + 手动冒烟。

---

## 排期建议

1. 先做 P0-1 + P0-2（本次实战最痛，影响面集中在 `main.rs` 传输与 channel 读取）
2. 再做 P1-1 + P1-2 + P1-3（低成本高收益，AI 场景刚需）
3. P2/P3 按需排入下两个版本

## 验证基线

- `npm test`（node --check + cargo test）
- `npm run build:native`
- 手工冒烟：jumpHost 跳板、--no-cache/daemon 双模式、大文件续传

---

## 实施记录（2026-08-01）

### P0-1 传输超时可配 ✅

- `TransferArgs` 新增 `timeout_ms: Option<u64>`（None = 不限制），upload/download 支持 `--timeout <ms>`。
- 消除 30s 超时来源：
  - daemon 侧 download 的 `request.timeout.unwrap_or(30000)` → 跟随请求（None 时 `block_on` 不设限）。
  - no-cache 侧 `download_file(..., 30000)` 硬编码 → 跟随 `parsed.timeout_ms`。
  - upload 两侧统一支持可选总超时。
  - SSH `inactivity_timeout` 30s → 300s（避免慢速大文件/长任务被误断）。
- 修复参数解析顺序：先取命名参数再解析位置参数，避免 `--timeout` 被当作 connectionName。
- 新增 3 个单元测试；HELP_UPLOAD/HELP_DOWNLOAD 更新。

### P0-2 stdout 可靠性 ✅

根因定位：**不是 CLI 输出丢失，是远端 shell 自杀**。

- `pkill -f` / `pgrep -f` 的匹配串会命中执行命令的远端 shell 自身（bash -c 命令行含该字符串），shell 被杀 → 无输出 + 无 ExitStatus → CLI 静默返回空 stdout + exit 0，误导排查。
- 修复（`execute_remote_command_with_session_async`）：
  - 通道关闭但无 ExitStatus → 报 `[remote] 会话异常终止（无退出状态）`，不再静默成功。
  - 收到 ExitStatus 后最多再等 EOF 2s，超时视为命令结束（解决后台进程持有通道 stdout 导致挂起到总超时的问题）。
- 实测：`sleep 30 & echo hi` 从"超时"变为正常返回 `hi`；shell 自杀场景从"exit 0 无输出"变为明确报错。

### P1-1 --json 结构化输出 ✅

- `exec` / `upload` / `download` 支持 `--json`，输出 `{"exitCode", "stdout", "stderr"}`。
- 错误也 JSON 化（stderr），`exitCode` 为 1；`list --json` 兼容保留。
- 移除 `parse_global_args` 中吞掉 `--json` 的空分支（导致紧跟 `--no-cache` 的 `--json` 失效）。
- 新增 2 个单元测试；帮助文本更新。

### P1-2 --command-file 可靠性 ✅

- 往返测试（heredoc JSON 含 `+ / = &`、单双引号、多行）验证内容逐字节透传，daemon 与 --no-cache 双模式一致。
- 实战中"内容破坏/静默"实为 P0-2 的 shell 自杀连锁误判，无独立缺陷。
- 语义（读取本地文件内容作为命令执行）已在 SKILL.md 明确。

### P1-3 文档同步 ✅

- SKILL.md：补配置字段（jumpHost/socksProxy 说明 + 跳板示例）、init-config/stop-daemon 小节、--json/--timeout 参数、exec 注意事项（pkill 自杀、会话异常终止、后台进程 stdout 重定向）。
- README.md：补常用参数（--timeout/--json/init-config/stop-daemon）。
- 全部 `npm test`（23 个）与 `npm run build:native` 通过。

### 第二轮实施记录（2026-08-01，五项优化）

#### 1. list 显示 jumpHost ✅

- list 输出增加 `jumpHost` 字段（仅配置了跳板的连接才输出，非敏感字段）。

#### 2. upload 进度防刷屏 ✅

- 进度输出从"每 1MB chunk 一行"改为**百分比变化时输出**，大文件不再刷屏；保留起点输出（0%/续传点），空文件显示 100%。

#### 3. download 断点续传 + 进度 ✅

- 复用 upload 的续传模式：本地 `.part` + `.part.meta`（记录远端大小/mtime/chunk），meta 匹配才续传，远端文件变化自动删旧重下。
- 远端文件用 SFTP seek 从断点继续读；完成后校验大小再 rename。
- 新增进度输出（百分比变化时打印）。
- 实测：20MB 下载 5s 超时中断留下 2.7M `.part`，重试自动续传，md5 与远端一致。

#### 4. 目录传输 --recursive ✅

- upload/download 新增 `--recursive`：递归遍历目录、保持相对路径、远端目录逐级创建，文件粒度复用上传续传/下载续传。
- daemon 与 --no-cache 双模式支持（daemon 请求带 `recursive` 字段）。
- 修复 `ensure_remote_dir_all` 绝对路径处理 bug（`/tmp/x` 被误建为相对路径）。
- 实测：三级目录 upload/download 往返 md5 全部一致，daemon 模式正常。

#### 5. 文档同步 ✅

- HELP_UPLOAD/HELP_DOWNLOAD、SKILL.md（--recursive、download 续传说明）、README.md（--recursive、下载续传）已更新。
- `npm test` 24 个全绿，`npm run build:native` 通过。
