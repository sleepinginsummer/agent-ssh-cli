# Release Notes

## v0.5.5

原生程序按职责完成模块化拆分，并补上平台分支守卫；命令行为与 v0.5.4 一致。

- `native/src/main.rs` 由 2232 行收敛到 74 行：新增 `config.rs`（连接配置读写校验、secret 密钥库、凭据迁移、配置快照、命令黑白名单）与 `cli.rs`（参数结构体、help、解析与子命令调度），入口只保留模块声明、错误类型、输出模式与 `main()`。
- 模块依赖单向化且无环：`cli → config / daemon / exec / transfer`；daemon 不再认识 CLI 解析层类型，改由 `DaemonExecRequest` / `DaemonTransferRequest` / `DaemonClientConfig` 接收请求，CLI 负责映射。
- 可见性收窄：`config.rs` 只放行跨模块真实入口（`Connection` 及其必需字段、`ConfigSnapshot` 与加载/凭据/路径/策略 API），`normalize_entry`、secret DTO、加解密与迁移等内部实现恢复私有；`cli.rs` 仅 `run` 对外；删除 4 处 `allow(unused_imports)`。
- 测试按职责归位：配置/凭据用例移入 `config.rs`，参数解析与 command-file 用例移入 `cli.rs`，daemon/privilege 用例保持原位，共 41 项。
- `normalize_entry` 由 141 行拆为 29 行，配合 `normalize_endpoint` / `normalize_auth` / `validate_optional_refs` / `normalize_privilege`，校验顺序与错误文案不变。
- 新增 `scripts/check-cfg-ports.js` 并接入 `npm test`：静态拦截只在 win32 暴露的三类问题（cfg 变体可见性不一致、跨模块引用私有项、`#[cfg]` 孤儿属性贴在平台无关 std import 上）。

验证：

- `npm test` 通过：平台分支检查 + 41 项测试。
- `cargo clippy` 0 error，警告 6 项（均为既有风格项）。
- 真机冒烟：`list`、直连 exec、`--pty`、`--sudo`、`--su`（CentOS 7 管道路径）、`--su`（util-linux 2.32 `-P` 路径）、跳板机、upload、`download` 命名参数、daemon exec/download、`stop-daemon` 全部通过。
- CI 演练（`workflow_dispatch`，run 34479799594）：5 个平台构建全绿（含 win32-x64），发布阶段按 guard 跳过、未写入 registry。
## v0.5.4

修复 `download` 命名参数倒置，把原生程序按职责拆分为模块，并修复拆分引入的 Windows 构建失败：

> v0.5.3 的 tag 曾推送，但 win32-x64 构建失败导致主包与 Release 未发布，故本次以 v0.5.4 重新发布；npm 上可能残留 v0.5.3 的 4 个平台包（无主包引用，不影响安装）。

- 修复 `download --remote <path> --local <path>` 把两个路径互换的问题：`parse_transfer_args` 在 download 分支先按 upload 语义取值再按变量名解释，导致远端 stat 打到本地路径上，命名参数形式必然报「读取远端文件信息失败: No such file」。
- 重构为 `TransferMode` 枚举：`--local`/`--remote` 始终解析到同名字段，两个子命令的差异只体现在位置参数顺序（upload 为 local → remote，download 为 remote → local），并补充命名参数语义的回归测试。
- `native/src/main.rs` 由 4539 行拆分到 2232 行：新增 `daemon.rs`（协议/进程生命周期/连接池/请求分发）、`transfer.rs`（SFTP 传输）、`ssh.rs`（建连与认证）、`exec.rs`（命令执行与提权编排）、`runtime.rs`（runtime/超时封装）；`privilege.rs` 保持纯逻辑不变。
- `handle_daemon_stream` 由约 200 行拆为 33 行路由，配合 `prepare_daemon_request`、`acquire_pool_entry`、`dispatch_daemon_operation`、`handle_daemon_upload`、`handle_daemon_download`，行为保持不变。
- 模块依赖单向化：`exec`/`transfer` 直接依赖 `ssh`、`runtime` 与根级共享类型，不再经由入口模块的私有导入别名。
- 修复拆分引入的 Windows 构建失败：`daemon.rs` 的 windows 版 `run_daemon` 忘记提升为 `pub(crate)`，且 windows 分支使用的 `home_dir` 未导入；该问题只在 `cfg(windows)` 下暴露，Linux/macOS 冒烟无法发现，现由 CI 的 win32-x64 构建验证。

验证：

- `npm test` 通过，共 41 项测试（新增 download 命名参数回归用例）。
- `cargo clippy` 0 error；警告 8 → 6，均为既有风格项。
- 真机冒烟：`list`、直连 exec、`--pty`、`--sudo`、`--su`（CentOS 7 管道路径）、`--su`（util-linux 2.32 `-P` 路径）、跳板机、daemon execute/upload/download（含目录递归）、非缓存 exec/upload/download，全部返回预期结果且内容比对一致。
- `download` 命名与位置参数两种形式、daemon 与非缓存两条路径均通过。
## v0.5.2

修复 CentOS 7 等旧 su 环境下 `--su` 无法提权（或静默假成功）的问题：

- 移除 `script` 回退通道：`script` 在 stdin 非 tty 时创建的 pty termios 未初始化（实测 `-icanon min=0 time=0`），而 PAM 读取密码前执行 `tcsetattr(TCSAFLUSH)` 会丢弃提示符之前到达的密码，su 只能拿到空密码。
- 移除 `script` 回退通道：`script` 把 stdin EOF 视为会话结束，收到 EOF 后立刻关闭伪终端并以子进程退出码 0 退出，正在认证的 su 被终止，表现为只有 `Password:` 的静默成功（exitCode 0）。
- 无 `-P/--pty` 能力的 su 改为 `su -c '<command>' <user>`，密码直接走 SSH channel stdin，与 `sudo -S`、`su -P` 路径一致。
- 删除随之失效的 `SU_READY_MARKER`、`SCRIPT_FALLBACK_PROBE`、`su_script_command` 与 `CommandInput.close_stdin` 分支。

验证：

- `npm test` 通过，共 40 项测试。
- `npm run build:native` 通过。
- CentOS 7.6（util-linux 2.23.2，无 `-P`）`web正式1`、`web正式2` 的 `--su` 直连与 daemon 模式均返回 `root` / UID 0。
- `tangshan`（util-linux 2.32.1，`-P` 路径）回归通过，`--su` 返回 `root` / UID 0。

## v0.5.1

修复 russh 安全依赖并强化 agent Skill 的 sudo/su 使用规则：

- 将 `russh` 从 0.60.2 升级到修复版本 0.60.3，并同步将 `russh-cryptovec` 从 0.59.0 升级到 0.60.3。
- 修复 CVE-2026-46673 / GHSA-g9f8-wqj9-fjw5 / RUSTSEC-2026-0153 涉及的未检查容量增长、长度运算和不安全内存处理风险。
- 明确通过非 root 连接提权时必须使用 CLI 顶层 `--sudo` / `--su` 参数，且参数必须位于连接名之前。
- 明确禁止把 `sudo`、`sudo -S`、`sudo -n`、`su` 或 `su -c` 拼入远端命令，避免绕过 CLI 的提权密码通道。
- 补充正确与错误命令示例，并明确不能根据普通 `su -c` 超时判断 CLI 不支持密码输入。
- 明确 `--su --json` 的 `stderr` 可能包含无敏感信息的 `Password:` 提示，应结合 `exitCode` 与身份输出判断结果。
- 修正凭据说明：密码可加密保存到本机 `secrets.json`，不会输出明文，仅通过 SSH channel stdin 发送。

验证：

- `npm test` 通过，共 40 项测试。
- `npm run build:native` 通过。
- 依赖树确认 `russh` 与 `russh-cryptovec` 均为 0.60.3。
- `tangshan` 远端 `--su` 直连与 daemon 模式验证通过，均成功切换为 root（UID 0）。

## v0.5.0

新增安全的 sudo/su 提权执行通道：

- `exec` 新增互斥参数 `--sudo` / `--su`，支持缓存 daemon 与 `--no-cache` 直连模式。
- 连接配置新增 `privilegeEnabled` 安全开关，默认关闭；关闭时在凭据迁移和 SSH 连接前拒绝提权执行。
- 新增 sudo/su 独立用户与凭据字段，明文首次使用时迁移到 `secrets.json`；SSH、sudo、su 使用隔离的密文 key。
- sudo 独立密码缺失时可复用 SSH 密码；su 始终要求目标用户的独立密码。
- 密码仅通过 SSH channel stdin 发送，不进入本地/远端 argv，不写远端临时文件。
- 完整原始命令在提权后的 shell 中执行，支持管道、重定向和 `&&`，并统一进行 shell 参数转义与 Unix 用户名校验。
- 支持 sudo requiretty 常见错误探测、`su -P/--pty` 能力探测，以及具备 `-c/-e` 能力时的 `script` 安全 fallback。
- 提权逻辑拆分到 `native/src/privilege.rs`，channel 输出收集及 daemon execute 处理独立封装。
- `build-native-packages.yml` 改为仅手动触发，tag 发布只运行 `publish.yml`，避免重复五平台构建。
- README、SKILL.md 和示例配置同步更新。

验证：

- `npm test` 通过，共 40 项测试。
- `npm run build:native` 通过。
- 默认关闭及 `--json` 错误路径冒烟通过，拒绝执行时配置文件保持不变。
- sudo/su 远端实机兼容性仍需在具体目标环境验证。

## v0.4.1

修复 0.4.0 的两个参数解析回归：

- 修复 `download` 位置参数顺序颠倒：`download <connectionName> <remotePath> <localPath>` 中 remotePath/localPath 被解析反了（单文件下载报「远端文件不存在」）。
- 修复全局参数前缀扫描：`--no-cache`/`--cache-ttl`/`--config` 之前夹着 `--json`/`--timeout` 等子命令参数时会报误导性的「connectionName 位置参数非法」。现在连接名之前的全局参数与子命令参数可任意顺序混排；连接名之后的 flag 一律明确报「不支持的参数」，不再静默吞掉。

验证：

- `npm test` 通过，共 32 项测试。
- `npm run build:native` 通过。
- 真实服务器往返：单文件/目录上传下载 md5 一致、下载断点续传完成。

## v0.4.0

本次发布聚焦传输可靠性、结构化输出与目录传输：

- 传输超时可配：`upload`/`download` 支持 `--timeout <ms>`，默认不限制总超时（大文件长时间运行不再被 30s 误杀）；SSH 空闲超时放宽到 5 分钟。
- stdout 可靠性：远端会话异常终止（如 `pkill -f` 命中执行 shell 自身）时明确报 `[remote] 会话异常终止（无退出状态）`，不再静默返回成功；后台进程持有 stdout 时收尾等待 2 秒，不再挂到总超时。
- `--json` 结构化输出：`exec`/`upload`/`download` 支持 `--json`，`exitCode` 为远端命令**真实退出码**，`stdout`/`stderr` 如实返回；错误与参数解析阶段的错误同样 JSON 化，进程退出码保持 `1`。
- daemon 模式下远端命令非零退出不再重连重试（原来会重复执行两次）；仅会话异常时重连重试。
- `--command-file` 语义明确：读取本地文件内容作为命令执行（非先上传再执行），内容逐字节透传。
- 下载断点续传：本地 `.part` + `.part.meta` 元数据，中断后自动续传，远端文件特征变化自动重下；新增下载进度输出。
- 目录传输：`upload`/`download` 支持 `--recursive`，保持相对路径，文件粒度复用续传；符号链接不跟随（指向目录的链接跳过防循环，指向文件的链接上传其内容）。
- `list` 输出新增 `jumpHost` 字段（仅配置了跳板的连接）。
- 上传进度防刷屏：仅百分比变化时输出。
- 参数解析修复：`--json`/`--recursive` 等布尔参数只解析连接名之前的 token，命令内容中的同名 token 不再被误吞（命令请用引号包裹）；位置参数后的未知 flag 明确报错而非静默吞掉。
- 文档同步：SKILL.md/README 补齐 jumpHost/socksProxy、init-config/stop-daemon、`--json`/`--timeout`/`--recursive` 等说明与 exec 注意事项。

验证：

- `npm test` 通过，共 29 项测试。
- `npm run build:native` 通过。

## v0.3.9

- 修复多个 CLI 进程并发冷启动 SSH 缓存 daemon 时争抢同一 Unix socket 的竞态。
- daemon 启动使用跨进程文件锁串行化，持锁后重新探活，仅由启动方清理失效 socket。
- daemon 子进程不再无条件删除 socket，避免破坏其它并发进程已经建立的监听。
- 新增 daemon 并发启动锁回归测试。

验证：

- `cargo test --manifest-path native/Cargo.toml --locked` 通过，共 18 项测试。

## v0.3.7

本次发布聚焦上传稳定性：

- 新增 SFTP 上传断点续传：上传中断后保留远端 `<remotePath>.part`，下次同一文件同一路径自动从已有大小继续。
- 新增续传元数据文件 `<remotePath>.part.meta`：记录本地文件大小、修改时间和分块大小，避免本地文件变化后错误拼接旧分片。
- 新增临时文件安全落盘：先写 `.part`，完成后校验远端临时文件大小，再 rename 为正式目标文件。
- 新增分块顺序上传和进度输出：默认 1MB 分块，上传过程输出进度。
- 新增上传失败重试：失败后最多重试 3 次，优先复用可续传的 `.part`。
- 去掉 upload 的固定 30 秒总超时，避免大文件和慢网络下被误杀。
- 新增 `stop-daemon`：用于停止当前配置文件对应的 SSH daemon 连接池；它不是单任务取消命令，会影响同一 daemon 内其它任务。
- 修复 0.3.6 中首次创建 `.part.meta` 失败的问题：改为显式使用 `CREATE | TRUNCATE | WRITE` 创建续传元数据文件。

验证：

- `npm test` 通过。
- `npm run build:native` 通过。
- 已使用 36M 镜像包真实上传到 `rn-usa-dc3`，验证 `.part.meta` 创建和完整上传成功。
