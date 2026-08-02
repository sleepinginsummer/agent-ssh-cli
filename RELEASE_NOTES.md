# Release Notes

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
