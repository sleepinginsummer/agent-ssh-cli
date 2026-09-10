# AGENTS 指南

agent-ssh-cli 项目说明与发布流程，供 AI agent 与维护者使用。

## 项目结构

- `bin/agentsshcli.js`：Node 入口，查找并转发到 Rust 原生二进制
- `native/`：Rust 主程序，按职责拆分模块，`--version` 从 Cargo.toml 编译时读取：
  - `src/main.rs`：模块声明、`AppError`/`AppResult`、输出模式与 `main()`
  - `src/cli.rs`：参数结构体、help、解析与子命令调度（仅 `run` 对外）
  - `src/config.rs`：连接配置读写校验、secret 密钥库、凭据迁移、配置快照、命令黑白名单
  - `src/daemon.rs`：daemon 协议、进程生命周期、连接池与请求分发
  - `src/transfer.rs`：SFTP 上传下载、断点续传、目录递归
  - `src/ssh.rs`：建连与认证（直连 / SOCKS5 / 跳板机直连通道）
  - `src/exec.rs`：远端命令执行与 sudo/su 提权编排
  - `src/privilege.rs`：提权命令字符串（纯逻辑，无 IO）
  - `src/runtime.rs`：tokio runtime 与超时封装
  - `src/test_support.rs`：测试共享辅助（仅 `cargo test` 构建）
- `scripts/`：平台二进制构建与打包脚本、`check-cfg-ports.js`（平台分支静态检查）、`verify-published-packages.sh`（发布后自检）
- `.github/workflows/`：CI 发布流水线（`publish.yml` 监听 `v*` tag）

## 发布流程

1. **更新版本号**（按改动量决定 minor 或 patch）：
   - `package.json`：`version` 及 `optionalDependencies` 中 5 个平台包版本
   - `native/Cargo.toml`：`version`（含 `Cargo.lock` 同步）
   - `README.md`：release badge 中的版本号
   - `package-lock.json`：版本引用同步
   - `plan.md`：开头「当前版本」行

2. **更新 `RELEASE_NOTES.md`**：在文件顶部新增 `## vX.Y.Z` 一节，列出本次改动与验证结果。

3. **提交并推送**（推送 tag 自动触发 GitHub Action 发布）：

   ```bash
   git add -A
   git commit -m "release vX.Y.Z"
   git tag vX.Y.Z
   git push origin main --tags
   ```

4. **等待 GitHub Action 发布完成**（`publish.yml`，三阶段）：
   - 阶段一 `build-platform`：矩阵构建 5 个平台并上传 artifact，不接触 registry
   - 阶段二 `publish-platform` → `publish-main`：**全部平台构建成功后才开始发布**，任一平台编译失败则一个包都不发布；平台包发布前会恢复二进制可执行位（artifact 往返不保留文件权限，原因见「注意事项」）
   - 阶段三 `verify-packages` → `create-release`：执行 `scripts/verify-published-packages.sh <version>`，轮询 6 个包（主包 + 5 平台包）的 tarball 可下载性并校验非 win32 平台包的可执行位；npm 对含二进制的包有异步处理，tarball 可能延迟数分钟才可下载；自检未通过则整次发布判失败、不创建 Release
   - 矩阵覆盖：darwin-arm64/x64、linux-arm64/x64、win32-x64
   - 创建 GitHub Release：notes 从仓库内 `RELEASE_NOTES.md` 自动提取当前版本章节，无需二次编辑
   - 检查：`gh run list`；确认：`npm view agent-ssh-cli@X.Y.Z version`；确认 notes：`gh release view vX.Y.Z`

5. **更新本地 CLI 到最新版本**：发布完成后安装最新版并验证：

   ```bash
   npm install -g agent-ssh-cli@latest
   agentsshcli --version   # 确认输出新版本号
   ```


## 验证基线

- `npm test`（node --check + `scripts/check-cfg-ports.js` + cargo test）；平台分支检查静态拦截三类只在 win32 暴露的问题：cfg 变体可见性不一致、跨模块引用私有项、`#[cfg]` 孤儿属性贴在平台无关 import 上
- Windows 目标无法在 macOS/Linux 本地验证：`cargo check --target x86_64-pc-windows-msvc` 会在依赖 `aws-lc-sys` 处因缺少 `windows.h` 失败。改动涉及 `#[cfg(windows)]` 分支时必须靠 CI 的 `publish-platform (win32-x64)` job 验证；该 job 失败会连带跳过 `publish-main` 与 `create-release`，整次发布作废。
- `npm run build:native`（release 构建）
- 冒烟：`exec` / `upload` / `download` 双模式、`list`

## 注意事项

- **发布产物要自证可用**：`actions/upload-artifact` / `download-artifact` 不保留文件权限，平台包二进制经 artifact 往返会变成 `0644`，因此 `publish-platform` 里发布前有显式 `chmod +x`，改动发布流程时不要删掉（v0.5.5 曾因缺可执行位导致 macOS/Linux 安装后 `EACCES`，已发布的包无法覆盖，只能发 v0.5.6 补救）。
- 发布自检由 `scripts/verify-published-packages.sh` 完成（CI 与本地同一份脚本）：tarball 不可下载或平台包缺可执行位都会让整次发布失败；本地复核用 `npm run verify:published -- 0.5.7`（可加次数与间隔参数做快速核对）。
- 非 tag 触发（`workflow_dispatch`）只跑构建阶段，用于验证构建链路，不会写入 registry；发布类 job 由 `if: startsWith(github.ref, 'refs/tags/v')` 守住。
- 平台包与主包发布均由 GitHub Action 完成，**不要在本地手动 `npm publish`**（本地 npm 无发布权限，且 Action 会处理 5 平台矩阵）。
- 轻量 tag 即可：`publish.yml` 的 create-release 直接从 `RELEASE_NOTES.md` 提取 notes，不依赖 tag message。
- 版本号更新后需重新 `npm run build:native` 才能在本地验证 `--version`。
