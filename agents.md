# AGENTS 指南

agent-ssh-cli 项目说明与发布流程，供 AI agent 与维护者使用。

## 项目结构

- `bin/agentsshcli.js`：Node 入口，查找并转发到 Rust 原生二进制
- `native/`：Rust 主程序，按职责拆分模块，`--version` 从 Cargo.toml 编译时读取：
  - `src/main.rs`：CLI 解析与调度、配置/凭据、help 与共享类型
  - `src/daemon.rs`：daemon 协议、进程生命周期、连接池与请求分发
  - `src/transfer.rs`：SFTP 上传下载、断点续传、目录递归
  - `src/ssh.rs`：建连与认证（直连 / SOCKS5 / 跳板机直连通道）
  - `src/exec.rs`：远端命令执行与 sudo/su 提权编排
  - `src/privilege.rs`：提权命令字符串（纯逻辑，无 IO）
  - `src/runtime.rs`：tokio runtime 与超时封装
- `scripts/`：平台二进制构建与打包脚本
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

4. **等待 GitHub Action 发布完成**（`publish.yml`）：
   - 矩阵构建并发布 5 个平台包（darwin-arm64/x64、linux-arm64/x64、win32-x64）
   - 发布主包 `agent-ssh-cli`
   - 创建 GitHub Release：notes 从仓库内 `RELEASE_NOTES.md` 自动提取当前版本章节，无需二次编辑
   - 检查：`gh run list`；确认：`npm view agent-ssh-cli@X.Y.Z version`；确认 notes：`gh release view vX.Y.Z`
5. **更新本地 CLI 到最新版本**：发布完成后安装最新版并验证：

   ```bash
   npm install -g agent-ssh-cli@latest
   agentsshcli --version   # 确认输出新版本号
   ```


## 验证基线

- `npm test`（node --check + cargo test）
- Windows 目标无法在 macOS/Linux 本地验证：`cargo check --target x86_64-pc-windows-msvc` 会在依赖 `aws-lc-sys` 处因缺少 `windows.h` 失败。改动涉及 `#[cfg(windows)]` 分支时必须靠 CI 的 `publish-platform (win32-x64)` job 验证；该 job 失败会连带跳过 `publish-main` 与 `create-release`，整次发布作废。
- `npm run build:native`（release 构建）
- 冒烟：`exec` / `upload` / `download` 双模式、`list`

## 注意事项

- 平台包与主包发布均由 GitHub Action 完成，**不要在本地手动 `npm publish`**（本地 npm 无发布权限，且 Action 会处理 5 平台矩阵）。
- 轻量 tag 即可：`publish.yml` 的 create-release 直接从 `RELEASE_NOTES.md` 提取 notes，不依赖 tag message。
- 版本号更新后需重新 `npm run build:native` 才能在本地验证 `--version`。
