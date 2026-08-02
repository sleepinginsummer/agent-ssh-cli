# AGENTS 指南

agent-ssh-cli 项目说明与发布流程，供 AI agent 与维护者使用。

## 项目结构

- `bin/agentsshcli.js`：Node 入口，查找并转发到 Rust 原生二进制
- `native/`：Rust 主程序（单文件 `src/main.rs`，`--version` 从 Cargo.toml 编译时读取）
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
   # 提取 RELEASE_NOTES.md 顶部章节（最新版本）作为 tag message：
   # Action 创建 GitHub Release 时直接使用 tag message 作为 notes，一步到位
   VERSION="X.Y.Z"
   awk -v ver="v${VERSION}" '
     /^## / { if ($0 == "## " ver) { in_section = 1 } else if (in_section) { exit } }
     in_section { print }
   ' RELEASE_NOTES.md > /tmp/tag-notes.md
   git tag -a "v${VERSION}" -F /tmp/tag-notes.md   # 必须用 -a 带 message 的 annotated tag
   git push origin main --tags
   ```

4. **等待 GitHub Action 发布完成**（`publish.yml`）：
   - 矩阵构建并发布 5 个平台包（darwin-arm64/x64、linux-arm64/x64、win32-x64）
   - 发布主包 `agent-ssh-cli`
   - 创建 GitHub Release，notes 直接取 tag message（即 RELEASE_NOTES.md 对应章节），无需二次编辑
   - 检查：`gh run list`；确认：`npm view agent-ssh-cli@X.Y.Z version`
5. **更新本地 CLI 到最新版本**：发布完成后安装最新版并验证：

   ```bash
   npm install -g agent-ssh-cli@latest
   agentsshcli --version   # 确认输出新版本号
   ```


## 验证基线

- `npm test`（node --check + cargo test）
- `npm run build:native`（release 构建）
- 冒烟：`exec` / `upload` / `download` 双模式、`list`

## 注意事项

- 平台包与主包发布均由 GitHub Action 完成，**不要在本地手动 `npm publish`**（本地 npm 无发布权限，且 Action 会处理 5 平台矩阵）。
- tag 必须使用带 message 的 annotated tag（`git tag -a -F`）：`publish.yml` 创建 Release 时以 tag message 作为 notes；轻量 tag 的 notes 只有 commit 标题，发布后还需手动补充。
- 版本号更新后需重新 `npm run build:native` 才能在本地验证 `--version`。
