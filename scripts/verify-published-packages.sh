#!/usr/bin/env bash
# 发布后自检：确认 npm 上 6 个包（主包 + 5 个平台包）的 tarball 可下载，并校验非 win32 平台包的可执行位。
#
# 背景：npm 对含二进制的包有异步处理，tarball 可能延迟数分钟才可下载（发布后立刻安装会 404）；
# 平台包二进制还会因 artifact 往返丢失可执行位（v0.5.5 因此发过不可运行的包）。
#
# 用法：
#   scripts/verify-published-packages.sh <version> [attempts] [interval_seconds]
#   scripts/verify-published-packages.sh 0.5.7          # 默认 12 次 × 30s
#   scripts/verify-published-packages.sh 0.5.7 2 2      # 本地快速核对
#
# 退出码：0 全部通过；1 有包不可下载或权限异常。
set -uo pipefail

VERSION="${1:-}"
ATTEMPTS="${2:-12}"
INTERVAL="${3:-30}"

if [ -z "$VERSION" ]; then
  echo "用法: $0 <version> [attempts] [interval_seconds]" >&2
  exit 2
fi

# 包清单集中在此：平台包需校验可执行位，主包与 win32 包无需校验（.exe 不讲 Unix 权限）。
MAIN_PACKAGE="agent-ssh-cli"
PLATFORM_PACKAGES=("darwin-arm64" "darwin-x64" "linux-x64" "linux-arm64")
WINDOWS_PACKAGE="win32-x64"

TARBALL_PATH="/tmp/verify-published-package.tgz"
failed=0

check_package() {
  local package="$1" expect_exec="$2" attempt tarball mode
  for attempt in $(seq 1 "$ATTEMPTS"); do
    tarball=$(npm view "${package}@${VERSION}" dist.tarball 2>/dev/null || true)
    if [ -n "$tarball" ] && curl -fsSL "$tarball" -o "$TARBALL_PATH" 2>/dev/null; then
      if [ "$expect_exec" = "yes" ]; then
        mode=$(tar -tzvf "$TARBALL_PATH" | awk '/bin\/agentsshcli-native$/ {print substr($1,1,10); exit}')
        if [ "$mode" != "-rwxr-xr-x" ]; then
          echo "${package}@${VERSION} 二进制权限异常: ${mode:-未找到可执行文件}"
          return 1
        fi
      fi
      echo "${package}@${VERSION} 可用$([ "$expect_exec" = "yes" ] && echo "（可执行位已校验）")"
      return 0
    fi
    echo "${package}@${VERSION} 尚未就绪（第 ${attempt}/${ATTEMPTS} 次），${INTERVAL}s 后重试"
    sleep "$INTERVAL"
  done
  echo "${package}@${VERSION} 在 $((ATTEMPTS * INTERVAL))s 内不可下载"
  return 1
}

check_package "$MAIN_PACKAGE" "no" || failed=1
for platform in "${PLATFORM_PACKAGES[@]}"; do
  check_package "@agent-ssh-cli/${platform}" "yes" || failed=1
done
check_package "@agent-ssh-cli/${WINDOWS_PACKAGE}" "no" || failed=1

rm -f "$TARBALL_PATH"
exit "$failed"
