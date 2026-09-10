// 测试共享辅助：仅在 `cargo test` 构建中编译。

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

/// 写入临时配置文件，返回 (临时目录, 配置文件路径)。
pub(crate) fn write_config(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, content).unwrap();
    (dir, path)
}
