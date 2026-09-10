// 异步运行时辅助：把 tokio 运行时创建与超时封装集中在一处，供 exec/transfer/daemon 复用。

use crate::{AppError, AppResult};
use std::time::Duration;

pub(crate) fn run_with_timeout<T, F>(timeout_ms: u64, future: F) -> AppResult<T>
where
    F: std::future::Future<Output = AppResult<T>>,
{
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
    block_with_timeout(&runtime, timeout_ms, future)
}

pub(crate) fn block_with_timeout<T, F>(
    runtime: &tokio::runtime::Runtime,
    timeout_ms: u64,
    future: F,
) -> AppResult<T>
where
    F: std::future::Future<Output = AppResult<T>>,
{
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(timeout_ms), future)
            .await
            .map_err(|_| AppError::new(format!("操作超时: {} ms", timeout_ms)))?
    })
}
