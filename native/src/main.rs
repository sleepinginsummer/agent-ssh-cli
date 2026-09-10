mod cli;
mod config;
mod daemon;
mod exec;
mod privilege;
mod runtime;
mod ssh;
mod transfer;

use std::env;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
struct AppError(String);

type AppResult<T> = Result<T, AppError>;

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<url::ParseError> for AppError {
    fn from(error: url::ParseError) -> Self {
        Self::new(error.to_string())
    }
}

static JSON_OUTPUT_MODE: AtomicBool = AtomicBool::new(false);

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    // 预扫描 --json：参数解析阶段的错误也按 JSON 格式输出（解析成功后会以 parsed 为准覆盖）。
    if argv.iter().any(|item| item == "--json") {
        JSON_OUTPUT_MODE.store(true, Ordering::Relaxed);
    }
    if let Err(error) = cli::run(argv) {
        if JSON_OUTPUT_MODE.load(Ordering::Relaxed) {
            eprintln!(
                "{}",
                serde_json::json!({"exitCode": 1, "stdout": "", "stderr": error.to_string()})
            );
        } else {
            eprintln!("{}", error);
        }
        process::exit(1);
    }
}

#[cfg(test)]
mod test_support;
