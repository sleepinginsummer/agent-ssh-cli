use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
#[cfg(windows)]
use interprocess::local_socket::{
    prelude::*, GenericNamespaced, ListenerOptions, Stream as LocalSocketStream,
};
use rand_core::{OsRng, RngCore};
use regex::Regex;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{client, ChannelMsg, Disconnect, Preferred};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, SeekFrom, Write};
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use url::Url;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG_DIR: &str = ".agent-ssh-cli";
const DEFAULT_CONFIG_FILE: &str = "config.json";
const SECRET_KEY_FILE: &str = "secret.key";
const SECRETS_FILE: &str = "secrets.json";
const MIGRATION_LOCK_FILE: &str = ".password-migration.lock";
const SECRETS_VERSION: u8 = 1;
const PASSWORD_REF_PREFIX: &str = "agentsshcli:";
const DEFAULT_CACHE_TTL_MS: u64 = 180_000;
const DAEMON_START_TIMEOUT_MS: u64 = 3_000;
const DAEMON_REQUEST_TIMEOUT_MS: u64 = 86_400_000;
const DAEMON_RESPONSE_LENGTH_BYTES: usize = 8;
const TRANSFER_CHUNK_BYTES: usize = 1024 * 1024;
const TRANSFER_MAX_RETRIES: usize = 3;

const HELP_AGENTSSHCLI: &str = r#"
用法:
  agentsshcli list [--config <path>] [--json]
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] --connection <name> (--command <command>|--command-file <path>) [--directory <dir>] [--timeout <ms>]
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <localPath> <remotePath>
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --local <path> --remote <path>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <remotePath> <localPath>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --remote <path> --local <path>
  agentsshcli init-config
  agentsshcli stop-daemon [--config <path>]
  agentsshcli help [list|exec|upload|download|stop-daemon]
  agentsshcli --help
  agentsshcli --version

说明:
  agent-ssh-cli Rust 原生入口。exec/upload/download 默认使用 Rust daemon 缓存 SSH 连接；传入 --no-cache 时才跳过缓存并直连。
"#;

const HELP_LIST: &str = r#"
用法:
  agentsshcli list [--config <path>] [--json]
  agentsshcli help list
  agentsshcli --version

说明:
  列出当前配置文件中的 SSH 连接。
"#;

const HELP_EXEC: &str = r#"
用法:
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] [--json] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] [--json] --connection <name> (--command <command>|--command-file <path>) [--directory <dir>] [--timeout <ms>]
  agentsshcli help exec
  agentsshcli --version

说明:
  在远端执行命令。默认不分配伪终端，可通过 --pty 临时开启。
  --json: 输出结构化 JSON，字段为 exitCode/stdout/stderr。
"#;

const HELP_UPLOAD: &str = r#"
用法:
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] [--timeout <ms>] [--json] [--recursive] <connectionName> <localPath> <remotePath>
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] [--timeout <ms>] [--json] [--recursive] --connection <name> --local <path> --remote <path>
  agentsshcli help upload
  agentsshcli --version

说明:
  上传本地文件到远端。默认使用 daemon 缓存，可通过 --no-cache 直连。
  --timeout <ms>: 总超时毫秒值，默认不限制（大文件允许长时间运行）。
  --recursive: 递归上传目录，保持相对路径。
  --json: 输出结构化 JSON。
"#;
const HELP_DOWNLOAD: &str = r#"
用法:
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] [--timeout <ms>] [--json] [--recursive] <connectionName> <remotePath> <localPath>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] [--timeout <ms>] [--json] [--recursive] --connection <name> --remote <path> --local <path>
  agentsshcli help download
  agentsshcli --version

说明:
  下载远端文件到本地。默认使用 daemon 缓存，可通过 --no-cache 直连。
  --timeout <ms>: 总超时毫秒值，默认不限制（大文件允许长时间运行）。
  --recursive: 递归下载目录，保持相对路径。
  --json: 输出结构化 JSON。
"#;

const HELP_STOP_DAEMON: &str = r#"
用法:
  agentsshcli stop-daemon [--config <path>]
  agentsshcli help stop-daemon

说明:
  停止当前配置文件对应的 SSH 缓存进程。这是连接池维护命令，不用于精确取消单个上传任务。
"#;

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConnection {
    name: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    password_ref: Option<String>,
    private_key: Option<String>,
    passphrase: Option<String>,
    socks_proxy: Option<String>,
    jump_host: Option<String>,
    pty: Option<bool>,
    allowed_local_paths: Option<Vec<String>>,
    command_whitelist: Option<Vec<String>>,
    command_blacklist: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct PatternRule {
    regex: Regex,
}

#[derive(Debug, Clone)]
struct Connection {
    name: String,
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    password_ref: Option<String>,
    private_key: Option<String>,
    passphrase: Option<String>,
    socks_proxy: Option<String>,
    jump_host: Option<String>,
    pty: Option<bool>,
    command_whitelist: Vec<PatternRule>,
    command_blacklist: Vec<PatternRule>,
}

#[derive(Debug)]
struct GlobalArgs {
    config_path: PathBuf,
    help: bool,
    version: bool,
    no_cache: bool,
    cache_ttl_ms: Option<u64>,
    args: Vec<String>,
}

#[derive(Debug)]
struct ExecuteArgs {
    global: GlobalArgs,
    connection_name: String,
    command: String,
    command_file: Option<String>,
    directory: Option<String>,
    timeout_ms: u64,
    pty: Option<bool>,
    json_output: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadResumeMeta {
    file_size: u64,
    modified_ms: u64,
    chunk_bytes: usize,
}

#[derive(Debug)]
struct TransferArgs {
    global: GlobalArgs,
    connection_name: String,
    local_path: String,
    remote_path: String,
    // None 表示不限制总超时（大文件传输默认不设限），传入 --timeout 时限制。
    timeout_ms: Option<u64>,
    recursive: bool,
    json_output: bool,
}

#[derive(Debug)]
struct SocksProxy {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

trait SshStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> SshStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

// --json 模式下，错误输出也转为 JSON，由 main 统一格式化。
static JSON_OUTPUT_MODE: AtomicBool = AtomicBool::new(false);

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    // 预扫描 --json：参数解析阶段的错误也按 JSON 格式输出（解析成功后会以 parsed 为准覆盖）。
    if argv.iter().any(|item| item == "--json") {
        JSON_OUTPUT_MODE.store(true, Ordering::Relaxed);
    }
    if let Err(error) = run(argv) {
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

fn run(argv: Vec<String>) -> AppResult<()> {
    let Some((command, args)) = argv.split_first() else {
        print_help("agentsshcli")?;
        return Ok(());
    };
    match command.as_str() {
        "--help" | "-h" => print_help("agentsshcli"),
        "--version" | "-v" | "version" => print_version(),
        "help" => print_help(args.first().map(String::as_str).unwrap_or("agentsshcli")),
        "init-config" => init_config(),
        "list" => run_list(args.to_vec()),
        "exec" => run_exec(args.to_vec()),
        "upload" => run_upload(args.to_vec()),
        "download" => run_download(args.to_vec()),
        "stop-daemon" => run_stop_daemon(args.to_vec()),
        "__daemon" => run_daemon(args.to_vec()),
        _ => Err(AppError::new(format!(
            "未知命令: {}，使用 agentsshcli --help 查看说明",
            command
        ))),
    }
}

fn print_version() -> AppResult<()> {
    println!("{}", VERSION);
    Ok(())
}

fn print_help(name: &str) -> AppResult<()> {
    let help = match name {
        "agentsshcli" => HELP_AGENTSSHCLI,
        "list" | "sshls" => HELP_LIST,
        "exec" | "sshx" => HELP_EXEC,
        "upload" | "sshupload" => HELP_UPLOAD,
        "download" | "sshdownload" => HELP_DOWNLOAD,
        "stop-daemon" => HELP_STOP_DAEMON,
        _ => return Err(AppError::new(format!("未知帮助命令: {}", name))),
    };
    println!("{}", help.trim());
    Ok(())
}

fn default_config_path() -> PathBuf {
    if let Ok(value) = env::var("AGENT_SSH_CONFIG") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_CONFIG_DIR)
        .join(DEFAULT_CONFIG_FILE)
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
}

fn project_root() -> AppResult<PathBuf> {
    let exe = env::current_exe()?;
    let mut current = exe.parent();
    while let Some(dir) = current {
        if dir.join("package.json").exists() && dir.join("example.config.json").exists() {
            return Ok(dir.to_path_buf());
        }
        current = dir.parent();
    }
    Ok(env::current_dir()?)
}

fn init_config() -> AppResult<()> {
    let target = default_config_path();
    if target.exists() {
        return Err(AppError::new(format!(
            "{} 已存在，未覆盖",
            target.display()
        )));
    }
    let source = project_root()?.join("example.config.json");
    fs::create_dir_all(
        target
            .parent()
            .ok_or_else(|| AppError::new("默认配置路径缺少父目录"))?,
    )?;
    fs::copy(&source, &target).map_err(|error| {
        AppError::new(format!(
            "复制默认配置失败: {} -> {}，{}",
            source.display(),
            target.display(),
            error
        ))
    })?;
    println!("已创建 {}", target.display());
    Ok(())
}

fn is_non_empty(value: &Option<String>) -> bool {
    value.as_ref().is_some_and(|item| !item.trim().is_empty())
}

fn ensure_string_array(
    values: Option<Vec<String>>,
    field_name: &str,
    index: usize,
) -> AppResult<Vec<String>> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| {
            if value.trim().is_empty() {
                return Err(AppError::new(format!(
                    "ssh-config.json 第 {} 项的 {} 必须只包含非空字符串",
                    index + 1,
                    field_name
                )));
            }
            Ok(value)
        })
        .collect()
}

fn ensure_regex_array(
    values: Option<Vec<String>>,
    field_name: &str,
    index: usize,
) -> AppResult<Vec<PatternRule>> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|pattern| {
            if pattern.trim().is_empty() {
                return Err(AppError::new(format!(
                    "ssh-config.json 第 {} 项的 {} 必须只包含非空字符串",
                    index + 1,
                    field_name
                )));
            }
            let regex = Regex::new(&pattern).map_err(|error| {
                AppError::new(format!(
                    "ssh-config.json 第 {} 项的 {} 含有非法正则: {}，{}",
                    index + 1,
                    field_name,
                    pattern,
                    error
                ))
            })?;
            Ok(PatternRule { regex })
        })
        .collect()
}

fn normalize_entry(entry: RawConnection, index: usize) -> AppResult<Connection> {
    let name = entry
        .name
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::new(format!(
                "ssh-config.json 第 {} 项缺少合法的 name",
                index + 1
            ))
        })?;
    let host = entry
        .host
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::new(format!(
                "ssh-config.json 第 {} 项缺少合法的 host",
                index + 1
            ))
        })?;
    let username = entry
        .username
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::new(format!(
                "ssh-config.json 第 {} 项缺少合法的 username",
                index + 1
            ))
        })?;
    let port = entry.port.unwrap_or(22);
    if port == 0 {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 port 非法",
            index + 1
        )));
    }
    let has_password = is_non_empty(&entry.password);
    let has_password_ref = is_non_empty(&entry.password_ref);
    let has_private_key = is_non_empty(&entry.private_key);
    let auth_count = [has_password || has_password_ref, has_private_key]
        .iter()
        .filter(|item| **item)
        .count();
    if auth_count == 0 {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项必须配置 password、passwordRef 或 privateKey 其中之一",
            index + 1
        )));
    }
    if auth_count > 1 {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项同时配置了多个认证方式，只允许保留一种",
            index + 1
        )));
    }
    if entry
        .password_ref
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 passwordRef 必须是非空字符串",
            index + 1
        )));
    }
    if entry
        .passphrase
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 passphrase 必须是非空字符串",
            index + 1
        )));
    }
    if entry
        .socks_proxy
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 socksProxy 必须是非空字符串",
            index + 1
        )));
    }
    if entry
        .jump_host
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 jumpHost 必须是非空字符串",
            index + 1
        )));
    }
    if matches!(
        entry.jump_host.as_deref().map(str::trim),
        Some(value) if value == name
    ) {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 jumpHost 不能指向自身",
            index + 1
        )));
    }
    let _ = ensure_string_array(entry.allowed_local_paths, "allowedLocalPaths", index)?;
    Ok(Connection {
        name,
        host,
        port,
        username,
        password: entry.password.filter(|_| has_password),
        password_ref: entry.password_ref.filter(|_| has_password_ref),
        private_key: entry.private_key.filter(|_| has_private_key),
        passphrase: entry.passphrase,
        socks_proxy: entry.socks_proxy,
        jump_host: entry.jump_host,
        pty: entry.pty,
        command_whitelist: ensure_regex_array(entry.command_whitelist, "commandWhitelist", index)?,
        command_blacklist: ensure_regex_array(entry.command_blacklist, "commandBlacklist", index)?,
    })
}

fn load_config(config_path: &Path) -> AppResult<Vec<Connection>> {
    let raw = fs::read_to_string(config_path)?;
    let parsed: Vec<RawConnection> = serde_json::from_str(&raw)
        .map_err(|error| AppError::new(format!("ssh-config.json 解析失败: {}", error)))?;
    if parsed.is_empty() {
        return Err(AppError::new("ssh-config.json 不能为空"));
    }
    let configs: Vec<Connection> = parsed
        .into_iter()
        .enumerate()
        .map(|(index, item)| normalize_entry(item, index))
        .collect::<AppResult<Vec<_>>>()?;
    let mut seen = HashSet::new();
    for config in &configs {
        if !seen.insert(config.name.clone()) {
            return Err(AppError::new(format!(
                "ssh-config.json 存在重复的连接名: {}",
                config.name
            )));
        }
    }
    Ok(configs)
}

fn load_config_for_connection(
    config_path: &Path,
    connection_name: &str,
) -> AppResult<Vec<Connection>> {
    let mut configs = load_config(config_path)?;
    let _ = find_connection(&configs, connection_name)?;
    resolve_password_ref_for_connection(config_path, &mut configs, connection_name)?;
    resolve_jump_password_refs(config_path, &mut configs, connection_name)?;
    validate_jump_hosts(&configs)?;
    Ok(configs)
}

fn validate_jump_hosts(configs: &[Connection]) -> AppResult<()> {
    for connection in configs {
        let Some(jump_name) = connection.jump_host.as_deref() else {
            continue;
        };
        let jump = find_connection(configs, jump_name)?;
        if jump.jump_host.is_some() {
            return Err(AppError::new(format!(
                "连接 {} 的 jumpHost {} 不能再配置 jumpHost，当前仅支持单级跳板机",
                connection.name, jump_name
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct SecretsFile {
    version: u8,
    items: HashMap<String, SecretItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecretItem {
    nonce: String,
    ciphertext: String,
}

fn config_dir(config_path: &Path) -> AppResult<PathBuf> {
    let absolute = path_absolute(config_path)?;
    absolute
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| AppError::new("配置路径缺少父目录"))
}

fn secret_key_path(config_path: &Path) -> AppResult<PathBuf> {
    Ok(config_dir(config_path)?.join(SECRET_KEY_FILE))
}

fn secrets_path(config_path: &Path) -> AppResult<PathBuf> {
    Ok(config_dir(config_path)?.join(SECRETS_FILE))
}

struct MigrationLock {
    file: File,
}

impl MigrationLock {
    fn acquire(config_path: &Path) -> AppResult<Self> {
        let path = config_dir(config_path)?.join(MIGRATION_LOCK_FILE);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        lock_file_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(unix)]
fn lock_file_exclusive(file: &File) -> AppResult<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(file);
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(AppError::new(format!(
            "获取本地文件锁失败: {}",
            std::io::Error::last_os_error()
        )))
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) -> AppResult<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(file);
    let rc = unsafe { libc::flock(fd, libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(AppError::new(format!(
            "释放本地文件锁失败: {}",
            std::io::Error::last_os_error()
        )))
    }
}

#[cfg(not(unix))]
fn lock_file_exclusive(_file: &File) -> AppResult<()> {
    Ok(())
}

#[cfg(not(unix))]
fn unlock_file(_file: &File) -> AppResult<()> {
    Ok(())
}

fn load_or_create_secret_key(config_path: &Path) -> AppResult<[u8; 32]> {
    let path = secret_key_path(config_path)?;
    if path.exists() {
        let encoded = fs::read_to_string(&path)?;
        let bytes = BASE64_STANDARD
            .decode(encoded.trim())
            .map_err(|error| AppError::new(format!("读取本地密码密钥失败: {}", error)))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AppError::new("本地密码密钥长度非法"))?;
        return Ok(key);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    write_private_file(&path, BASE64_STANDARD.encode(key).as_bytes())?;
    Ok(key)
}

fn load_local_secret_key(config_path: &Path) -> AppResult<[u8; 32]> {
    let path = secret_key_path(config_path)?;
    let encoded = fs::read_to_string(&path).map_err(|error| {
        AppError::new(format!(
            "读取本地密码密钥失败: {}，{}",
            path.display(),
            error
        ))
    })?;
    let bytes = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|error| AppError::new(format!("读取本地密码密钥失败: {}", error)))?;
    bytes
        .try_into()
        .map_err(|_| AppError::new("本地密码密钥长度非法"))
}

fn load_secrets(config_path: &Path) -> AppResult<SecretsFile> {
    let path = secrets_path(config_path)?;
    if !path.exists() {
        return Ok(SecretsFile {
            version: SECRETS_VERSION,
            items: HashMap::new(),
        });
    }
    let raw = fs::read_to_string(&path)?;
    let secrets: SecretsFile = serde_json::from_str(&raw)
        .map_err(|error| AppError::new(format!("secrets.json 解析失败: {}", error)))?;
    if secrets.version != SECRETS_VERSION {
        return Err(AppError::new("secrets.json 版本不支持"));
    }
    Ok(secrets)
}

fn save_secrets(config_path: &Path, secrets: &SecretsFile) -> AppResult<()> {
    let path = secrets_path(config_path)?;
    let raw = serde_json::to_vec_pretty(secrets)?;
    write_private_file(&path, &raw)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn encrypt_password(config_path: &Path, password_ref: &str, password: &str) -> AppResult<()> {
    let key = load_or_create_secret_key(config_path)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), password.as_bytes())
        .map_err(|_| AppError::new("加密密码失败"))?;
    let mut secrets = load_secrets(config_path)?;
    secrets.items.insert(
        password_ref.to_string(),
        SecretItem {
            nonce: BASE64_STANDARD.encode(nonce_bytes),
            ciphertext: BASE64_STANDARD.encode(ciphertext),
        },
    );
    save_secrets(config_path, &secrets)
}

fn decrypt_password(config_path: &Path, password_ref: &str) -> AppResult<String> {
    let key = load_local_secret_key(config_path)?;
    let secrets = load_secrets(config_path)?;
    let item = secrets.items.get(password_ref).ok_or_else(|| {
        AppError::new(format!(
            "未找到 passwordRef 对应的本地密码: {}",
            password_ref
        ))
    })?;
    let nonce = BASE64_STANDARD
        .decode(&item.nonce)
        .map_err(|error| AppError::new(format!("本地密码 nonce 非法: {}", error)))?;
    if nonce.len() != 12 {
        return Err(AppError::new("本地密码 nonce 长度非法"));
    }
    let ciphertext = BASE64_STANDARD
        .decode(&item.ciphertext)
        .map_err(|error| AppError::new(format!("本地密码密文非法: {}", error)))?;
    let plaintext = ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| AppError::new(format!("解密本地密码失败: {}", password_ref)))?;
    String::from_utf8(plaintext)
        .map_err(|error| AppError::new(format!("本地密码编码非法: {}", error)))
}

fn resolve_password_ref_for_connection(
    config_path: &Path,
    configs: &mut [Connection],
    connection_name: &str,
) -> AppResult<()> {
    let config = configs
        .iter_mut()
        .find(|item| item.name == connection_name)
        .ok_or_else(|| AppError::new(format!("未找到连接配置: {}", connection_name)))?;
    if config.password.is_none() {
        if let Some(password_ref) = config.password_ref.as_deref() {
            config.password = Some(decrypt_password(config_path, password_ref)?);
        }
    }
    Ok(())
}

fn resolve_jump_password_refs(
    config_path: &Path,
    configs: &mut [Connection],
    connection_name: &str,
) -> AppResult<()> {
    let jump_name = find_connection(configs, connection_name)?.jump_host.clone();
    if let Some(jump_name) = jump_name {
        resolve_password_ref_for_connection(config_path, configs, &jump_name)?;
    }
    Ok(())
}

fn password_ref_for(connection_name: &str) -> String {
    format!("{}{}", PASSWORD_REF_PREFIX, connection_name)
}

fn migrate_plain_password_for_connection(
    config_path: &Path,
    connection_name: &str,
) -> AppResult<bool> {
    let _lock = MigrationLock::acquire(config_path)?;
    let raw = fs::read_to_string(config_path)?;
    let mut values: Vec<serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|error| AppError::new(format!("ssh-config.json 解析失败: {}", error)))?;
    let mut migrated = false;
    for (index, value) in values.iter_mut().enumerate() {
        let object = value.as_object_mut().ok_or_else(|| {
            AppError::new(format!("ssh-config.json 第 {} 项必须是对象", index + 1))
        })?;
        let name = object
            .get("name")
            .and_then(|item| item.as_str())
            .unwrap_or_default();
        if name != connection_name {
            continue;
        }
        let Some(password) = object.get("password").and_then(|item| item.as_str()) else {
            return Ok(false);
        };
        if password.trim().is_empty() {
            return Ok(false);
        }
        let password = password.to_string();
        let password_ref = object
            .get("passwordRef")
            .and_then(|item| item.as_str())
            .filter(|item| !item.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| password_ref_for(connection_name));
        encrypt_password(config_path, &password_ref, &password)?;
        object.insert(
            "password".to_string(),
            serde_json::Value::String(String::new()),
        );
        object.insert(
            "passwordRef".to_string(),
            serde_json::Value::String(password_ref),
        );
        migrated = true;
        break;
    }
    if migrated {
        write_config_values(config_path, &values)?;
    }
    Ok(migrated)
}

fn write_config_values(config_path: &Path, values: &[serde_json::Value]) -> AppResult<()> {
    let raw = serde_json::to_vec_pretty(values)?;
    let tmp = config_path.with_extension("tmp");
    fs::write(&tmp, raw)?;
    fs::rename(tmp, config_path)?;
    Ok(())
}

fn prepare_connection_config(config_path: &Path, connection_name: &str) -> AppResult<()> {
    let _ = migrate_plain_password_for_connection(config_path, connection_name)?;
    Ok(())
}

fn hash_file(path: &Path) -> AppResult<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigSnapshot {
    modified: Option<SystemTime>,
    len: u64,
    hash: String,
}

impl ConfigSnapshot {
    fn read(path: &Path) -> AppResult<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            modified: metadata.modified().ok(),
            len: metadata.len(),
            hash: hash_file(path)?,
        })
    }

    fn metadata_matches(&self, path: &Path) -> AppResult<bool> {
        let metadata = fs::metadata(path)?;
        Ok(self.modified == metadata.modified().ok() && self.len == metadata.len())
    }
}

fn find_connection<'a>(
    configs: &'a [Connection],
    connection_name: &str,
) -> AppResult<&'a Connection> {
    configs
        .iter()
        .find(|item| item.name == connection_name)
        .ok_or_else(|| AppError::new(format!("未找到连接配置: {}", connection_name)))
}

fn path_absolute(path: &Path) -> AppResult<PathBuf> {
    path_absolute_from(path, &env::current_dir()?)
}

fn path_absolute_from(path: &Path, base_cwd: &Path) -> AppResult<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(base_cwd.join(path))
    }
}

fn canonical_or_absolute(path: PathBuf) -> PathBuf {
    path.canonicalize().unwrap_or(path)
}

fn parse_global_args(argv: Vec<String>) -> AppResult<GlobalArgs> {
    let mut args = argv.into_iter().peekable();
    let mut config_path = default_config_path();
    let mut help = false;
    let mut version = false;
    let mut no_cache = false;
    let mut cache_ttl_ms = None;
    let mut remaining = Vec::new();
    // 扫描到第一个位置参数（非 - 开头的 token）为止：
    // 全局参数（--no-cache/--cache-ttl/--config 等）可与子命令参数（--json/--timeout 等）
    // 任意顺序混排，只需位于连接名之前；位置参数之后的 token 原样交给子命令解析器，
    // 避免误吞命令内容中的同名 flag。
    while let Some(current) = args.next() {
        if !current.starts_with('-') {
            remaining.push(current);
            remaining.extend(args);
            break;
        }
        match current.as_str() {
            "--help" | "-h" => help = true,
            "--version" | "-v" => version = true,
            "--no-cache" => no_cache = true,
            "--cache-ttl" => {
                let value = args
                    .next()
                    .ok_or_else(|| AppError::new("--cache-ttl 缺少毫秒值"))?;
                let ttl = normalize_positive_u64(&value, "cache-ttl 必须是正整数毫秒值")?;
                cache_ttl_ms = Some(ttl);
            }
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| AppError::new("--config 缺少路径"))?;
                config_path = PathBuf::from(value);
            }
            // 未知 flag：保留给子命令解析器（如 --json/--timeout/--pty/--recursive）
            _ => remaining.push(current),
        }
    }
    Ok(GlobalArgs {
        config_path,
        help,
        version,
        no_cache,
        cache_ttl_ms,
        args: remaining,
    })
}

fn normalize_positive_u64(value: &str, message: &str) -> AppResult<u64> {
    let parsed = value.parse::<u64>().map_err(|_| AppError::new(message))?;
    if parsed == 0 {
        return Err(AppError::new(message));
    }
    Ok(parsed)
}

fn take_option(args: &mut Vec<String>, names: &[&str]) -> AppResult<Option<String>> {
    let indexes: Vec<usize> = args
        .iter()
        .enumerate()
        .filter_map(|(index, item)| names.contains(&item.as_str()).then_some(index))
        .collect();
    if indexes.len() > 1 {
        return Err(AppError::new(format!("参数重复声明: {}", names[0])));
    }
    let Some(index) = indexes.first().copied() else {
        return Ok(None);
    };
    let Some(value) = args.get(index + 1).cloned() else {
        return Err(AppError::new(format!("{} 缺少参数值", args[index])));
    };
    if value.starts_with("--") {
        return Err(AppError::new(format!("{} 缺少参数值", args[index])));
    }
    args.drain(index..=index + 1);
    Ok(Some(value))
}

fn take_positional(args: &mut Vec<String>, field_name: &str) -> AppResult<Option<String>> {
    if args.is_empty() {
        return Ok(None);
    }
    let value = args.remove(0);
    if value.starts_with("--") {
        return Err(AppError::new(format!(
            "{} 位置参数非法: {}",
            field_name, value
        )));
    }
    Ok(Some(value))
}

// 第一个位置参数（不以 - 开头的 token）的索引；全部是 flag 时返回 args.len()。
fn positional_boundary(args: &[String]) -> usize {
    args.iter()
        .position(|item| !item.starts_with('-'))
        .unwrap_or(args.len())
}

fn take_bool_flag(args: &mut Vec<String>, flag_name: &str) -> AppResult<bool> {
    // 只解析第一个位置参数之前的 flag（本项目约定参数放在连接名前），
    // 避免命令内容中的同名 token（如 --json）被误吞。
    let boundary = positional_boundary(args);
    let count = args[..boundary]
        .iter()
        .filter(|item| item.as_str() == flag_name)
        .count();
    if count > 1 {
        return Err(AppError::new(format!("参数重复声明: {}", flag_name)));
    }
    if let Some(index) = args[..boundary].iter().position(|item| item == flag_name) {
        args.remove(index);
        return Ok(true);
    }
    Ok(false)
}

fn take_bool_flag_pair(
    args: &mut Vec<String>,
    true_name: &str,
    false_name: &str,
) -> AppResult<Option<bool>> {
    // 与 take_bool_flag 相同：只解析第一个位置参数之前的 flag。
    let boundary = positional_boundary(args);
    let true_count = args[..boundary]
        .iter()
        .filter(|item| item.as_str() == true_name)
        .count();
    let false_count = args[..boundary]
        .iter()
        .filter(|item| item.as_str() == false_name)
        .count();
    if true_count > 1 {
        return Err(AppError::new(format!("参数重复声明: {}", true_name)));
    }
    if false_count > 1 {
        return Err(AppError::new(format!("参数重复声明: {}", false_name)));
    }
    if true_count == 1 && false_count == 1 {
        return Err(AppError::new(format!(
            "{} 和 {} 只能选择一个",
            true_name, false_name
        )));
    }
    if let Some(index) = args[..boundary].iter().position(|item| item == true_name) {
        args.remove(index);
        return Ok(Some(true));
    }
    if let Some(index) = args[..boundary].iter().position(|item| item == false_name) {
        args.remove(index);
        return Ok(Some(false));
    }
    Ok(None)
}


fn ensure_no_mixed(
    named: &Option<String>,
    positional: &Option<String>,
    field_name: &str,
) -> AppResult<()> {
    if named.is_some() && positional.is_some() {
        return Err(AppError::new(format!(
            "{} 同时使用了命名参数和位置参数，保留一种即可",
            field_name
        )));
    }
    Ok(())
}

fn ensure_no_unknown_options(args: &[String]) -> AppResult<()> {
    if let Some(unknown) = args.iter().find(|item| item.starts_with("--")) {
        return Err(AppError::new(format!("不支持的参数: {}", unknown)));
    }
    Ok(())
}

fn ensure_no_extra_positionals(args: &[String]) -> AppResult<()> {
    if !args.is_empty() {
        return Err(AppError::new(format!(
            "存在多余的位置参数: {}",
            args.join(" ")
        )));
    }
    Ok(())
}

fn parse_execute_args(argv: Vec<String>) -> AppResult<ExecuteArgs> {
    let global = parse_global_args(argv)?;
    if global.help || global.version {
        return Ok(ExecuteArgs {
            global,
            connection_name: String::new(),
            command: String::new(),
            command_file: None,
            directory: None,
            timeout_ms: 30000,
            pty: None,
            json_output: false,
        });
    }
    let mut args = global.args.clone();
    // 先提取全部命名参数，再解析布尔参数（只识别位置参数之前的 flag），
    // 避免命令内容中的同名 token（如 --json）被误吞。
    let connection_option = take_option(&mut args, &["--connection", "-c"])?;
    let command_option = take_option(&mut args, &["--command"])?;
    let command_file = take_option(&mut args, &["--command-file"])?;
    let directory = take_option(&mut args, &["--directory", "-d"])?;
    let timeout_value = take_option(&mut args, &["--timeout", "-t"])?;
    let json_output = take_bool_flag(&mut args, "--json")?;
    let pty = take_bool_flag_pair(&mut args, "--pty", "--no-pty")?;
    let connection_positional = take_positional(&mut args, "connectionName")?;
    let command_positional = take_positional(&mut args, "command")?;
    ensure_no_mixed(&connection_option, &connection_positional, "connectionName")?;
    ensure_no_mixed(&command_option, &command_positional, "command")?;
    ensure_no_mixed(&command_file, &command_positional, "command")?;
    if command_option.is_some() && command_file.is_some() {
        return Err(AppError::new(
            "command 同时使用了 --command 和 --command-file，保留一种即可",
        ));
    }
    ensure_no_unknown_options(&args)?;
    ensure_no_extra_positionals(&args)?;
    let connection_name = connection_option.or(connection_positional).ok_or_else(|| {
        AppError::new("缺少必填参数 connectionName 或 command，使用 --help 查看说明")
    })?;
    let command = command_option.or(command_positional).unwrap_or_default();
    if command.is_empty() && command_file.is_none() {
        return Err(AppError::new(
            "缺少必填参数 connectionName 或 command，使用 --help 查看说明",
        ));
    }
    let timeout_ms = match timeout_value {
        Some(value) => normalize_positive_u64(&value, "timeout 必须是正整数毫秒值")?,
        None => 30000,
    };
    Ok(ExecuteArgs {
        global,
        connection_name,
        command,
        command_file,
        directory,
        timeout_ms,
        pty,
        json_output,
    })
}

fn parse_transfer_args(argv: Vec<String>, mode: &str) -> AppResult<TransferArgs> {
    let global = parse_global_args(argv)?;
    if global.help || global.version {
        return Ok(TransferArgs {
            global,
            connection_name: String::new(),
            local_path: String::new(),
            remote_path: String::new(),
            timeout_ms: None,
            recursive: false,
            json_output: false,
        });
    }
    let mut args = global.args.clone();
    // 先提取全部命名参数，再解析布尔参数（只识别位置参数之前的 flag），
    // 最后补位置参数，避免路径中的同名 token 被误吞。
    let connection_named = take_option(&mut args, &["--connection", "-c"])?;
    let timeout_value = take_option(&mut args, &["--timeout", "-t"])?;
    let (local_named, remote_named) = if mode == "upload" {
        (
            take_option(&mut args, &["--local", "-l"])?,
            take_option(&mut args, &["--remote", "-r"])?,
        )
    } else {
        (
            take_option(&mut args, &["--remote", "-r"])?,
            take_option(&mut args, &["--local", "-l"])?,
        )
    };
    let json_output = take_bool_flag(&mut args, "--json")?;
    let recursive = take_bool_flag(&mut args, "--recursive")?;
    // 位置参数按字段顺序解析：upload 为 connection → local → remote，
    // download 为 connection → remote → local（与 CLI 语义一致），命名参数已占用时跳过。
    let connection_name = match connection_named {
        Some(name) => Some(name),
        None => take_positional(&mut args, "connectionName")?,
    };
    let (local_path, remote_path) = if mode == "upload" {
        let local_path = match local_named {
            Some(path) => Some(path),
            None => take_positional(&mut args, "localPath")?,
        };
        let remote_path = match remote_named {
            Some(path) => Some(path),
            None => take_positional(&mut args, "remotePath")?,
        };
        (local_path, remote_path)
    } else {
        let remote_path = match remote_named {
            Some(path) => Some(path),
            None => take_positional(&mut args, "remotePath")?,
        };
        let local_path = match local_named {
            Some(path) => Some(path),
            None => take_positional(&mut args, "localPath")?,
        };
        (local_path, remote_path)
    };
    ensure_no_unknown_options(&args)?;
    ensure_no_extra_positionals(&args)?;
    let Some(connection_name) = connection_name else {
        return Err(AppError::new("缺少必填参数，使用 --help 查看说明"));
    };
    let Some(local_path) = local_path else {
        return Err(AppError::new("缺少必填参数，使用 --help 查看说明"));
    };
    let Some(remote_path) = remote_path else {
        return Err(AppError::new("缺少必填参数，使用 --help 查看说明"));
    };
    let timeout_ms = match timeout_value {
        Some(value) => Some(normalize_positive_u64(&value, "timeout 必须是正整数毫秒值")?),
        None => None,
    };
    Ok(TransferArgs {
        global,
        connection_name,
        local_path,
        remote_path,
        timeout_ms,
        recursive,
        json_output,
    })
}

fn run_list(argv: Vec<String>) -> AppResult<()> {
    let global = parse_global_args(argv)?;
    if global.help {
        return print_help("list");
    }
    if global.version {
        return print_version();
    }
    let mut args = global.args.clone();
    // 兼容 list --json 用法：当前 list 默认输出即为 JSON。
    let _ = take_bool_flag(&mut args, "--json")?;
    if !args.is_empty() {
        return Err(AppError::new(format!(
            "agentsshcli list 不接受位置参数: {}",
            args.join(" ")
        )));
    }
    let configs = load_config(&global.config_path)?;
    let output: Vec<serde_json::Value> = configs
        .iter()
        .map(|item| {
            let mut entry = serde_json::Map::new();
            entry.insert("name".to_string(), serde_json::json!(item.name));
            entry.insert("host".to_string(), serde_json::json!(item.host));
            entry.insert("port".to_string(), serde_json::json!(item.port));
            entry.insert("username".to_string(), serde_json::json!(item.username));
            if let Some(jump) = item.jump_host.as_deref() {
                entry.insert("jumpHost".to_string(), serde_json::json!(jump));
            }
            serde_json::Value::Object(entry)
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn run_stop_daemon(argv: Vec<String>) -> AppResult<()> {
    let global = parse_global_args(argv)?;
    if global.help {
        return print_help("stop-daemon");
    }
    if global.version {
        return print_version();
    }
    if !global.args.is_empty() {
        return Err(AppError::new(format!(
            "agentsshcli stop-daemon 不接受位置参数: {}",
            global.args.join(" ")
        )));
    }
    request_stop_daemon(&global.config_path)?;
    println!("SSH 缓存进程已停止");
    Ok(())
}

fn run_exec(argv: Vec<String>) -> AppResult<()> {
    let parsed = parse_execute_args(argv)?;
    if parsed.global.help {
        return print_help("exec");
    }
    if parsed.global.version {
        return print_version();
    }
    JSON_OUTPUT_MODE.store(parsed.json_output, Ordering::Relaxed);
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    let configs = load_config_for_connection(&parsed.global.config_path, &parsed.connection_name)?;
    let connection = find_connection(&configs, &parsed.connection_name)?;
    let command = resolve_execute_command(&configs, &parsed)?;
    validate_command(connection, &command)?;
    let remote_command = match parsed.directory {
        Some(ref directory) => format!("cd -- {} && {}", shell_json_quote(directory)?, command),
        None => command.clone(),
    };
    let output = if parsed.global.no_cache {
        execute_remote_command(
            &configs,
            connection,
            &remote_command,
            parsed.timeout_ms,
            resolve_pty(connection, parsed.pty),
        )?
    } else {
        let response = request_daemon_execute(&parsed, &command)?;
        ExecOutput {
            exit_code: response.exit_code.unwrap_or(0),
            stdout: response.stdout.unwrap_or_default(),
            stderr: response.stderr.unwrap_or_default(),
        }
    };
    if parsed.json_output {
        println!(
            "{}",
            serde_json::json!({"exitCode": output.exit_code, "stdout": output.stdout, "stderr": output.stderr})
        );
        // JSON 模式下远端命令非零退出：进程退出码仍为 1（exitCode 字段已反映真实退出码），
        // 便于脚本按退出码判断成败；此处直接退出避免 main 重复输出错误 JSON。
        if output.exit_code != 0 {
            process::exit(1);
        }
    } else if output.exit_code != 0 {
        // 文本模式保持原有行为：stdout/stderr 与退出码一起作为错误信息输出。
        let mut parts = Vec::new();
        if !output.stdout.is_empty() {
            parts.push(output.stdout);
        }
        if !output.stderr.is_empty() {
            parts.push(format!("[stderr]\n{}", output.stderr));
        }
        parts.push(format!("[exit code] {}", output.exit_code));
        return Err(AppError::new(parts.join("\n")));
    } else if !output.stdout.is_empty() {
        println!("{}", output.stdout);
    }
    Ok(())
}

fn run_upload(argv: Vec<String>) -> AppResult<()> {
    let parsed = parse_transfer_args(argv, "upload")?;
    if parsed.global.help {
        return print_help("upload");
    }
    if parsed.global.version {
        return print_version();
    }
    JSON_OUTPUT_MODE.store(parsed.json_output, Ordering::Relaxed);
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    let configs = load_config_for_connection(&parsed.global.config_path, &parsed.connection_name)?;
    let connection = find_connection(&configs, &parsed.connection_name)?;
    if parsed.global.no_cache {
        let local_path = path_absolute_from(Path::new(&parsed.local_path), &env::current_dir()?)?;
        if parsed.recursive {
            upload_dir(
                &configs,
                connection,
                &local_path,
                &parsed.remote_path,
                parsed.timeout_ms,
            )?;
        } else {
            upload_file(
                &configs,
                connection,
                &local_path,
                &parsed.remote_path,
                parsed.timeout_ms,
            )?;
        }
    } else {
        request_daemon_transfer(&parsed, "upload")?;
    }
    if parsed.json_output {
        println!("{}", serde_json::json!({"exitCode": 0, "stdout": "File uploaded successfully", "stderr": ""}));
    } else {
        println!("File uploaded successfully");
    }
    Ok(())
}

fn run_download(argv: Vec<String>) -> AppResult<()> {
    let parsed = parse_transfer_args(argv, "download")?;
    if parsed.global.help {
        return print_help("download");
    }
    if parsed.global.version {
        return print_version();
    }
    JSON_OUTPUT_MODE.store(parsed.json_output, Ordering::Relaxed);
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    let configs = load_config_for_connection(&parsed.global.config_path, &parsed.connection_name)?;
    let connection = find_connection(&configs, &parsed.connection_name)?;
    if parsed.global.no_cache {
        let local_path = path_absolute_from(Path::new(&parsed.local_path), &env::current_dir()?)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if parsed.recursive {
            download_dir(
                &configs,
                connection,
                &parsed.remote_path,
                &local_path,
                parsed.timeout_ms,
            )?;
        } else {
            download_file(
                &configs,
                connection,
                &parsed.remote_path,
                &local_path,
                parsed.timeout_ms,
            )?;
        }
    } else {
        request_daemon_transfer(&parsed, "download")?;
    }
    if parsed.json_output {
        println!("{}", serde_json::json!({"exitCode": 0, "stdout": "File downloaded successfully", "stderr": ""}));
    } else {
        println!("File downloaded successfully");
    }
    Ok(())
}

fn validate_command(connection: &Connection, command: &str) -> AppResult<()> {
    if !connection.command_whitelist.is_empty()
        && !connection
            .command_whitelist
            .iter()
            .any(|item| item.regex.is_match(command))
    {
        return Err(AppError::new("命令未命中白名单，拒绝执行"));
    }
    if connection
        .command_blacklist
        .iter()
        .any(|item| item.regex.is_match(command))
    {
        return Err(AppError::new("命令命中黑名单，拒绝执行"));
    }
    Ok(())
}

fn shell_json_quote(value: &str) -> AppResult<String> {
    Ok(serde_json::to_string(value)?)
}

fn parse_socks_proxy(proxy: &str) -> AppResult<SocksProxy> {
    let value = if proxy.contains("://") {
        proxy.to_string()
    } else {
        format!("socks5://{}", proxy)
    };
    let parsed = Url::parse(&value)
        .map_err(|error| AppError::new(format!("socksProxy 格式非法: {}", error)))?;
    if parsed.scheme() != "socks5" {
        return Err(AppError::new("socksProxy 仅支持 socks5:// 协议"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::new("socksProxy 必须包含代理主机和端口"))?
        .to_string();
    let port = parsed
        .port()
        .ok_or_else(|| AppError::new("socksProxy 必须包含代理主机和端口"))?;
    let username = (!parsed.username().is_empty()).then(|| parsed.username().to_string());
    let password = parsed.password().map(ToString::to_string);
    if username.is_some() != password.is_some() {
        return Err(AppError::new("socksProxy 用户名和密码必须同时提供"));
    }
    Ok(SocksProxy {
        host,
        port,
        username,
        password,
    })
}

async fn read_exact_async(stream: &mut tokio::net::TcpStream, length: usize) -> AppResult<Vec<u8>> {
    let mut buffer = vec![0_u8; length];
    stream.read_exact(&mut buffer).await?;
    Ok(buffer)
}

async fn authenticate_socks_proxy(
    stream: &mut tokio::net::TcpStream,
    proxy: &SocksProxy,
) -> AppResult<()> {
    let method = if proxy.username.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let response = read_exact_async(stream, 2).await?;
    if response[0] != 0x05 {
        return Err(AppError::new("SOCKS5 代理响应版本非法"));
    }
    if response[1] == 0xff {
        return Err(AppError::new("SOCKS5 代理不接受当前认证方式"));
    }
    if response[1] == 0x00 {
        return Ok(());
    }
    if response[1] != 0x02 || proxy.username.is_none() {
        return Err(AppError::new("SOCKS5 代理返回了不支持的认证方式"));
    }
    let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
    let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
    if username.len() > 255 || password.len() > 255 {
        return Err(AppError::new("SOCKS5 用户名或密码过长"));
    }
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    let auth_response = read_exact_async(stream, 2).await?;
    if auth_response[1] != 0x00 {
        return Err(AppError::new("SOCKS5 代理认证失败"));
    }
    Ok(())
}

fn encode_target_address(host: &str) -> AppResult<Vec<u8>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(addr) => {
                let mut bytes = vec![0x01];
                bytes.extend_from_slice(&addr.octets());
                bytes
            }
            IpAddr::V6(addr) => {
                let mut bytes = vec![0x04];
                bytes.extend_from_slice(&addr.octets());
                bytes
            }
        });
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(AppError::new("SOCKS5 目标主机名过长"));
    }
    let mut bytes = vec![0x03, host_bytes.len() as u8];
    bytes.extend_from_slice(host_bytes);
    Ok(bytes)
}

async fn read_socks_connect_response(stream: &mut tokio::net::TcpStream) -> AppResult<()> {
    let header = read_exact_async(stream, 4).await?;
    if header[0] != 0x05 {
        return Err(AppError::new("SOCKS5 代理响应版本非法"));
    }
    if header[1] != 0x00 {
        return Err(AppError::new(format!(
            "SOCKS5 代理连接目标失败，响应码 {}",
            header[1]
        )));
    }
    if header[2] != 0x00 {
        return Err(AppError::new("SOCKS5 代理响应保留字段非法"));
    }
    match header[3] {
        0x01 => {
            read_exact_async(stream, 4).await?;
        }
        0x04 => {
            read_exact_async(stream, 16).await?;
        }
        0x03 => {
            let len = read_exact_async(stream, 1).await?[0] as usize;
            read_exact_async(stream, len).await?;
        }
        _ => return Err(AppError::new("SOCKS5 代理响应地址类型非法")),
    }
    read_exact_async(stream, 2).await?;
    Ok(())
}

async fn connect_socks_proxy(connection: &Connection) -> AppResult<tokio::net::TcpStream> {
    let proxy = parse_socks_proxy(
        connection
            .socks_proxy
            .as_deref()
            .ok_or_else(|| AppError::new("缺少 socksProxy 配置"))?,
    )?;
    let mut stream = tokio::net::TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
    authenticate_socks_proxy(&mut stream, &proxy).await?;
    let mut request = vec![0x05, 0x01, 0x00];
    request.extend_from_slice(&encode_target_address(&connection.host)?);
    request.extend_from_slice(&connection.port.to_be_bytes());
    stream.write_all(&request).await?;
    read_socks_connect_response(&mut stream).await?;
    Ok(stream)
}

struct RusshClient;

impl client::Handler for RusshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect_russh(
    configs: &[Connection],
    connection: &Connection,
) -> AppResult<client::Handle<RusshClient>> {
    let stream = open_connection_stream(configs, connection).await?;
    connect_russh_over_stream(connection, stream).await
}

async fn connect_russh_direct(connection: &Connection) -> AppResult<client::Handle<RusshClient>> {
    let stream: Box<dyn SshStream> = if connection.socks_proxy.is_some() {
        Box::new(connect_socks_proxy(connection).await?)
    } else {
        Box::new(tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?)
    };
    connect_russh_over_stream(connection, stream).await
}

async fn connect_russh_over_stream(
    connection: &Connection,
    stream: Box<dyn SshStream>,
) -> AppResult<client::Handle<RusshClient>> {
    let config = client::Config {
        // SSH 连接空闲超时：30s 过短，慢速大文件传输或长任务可能被误断，放宽到 5 分钟。
        inactivity_timeout: Some(Duration::from_secs(300)),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                russh::kex::CURVE25519,
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::DH_GEX_SHA256,
                russh::kex::DH_G14_SHA256,
                // 现代算法优先，旧 DH 算法仅作为兼容历史 OpenSSH 服务端的最后兜底。
                russh::kex::DH_G14_SHA1,
                russh::kex::DH_GEX_SHA1,
                russh::kex::DH_G1_SHA1,
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
            ]),
            mac: Cow::Owned(vec![
                russh::mac::HMAC_SHA512_ETM,
                russh::mac::HMAC_SHA256_ETM,
                russh::mac::HMAC_SHA512,
                russh::mac::HMAC_SHA256,
                // 旧 MAC 仅作为兼容历史 OpenSSH 服务端的最后兜底。
                russh::mac::HMAC_SHA1_ETM,
                russh::mac::HMAC_SHA1,
            ]),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut session = client::connect_stream(Arc::new(config), stream, RusshClient)
        .await
        .map_err(|error| {
            AppError::new(format!("连接 {} 建立 SSH 失败: {}", connection.name, error))
        })?;
    authenticate_russh(connection, &mut session).await?;
    Ok(session)
}

async fn open_connection_stream(
    configs: &[Connection],
    connection: &Connection,
) -> AppResult<Box<dyn SshStream>> {
    if let Some(jump_name) = connection.jump_host.as_deref() {
        let jump = find_connection(configs, jump_name)?;
        let jump_session = connect_russh_direct(jump).await?;
        let channel = jump_session
            .channel_open_direct_tcpip(
                connection.host.clone(),
                u32::from(connection.port),
                "127.0.0.1",
                0,
            )
            .await
            .map_err(|error| {
                AppError::new(format!(
                    "连接 {} 通过跳板机 {} 打开直连通道失败: {}",
                    connection.name, jump.name, error
                ))
            })?;
        return Ok(Box::new(channel.into_stream()));
    }
    if connection.socks_proxy.is_some() {
        return Ok(Box::new(connect_socks_proxy(connection).await?));
    }
    Ok(Box::new(
        tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?,
    ))
}

async fn authenticate_russh(
    connection: &Connection,
    session: &mut client::Handle<RusshClient>,
) -> AppResult<()> {
    if let Some(password) = connection.password.as_deref() {
        let auth = session
            .authenticate_password(connection.username.clone(), password.to_string())
            .await
            .map_err(|error| {
                AppError::new(format!("连接 {} 密码认证失败: {}", connection.name, error))
            })?;
        if !auth.success() {
            return Err(AppError::new(format!(
                "连接 {} 密码认证被拒绝",
                connection.name
            )));
        }
        return Ok(());
    }
    let private_key = connection
        .private_key
        .as_deref()
        .ok_or_else(|| AppError::new(format!("连接 {} 缺少认证配置", connection.name)))?;
    let key_pair =
        load_secret_key(private_key, connection.passphrase.as_deref()).map_err(|error| {
            AppError::new(format!(
                "连接 {} 加载私钥失败: {}，{}",
                connection.name, private_key, error
            ))
        })?;
    let hash_alg = session
        .best_supported_rsa_hash()
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 协商 RSA hash 失败: {}",
                connection.name, error
            ))
        })?
        .flatten();
    let auth = session
        .authenticate_publickey(
            connection.username.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg),
        )
        .await
        .map_err(|error| {
            AppError::new(format!("连接 {} 公钥认证失败: {}", connection.name, error))
        })?;
    if !auth.success() {
        return Err(AppError::new(format!(
            "连接 {} 公钥认证被拒绝",
            connection.name
        )));
    }
    Ok(())
}

// 远端命令执行结果：命令正常完成（无论退出码）时的结构化输出；
// 会话异常/连接失败仍以 Err 返回。
struct ExecOutput {
    exit_code: u32,
    stdout: String,
    stderr: String,
}

async fn execute_remote_command_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_command: &str,
    pty: bool,
) -> AppResult<ExecOutput> {
    let mut channel = session.channel_open_session().await.map_err(|error| {
        AppError::new(format!("连接 {} 打开会话失败: {}", connection.name, error))
    })?;
    if pty {
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .map_err(|error| {
                AppError::new(format!(
                    "连接 {} 分配伪终端失败: {}",
                    connection.name, error
                ))
            })?;
    }
    channel.exec(true, remote_command).await.map_err(|error| {
        AppError::new(format!("连接 {} 执行命令失败: {}", connection.name, error))
    })?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    // 收到 ExitStatus 后，若远端仍有后台进程持有通道 stdout，SSH 服务端不会发送 EOF，
    // 通道永不关闭。此时最多再等 EOF 一小段时间，超时即视为命令已结束，
    // 避免被后台进程拖挂到总超时。
    const EXIT_STATUS_EOF_TIMEOUT_MS: u64 = 2000;
    let mut after_exit_status = false;
    loop {
        let wait_result = if after_exit_status {
            tokio::time::timeout(
                Duration::from_millis(EXIT_STATUS_EOF_TIMEOUT_MS),
                channel.wait(),
            )
            .await
        } else {
            Ok(channel.wait().await)
        };
        match wait_result {
            Ok(Some(ChannelMsg::Data { data })) => stdout.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExtendedData { data, .. })) => stderr.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExitStatus { exit_status: code })) => {
                exit_status = Some(code);
                after_exit_status = true;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let stdout = String::from_utf8_lossy(&stdout).trim_end().to_string();
    let stderr = String::from_utf8_lossy(&stderr).trim_end().to_string();
    let code = match exit_status {
        Some(code) => code,
        None => {
            // 通道关闭但未收到退出状态：远端会话被异常终止
            // （例如 pkill -f 匹配到执行命令的 shell 自身），
            // 此时 stdout 不完整，不能静默当作成功返回。
            let mut parts = Vec::new();
            if !stdout.is_empty() {
                parts.push(stdout);
            }
            if !stderr.is_empty() {
                parts.push(format!("[stderr]\n{}", stderr));
            }
            parts.push("[remote] 会话异常终止（无退出状态）".to_string());
            return Err(AppError::new(parts.join("\n")));
        }
    };
    // 非零退出码不视为 Err：命令已正常完成，由调用方决定如何呈现（文本模式报错、JSON 模式如实返回）。
    Ok(ExecOutput {
        exit_code: code,
        stdout,
        stderr,
    })
}

async fn execute_remote_command_async(
    configs: &[Connection],
    connection: &Connection,
    remote_command: &str,
    pty: bool,
) -> AppResult<ExecOutput> {
    let session = connect_russh(configs, connection).await?;
    let result =
        execute_remote_command_with_session_async(&session, connection, remote_command, pty).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

fn execute_remote_command(
    configs: &[Connection],
    connection: &Connection,
    remote_command: &str,
    timeout_ms: u64,
    pty: bool,
) -> AppResult<ExecOutput> {
    run_with_timeout(
        timeout_ms,
        execute_remote_command_async(configs, connection, remote_command, pty),
    )
}

async fn open_sftp_session(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
) -> AppResult<SftpSession> {
    let channel = session.channel_open_session().await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 打开 SFTP 会话失败: {}",
            connection.name, error
        ))
    })?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 请求 SFTP 子系统失败: {}",
                connection.name, error
            ))
        })?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 初始化 SFTP 失败: {}",
                connection.name, error
            ))
        })
}

fn temporary_remote_path(remote_path: &str) -> String {
    format!("{}.part", remote_path)
}

fn temporary_remote_meta_path(remote_path: &str) -> String {
    format!("{}.part.meta", remote_path)
}

fn build_upload_resume_meta(metadata: &std::fs::Metadata) -> UploadResumeMeta {
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    UploadResumeMeta {
        file_size: metadata.len(),
        modified_ms,
        chunk_bytes: TRANSFER_CHUNK_BYTES,
    }
}

async fn upload_file_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
) -> AppResult<()> {
    let local_metadata = fs::metadata(local_path)?;
    let resume_meta = build_upload_resume_meta(&local_metadata);
    let file_size = resume_meta.file_size;
    let temp_remote_path = temporary_remote_path(remote_path);
    let temp_remote_meta_path = temporary_remote_meta_path(remote_path);
    let mut last_error: Option<AppError> = None;

    // SFTP 传输不再设置总超时：大文件允许长时间运行，失败时按整次上传重试。
    for attempt in 1..=TRANSFER_MAX_RETRIES {
        let sftp = open_sftp_session(session, connection).await?;
        let upload_result = upload_file_once(
            &sftp,
            connection,
            local_path,
            remote_path,
            &temp_remote_path,
            &temp_remote_meta_path,
            &resume_meta,
            file_size,
            attempt,
        )
        .await;
        let _ = sftp.close().await;

        match upload_result {
            Ok(()) => return Ok(()),
            Err(error) if attempt < TRANSFER_MAX_RETRIES => {
                eprintln!(
                    "上传失败，准备重试 {}/{}: {}",
                    attempt + 1,
                    TRANSFER_MAX_RETRIES,
                    error
                );
                last_error = Some(error);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(AppError::new(format!(
        "上传失败，已重试 {} 次: {}",
        TRANSFER_MAX_RETRIES,
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "未知错误".to_string())
    )))
}

async fn upload_file_once(
    sftp: &SftpSession,
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
    temp_remote_path: &str,
    temp_remote_meta_path: &str,
    resume_meta: &UploadResumeMeta,
    file_size: u64,
    attempt: usize,
) -> AppResult<()> {
    ensure_upload_resume_meta(sftp, temp_remote_path, temp_remote_meta_path, resume_meta).await?;
    let resume_offset = resolve_upload_resume_offset(sftp, temp_remote_path, file_size).await?;
    let mut local_file = tokio::fs::File::open(local_path).await?;
    if resume_offset > 0 {
        local_file.seek(SeekFrom::Start(resume_offset)).await?;
        eprintln!(
            "发现远端临时文件，断点续传: {}/{} bytes",
            resume_offset, file_size
        );
    }

    let open_flags = if resume_offset > 0 {
        OpenFlags::CREATE | OpenFlags::APPEND | OpenFlags::WRITE
    } else {
        OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
    };
    let mut remote_file = sftp
        .open_with_flags(temp_remote_path.to_string(), open_flags)
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 打开远端临时文件失败: {}",
                connection.name, error
            ))
        })?;

    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    let mut uploaded = resume_offset;
    // 起点输出（0% 或续传点）；空文件场景也在这里显示 100%。
    print_upload_progress(uploaded, file_size, attempt)?;
    let mut last_percent = u64::MAX;
    loop {
        let read_bytes = local_file.read(&mut buffer).await?;
        if read_bytes == 0 {
            break;
        }
        remote_file.write_all(&buffer[..read_bytes]).await?;
        remote_file.flush().await?;
        uploaded += read_bytes as u64;
        // 仅在百分比变化时输出，避免大文件逐 chunk 刷屏。
        let percent = if file_size == 0 {
            100
        } else {
            uploaded.saturating_mul(100) / file_size
        };
        if percent != last_percent {
            last_percent = percent;
            print_upload_progress(uploaded, file_size, attempt)?;
        }
    }

    remote_file.shutdown().await?;
    verify_remote_temp_size(sftp, temp_remote_path, file_size).await?;
    // 尽量先删除目标文件，兼容不支持覆盖 rename 的 SFTP 服务端。
    let _ = sftp.remove_file(remote_path.to_string()).await;
    sftp.rename(temp_remote_path.to_string(), remote_path.to_string())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 替换远端文件失败: {}",
                connection.name, error
            ))
        })?;
    let _ = sftp.remove_file(temp_remote_meta_path.to_string()).await;
    eprintln!("上传完成: {} bytes", file_size);
    Ok(())
}

async fn ensure_upload_resume_meta(
    sftp: &SftpSession,
    temp_remote_path: &str,
    temp_remote_meta_path: &str,
    resume_meta: &UploadResumeMeta,
) -> AppResult<()> {
    let expected = serde_json::to_vec(resume_meta)?;
    let current = match sftp.read(temp_remote_meta_path.to_string()).await {
        Ok(bytes) => Some(bytes),
        Err(_) => None,
    };
    if current.as_deref() == Some(expected.as_slice()) {
        return Ok(());
    }

    // 本地文件特征变化时，旧 .part 不能安全续传，必须删除后重建元数据。
    let _ = sftp.remove_file(temp_remote_path.to_string()).await;
    let _ = sftp.remove_file(temp_remote_meta_path.to_string()).await;
    let mut meta_file = sftp
        .open_with_flags(
            temp_remote_meta_path.to_string(),
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .map_err(|error| AppError::new(format!("创建远端续传元数据失败: {}", error)))?;
    meta_file
        .write_all(&expected)
        .await
        .map_err(|error| AppError::new(format!("写入远端续传元数据失败: {}", error)))?;
    meta_file
        .shutdown()
        .await
        .map_err(|error| AppError::new(format!("关闭远端续传元数据失败: {}", error)))?;
    Ok(())
}

async fn resolve_upload_resume_offset(
    sftp: &SftpSession,
    temp_remote_path: &str,
    file_size: u64,
) -> AppResult<u64> {
    let metadata = match sftp.metadata(temp_remote_path.to_string()).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(0),
    };
    let remote_size = metadata.size.unwrap_or(0);
    if remote_size == file_size {
        return Ok(remote_size);
    }
    if remote_size < file_size {
        return Ok(remote_size);
    }
    // 远端临时文件比本地还大，说明它不属于当前上传内容，删除后重传。
    let _ = sftp.remove_file(temp_remote_path.to_string()).await;
    Ok(0)
}

async fn verify_remote_temp_size(
    sftp: &SftpSession,
    temp_remote_path: &str,
    expected_size: u64,
) -> AppResult<()> {
    let metadata = sftp
        .metadata(temp_remote_path.to_string())
        .await
        .map_err(|error| AppError::new(format!("读取远端临时文件大小失败: {}", error)))?;
    let actual_size = metadata.size.unwrap_or(0);
    if actual_size != expected_size {
        return Err(AppError::new(format!(
            "远端临时文件大小不一致: 期望 {} bytes，实际 {} bytes",
            expected_size, actual_size
        )));
    }
    Ok(())
}

fn print_upload_progress(uploaded: u64, total: u64, attempt: usize) -> AppResult<()> {
    if total == 0 {
        eprintln!("上传进度: 100% (0/0 bytes, 第 {} 次)", attempt);
        return Ok(());
    }
    let percent = uploaded.saturating_mul(100) / total;
    eprintln!(
        "上传进度: {}% ({}/{} bytes, 第 {} 次)",
        percent, uploaded, total, attempt
    );
    Ok(())
}

fn print_download_progress(downloaded: u64, total: u64) -> AppResult<()> {
    if total == 0 {
        eprintln!("下载进度: 100% (0/0 bytes)");
        return Ok(());
    }
    let percent = downloaded.saturating_mul(100) / total;
    eprintln!("下载进度: {}% ({}/{} bytes)", percent, downloaded, total);
    Ok(())
}

fn temporary_local_part_path(local_path: &Path) -> PathBuf {
    let mut name = local_path.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

fn temporary_local_meta_path(local_path: &Path) -> PathBuf {
    let mut name = local_path.as_os_str().to_owned();
    name.push(".part.meta");
    PathBuf::from(name)
}

// 本地 .part 续传判定：meta 内容与远端文件特征一致才续传，否则删除 .part 重新下载。
fn resolve_download_resume_offset(
    part_path: &Path,
    meta_path: &Path,
    resume_meta: &UploadResumeMeta,
) -> AppResult<Option<u64>> {
    let expected = serde_json::to_vec(resume_meta)?;
    let current = match fs::read(meta_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if current != expected {
        let _ = fs::remove_file(part_path);
        let _ = fs::remove_file(meta_path);
        return Ok(None);
    }
    let part_size = match fs::metadata(part_path) {
        Ok(metadata) => metadata.len(),
        Err(_) => return Ok(None),
    };
    if part_size > resume_meta.file_size {
        let _ = fs::remove_file(part_path);
        let _ = fs::remove_file(meta_path);
        return Ok(None);
    }
    Ok(Some(part_size))
}

async fn download_file_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
) -> AppResult<()> {
    let sftp = open_sftp_session(session, connection).await?;
    let remote_metadata = sftp
        .metadata(remote_path.to_string())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 读取远端文件信息失败: {}",
                connection.name, error
            ))
        })?;
    let remote_size = remote_metadata.len();
    let modified_ms = remote_metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    // 复用 UploadResumeMeta 结构：字段与下载续传元数据一致。
    let resume_meta = UploadResumeMeta {
        file_size: remote_size,
        modified_ms,
        chunk_bytes: TRANSFER_CHUNK_BYTES,
    };
    let part_path = temporary_local_part_path(local_path);
    let meta_path = temporary_local_meta_path(local_path);
    let resume_offset =
        resolve_download_resume_offset(&part_path, &meta_path, &resume_meta)?.unwrap_or(0);
    let mut remote_file = sftp.open(remote_path.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 打开远端文件失败: {}",
            connection.name, error
        ))
    })?;
    let mut local_file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&part_path)
        .await?;
    if resume_offset > 0 {
        local_file.seek(SeekFrom::Start(resume_offset)).await?;
        remote_file.seek(SeekFrom::Start(resume_offset)).await?;
        eprintln!(
            "发现本地临时文件，断点续传: {}/{} bytes",
            resume_offset, remote_size
        );
    } else {
        local_file.set_len(0).await?;
    }
    // 下载前写入元数据，中断后下次可据此判定续传。
    fs::write(&meta_path, serde_json::to_vec(&resume_meta)?)?;
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    let mut downloaded = resume_offset;
    print_download_progress(downloaded, remote_size)?;
    let mut last_percent = u64::MAX;
    loop {
        let read_bytes = remote_file.read(&mut buffer).await?;
        if read_bytes == 0 {
            break;
        }
        local_file.write_all(&buffer[..read_bytes]).await?;
        downloaded += read_bytes as u64;
        let percent = if remote_size == 0 {
            100
        } else {
            downloaded.saturating_mul(100) / remote_size
        };
        if percent != last_percent {
            last_percent = percent;
            print_download_progress(downloaded, remote_size)?;
        }
    }
    local_file.shutdown().await?;
    let _ = sftp.close().await;
    if downloaded != remote_size {
        return Err(AppError::new(format!(
            "下载大小不一致: 期望 {} bytes，实际 {} bytes",
            remote_size, downloaded
        )));
    }
    tokio::fs::rename(&part_path, local_path).await?;
    let _ = fs::remove_file(&meta_path);
    Ok(())
}

async fn upload_file_async(
    configs: &[Connection],
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result =
        upload_file_with_session_async(&session, connection, local_path, remote_path).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

async fn download_file_async(
    configs: &[Connection],
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result =
        download_file_with_session_async(&session, connection, remote_path, local_path).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

fn upload_file(
    configs: &[Connection],
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
    match timeout_ms {
        Some(timeout_ms) => block_with_timeout(
            &runtime,
            timeout_ms,
            upload_file_async(configs, connection, local_path, remote_path),
        ),
        None => runtime.block_on(upload_file_async(
            configs,
            connection,
            local_path,
            remote_path,
        )),
    }
}

fn download_file(
    configs: &[Connection],
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    match timeout_ms {
        Some(timeout_ms) => run_with_timeout(
            timeout_ms,
            download_file_async(configs, connection, remote_path, local_path),
        ),
        None => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
            runtime.block_on(download_file_async(
                configs,
                connection,
                remote_path,
                local_path,
            ))
        }
    }
}

// 远端目录逐级创建，已存在的层级忽略错误。
async fn ensure_remote_dir_all(sftp: &SftpSession, remote_dir: &str) -> AppResult<()> {
    let mut current = String::new();
    if remote_dir.starts_with('/') {
        current.push('/');
    }
    for part in remote_dir.split('/').filter(|part| !part.is_empty()) {
        if !current.is_empty() && !current.ends_with('/') {
            current.push('/');
        }
        current.push_str(part);
        let _ = sftp.create_dir(current.clone()).await;
    }
    Ok(())
}

async fn upload_dir_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    local_dir: &Path,
    remote_dir: &str,
) -> AppResult<()> {
    // daemon 模式也做目录检查（no-cache 侧在 upload_dir 已检查），保证两模式报错一致。
    if !local_dir.is_dir() {
        return Err(AppError::new(format!(
            "--recursive 上传需要本地目录路径，当前为: {}",
            local_dir.display()
        )));
    }
    let sftp = open_sftp_session(session, connection).await?;
    ensure_remote_dir_all(&sftp, remote_dir).await?;
    let _ = sftp.close().await;
    let entries = fs::read_dir(local_dir)?;
    for entry in entries {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|item| item.to_str())
            .ok_or_else(|| AppError::new("本地路径包含非 UTF-8 文件名"))?
            .to_string();
        let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), name);
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_dir() {
            Box::pin(upload_dir_with_session_async(
                session,
                connection,
                &path,
                &remote_child,
            ))
            .await?;
        } else if file_type.is_symlink() {
            // 符号链接不递归跟随（防目录循环）：指向目录的链接跳过，指向文件的链接上传其内容。
            let target_is_dir = fs::metadata(&path)
                .map(|meta| meta.is_dir())
                .unwrap_or(true);
            if target_is_dir {
                continue;
            }
            upload_file_with_session_async(session, connection, &path, &remote_child).await?;
        } else {
            upload_file_with_session_async(session, connection, &path, &remote_child).await?;
        }
    }
    Ok(())
}

async fn download_dir_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_dir: &str,
    local_dir: &Path,
) -> AppResult<()> {
    fs::create_dir_all(local_dir)?;
    let sftp = open_sftp_session(session, connection).await?;
    let remote_meta = sftp.metadata(remote_dir.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 读取远端目录信息失败: {}",
            connection.name, error
        ))
    })?;
    if !remote_meta.is_dir() {
        let _ = sftp.close().await;
        return Err(AppError::new(format!(
            "--recursive 下载需要远端目录路径: {}",
            remote_dir
        )));
    }
    let entries = sftp.read_dir(remote_dir.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 读取远端目录失败: {}",
            connection.name, error
        ))
    })?;
    let _ = sftp.close().await;
    for entry in entries {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), name);
        let local_child = local_dir.join(&name);
        if entry.file_type().is_dir() {
            Box::pin(download_dir_with_session_async(
                session,
                connection,
                &remote_child,
                &local_child,
            ))
            .await?;
        } else if entry.file_type().is_file() {
            download_file_with_session_async(session, connection, &remote_child, &local_child).await?;
        }
    }
    Ok(())
}

async fn upload_dir_async(
    configs: &[Connection],
    connection: &Connection,
    local_dir: &Path,
    remote_dir: &str,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result = upload_dir_with_session_async(&session, connection, local_dir, remote_dir).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

async fn download_dir_async(
    configs: &[Connection],
    connection: &Connection,
    remote_dir: &str,
    local_dir: &Path,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result = download_dir_with_session_async(&session, connection, remote_dir, local_dir).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

fn upload_dir(
    configs: &[Connection],
    connection: &Connection,
    local_dir: &Path,
    remote_dir: &str,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    if !local_dir.is_dir() {
        return Err(AppError::new(format!(
            "--recursive 上传需要本地目录路径，当前为: {}",
            local_dir.display()
        )));
    }
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
    match timeout_ms {
        Some(timeout_ms) => block_with_timeout(
            &runtime,
            timeout_ms,
            upload_dir_async(configs, connection, local_dir, remote_dir),
        ),
        None => runtime.block_on(upload_dir_async(
            configs,
            connection,
            local_dir,
            remote_dir,
        )),
    }
}

fn download_dir(
    configs: &[Connection],
    connection: &Connection,
    remote_dir: &str,
    local_dir: &Path,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    match timeout_ms {
        Some(timeout_ms) => run_with_timeout(
            timeout_ms,
            download_dir_async(configs, connection, remote_dir, local_dir),
        ),
        None => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
            runtime.block_on(download_dir_async(
                configs,
                connection,
                remote_dir,
                local_dir,
            ))
        }
    }
}

fn run_with_timeout<T, F>(timeout_ms: u64, future: F) -> AppResult<T>
where
    F: std::future::Future<Output = AppResult<T>>,
{
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
    block_with_timeout(&runtime, timeout_ms, future)
}

fn block_with_timeout<T, F>(
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

fn resolve_pty(connection: &Connection, override_pty: Option<bool>) -> bool {
    override_pty.or(connection.pty).unwrap_or(false)
}

fn resolve_execute_command(_configs: &[Connection], parsed: &ExecuteArgs) -> AppResult<String> {
    let Some(command_file) = parsed.command_file.as_ref() else {
        return Ok(parsed.command.clone());
    };
    let path = path_absolute_from(Path::new(command_file), &env::current_dir()?)?;
    // 命令文件只做路径解析，不套用上传/下载的本地路径白名单。
    // 命令文件按 UTF-8 读取，避免二进制内容或错误编码被误当作远端 shell 命令执行。
    fs::read_to_string(&path).map_err(|error| {
        AppError::new(format!(
            "读取 command-file 失败: {}，{}",
            path.display(),
            error
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, content).unwrap();
        (dir, path)
    }

    #[test]
    fn load_config_validates_duplicate_names() {
        let (_dir, path) = write_config(
            r#"[
              {"name":"a","host":"127.0.0.1","username":"root","password":"p"},
              {"name":"a","host":"127.0.0.2","username":"root","password":"p"}
            ]"#,
        );
        let err = load_config(&path).unwrap_err();
        assert!(err.to_string().contains("重复的连接名"));
    }

    #[test]
    fn command_blacklist_blocks_matching_command() {
        let connection = normalize_entry(
            serde_json::from_str(
                r#"{"name":"a","host":"127.0.0.1","username":"root","password":"p","commandBlacklist":["(^|[;&|()\\s])rm(\\s|$)"]}"#,
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert!(validate_command(&connection, "rm -rf /tmp/a").is_err());
        assert!(validate_command(&connection, "pwd").is_ok());
    }

    #[test]
    fn parse_exec_allows_cache_mode() {
        let parsed = parse_execute_args(vec!["server".into(), "pwd".into()]).unwrap();
        assert!(!parsed.global.no_cache);
        assert_eq!(parsed.connection_name, "server");
        assert_eq!(parsed.command, "pwd");
    }

    #[test]
    fn parse_exec_supports_named_arguments() {
        let parsed = parse_execute_args(vec![
            "--no-cache".into(),
            "--pty".into(),
            "--connection".into(),
            "server".into(),
            "--command".into(),
            "pwd".into(),
            "--timeout".into(),
            "1000".into(),
        ])
        .unwrap();
        assert_eq!(parsed.connection_name, "server");
        assert_eq!(parsed.command, "pwd");
        assert_eq!(parsed.timeout_ms, 1000);
        assert_eq!(parsed.pty, Some(true));
    }

    #[test]
    fn parse_exec_supports_json_flag() {
        let parsed = parse_execute_args(vec![
            "--json".into(),
            "server".into(),
            "pwd".into(),
        ])
        .unwrap();
        assert!(parsed.json_output);
    }

    #[test]
    fn parse_global_flags_any_order_before_positional() {
        // 全局参数（--no-cache）与子命令参数（--json）可在连接名前任意顺序混排。
        let parsed = parse_execute_args(vec![
            "--json".into(),
            "--no-cache".into(),
            "server".into(),
            "pwd".into(),
        ])
        .unwrap();
        assert!(parsed.json_output);
        assert!(parsed.global.no_cache);
        assert_eq!(parsed.connection_name, "server");
        assert_eq!(parsed.command, "pwd");
    }

    #[test]
    fn parse_global_flag_after_positional_rejected() {
        // 位置参数之后的全局 flag 不被吞掉，明确报错（避免误吞命令内容）。
        let err = parse_execute_args(vec![
            "server".into(),
            "pwd".into(),
            "--no-cache".into(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("不支持的参数: --no-cache"));
    }

    #[test]
    fn parse_exec_does_not_swallow_flag_inside_quoted_command() {
        // 命令内容整体作为一个 token 时（引号包裹），其中的 --json 不被解析为参数。
        let parsed = parse_execute_args(vec!["server".into(), "echo --json".into()]).unwrap();
        assert!(!parsed.json_output);
        assert_eq!(parsed.command, "echo --json");
    }

    #[test]
    fn parse_exec_rejects_flag_after_positional() {
        // 位置参数（连接名/命令）之后的 flag 不再被静默吞掉，而是明确报错。
        let err = parse_execute_args(vec![
            "server".into(),
            "pwd".into(),
            "--json".into(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("不支持的参数: --json"));
    }

    #[test]
    fn parse_transfer_rejects_flag_after_positional() {
        let err = parse_transfer_args(
            vec![
                "server".into(),
                "/tmp/a".into(),
                "/tmp/b".into(),
                "--json".into(),
            ],
            "upload",
        )
        .unwrap_err();
        assert!(err.to_string().contains("不支持的参数: --json"));
    }

    #[test]
    fn parse_transfer_supports_recursive_flag() {
        let parsed = parse_transfer_args(
            vec![
                "--recursive".into(),
                "server".into(),
                "/tmp/a".into(),
                "/tmp/b".into(),
            ],
            "upload",
        )
        .unwrap();
        assert!(parsed.recursive);
    }

    #[test]
    fn parse_transfer_supports_json_flag() {
        let parsed = parse_transfer_args(
            vec![
                "--json".into(),
                "server".into(),
                "/tmp/a".into(),
                "/tmp/b".into(),
            ],
            "upload",
        )
        .unwrap();
        assert!(parsed.json_output);
    }

    #[test]
    fn parse_exec_rejects_conflicting_pty_flags() {
        let err = parse_execute_args(vec![
            "--pty".into(),
            "--no-pty".into(),
            "server".into(),
            "pwd".into(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("--pty 和 --no-pty"));
    }

    #[test]
    fn parse_download_positional_order_remote_then_local() {
        // download 位置参数语义为 <connectionName> <remotePath> <localPath>。
        let parsed = parse_transfer_args(
            vec![
                "server".into(),
                "/remote/file".into(),
                "/local/file".into(),
            ],
            "download",
        )
        .unwrap();
        assert_eq!(parsed.remote_path, "/remote/file");
        assert_eq!(parsed.local_path, "/local/file");
    }

    #[test]
    fn parse_transfer_mixed_named_and_positional() {
        // 命名参数占用 connection 后，位置参数顺延给 local/remote（原 resolve_value 语义）。
        let parsed = parse_transfer_args(
            vec![
                "--connection".into(),
                "server".into(),
                "/tmp/a".into(),
                "/tmp/b".into(),
            ],
            "upload",
        )
        .unwrap();
        assert_eq!(parsed.connection_name, "server");
        assert_eq!(parsed.local_path, "/tmp/a");
        assert_eq!(parsed.remote_path, "/tmp/b");
    }

    #[test]
    fn parse_transfer_defaults_timeout_to_none() {
        let parsed = parse_transfer_args(
            vec!["server".into(), "/tmp/a".into(), "/tmp/b".into()],
            "upload",
        )
        .unwrap();
        assert_eq!(parsed.connection_name, "server");
        assert_eq!(parsed.timeout_ms, None);
    }

    #[test]
    fn parse_transfer_supports_timeout_option() {
        let parsed = parse_transfer_args(
            vec![
                "--timeout".into(),
                "120000".into(),
                "--connection".into(),
                "server".into(),
                "--local".into(),
                "/tmp/a".into(),
                "--remote".into(),
                "/tmp/b".into(),
            ],
            "download",
        )
        .unwrap();
        assert_eq!(parsed.timeout_ms, Some(120000));
    }

    #[test]
    fn parse_transfer_rejects_zero_timeout() {
        let err = parse_transfer_args(
            vec![
                "--timeout".into(),
                "0".into(),
                "server".into(),
                "/tmp/a".into(),
                "/tmp/b".into(),
            ],
            "upload",
        )
        .unwrap_err();
        assert!(err.to_string().contains("timeout 必须是正整数毫秒值"));
    }

    #[test]
    fn load_config_rejects_agent_auth() {
        let (_dir, path) = write_config(
            r#"[
              {"name":"a","host":"127.0.0.1","username":"root","agent":"/tmp/agent.sock"}
            ]"#,
        );
        let err = load_config(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("password、passwordRef 或 privateKey"));
    }

    #[test]
    fn passive_password_migration_hides_plain_password() {
        let (_dir, path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","username":"root","password":"secret"}]"#,
        );
        assert!(migrate_plain_password_for_connection(&path, "server").unwrap());
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret"));
        assert!(raw.contains(r#""password": """#));
        assert!(raw.contains(r#""passwordRef": "agentsshcli:server""#));
        let configs = load_config_for_connection(&path, "server").unwrap();
        let connection = find_connection(&configs, "server").unwrap();
        assert_eq!(connection.password.as_deref(), Some("secret"));
    }

    #[test]
    fn load_config_for_connection_ignores_unrelated_missing_password_ref() {
        let (_dir, path) = write_config(
            r#"[
              {"name":"key-server","host":"127.0.0.1","username":"root","privateKey":"/tmp/id_rsa"},
              {"name":"bad-password-server","host":"127.0.0.2","username":"root","password":"","passwordRef":"agentsshcli:missing"}
            ]"#,
        );
        let configs = load_config_for_connection(&path, "key-server").unwrap();
        let connection = find_connection(&configs, "key-server").unwrap();
        assert_eq!(connection.private_key.as_deref(), Some("/tmp/id_rsa"));
    }

    #[test]
    fn load_config_for_connection_resolves_only_target_password_ref() {
        let (_dir, path) = write_config(
            r#"[
              {"name":"target","host":"127.0.0.1","username":"root","password":"secret"},
              {"name":"bad-password-server","host":"127.0.0.2","username":"root","password":"","passwordRef":"agentsshcli:missing"}
            ]"#,
        );
        assert!(migrate_plain_password_for_connection(&path, "target").unwrap());
        let configs = load_config_for_connection(&path, "target").unwrap();
        let connection = find_connection(&configs, "target").unwrap();
        assert_eq!(connection.password.as_deref(), Some("secret"));
    }

    #[test]
    fn passive_password_migration_skips_empty_password() {
        let (_dir, path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","username":"root","password":"","passwordRef":"agentsshcli:server"}]"#,
        );
        assert!(!migrate_plain_password_for_connection(&path, "server").unwrap());
    }

    #[test]
    fn config_snapshot_detects_metadata_and_hash_changes() {
        let (_dir, path) =
            write_config(r#"[{"name":"a","host":"127.0.0.1","username":"root","password":"p"}]"#);
        let snapshot = ConfigSnapshot::read(&path).unwrap();
        assert!(snapshot.metadata_matches(&path).unwrap());
        std::thread::sleep(Duration::from_millis(5));
        fs::write(
            &path,
            r#"[{"name":"b","host":"127.0.0.1","username":"root","password":"p"}]"#,
        )
        .unwrap();
        let changed = ConfigSnapshot::read(&path).unwrap();
        assert_ne!(snapshot.hash, changed.hash);
    }

    #[test]
    fn resolve_pty_prefers_cli_then_config_then_default_false() {
        let connection = normalize_entry(
            serde_json::from_str(
                r#"{"name":"a","host":"127.0.0.1","username":"root","password":"p","pty":true}"#,
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert!(resolve_pty(&connection, None));
        assert!(!resolve_pty(&connection, Some(false)));
        let default_connection = normalize_entry(
            serde_json::from_str(
                r#"{"name":"b","host":"127.0.0.1","username":"root","password":"p"}"#,
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert!(!resolve_pty(&default_connection, None));
    }

    #[test]
    fn parse_exec_supports_command_file() {
        let parsed = parse_execute_args(vec![
            "--connection".into(),
            "server".into(),
            "--command-file".into(),
            "script.sh".into(),
        ])
        .unwrap();
        assert_eq!(parsed.connection_name, "server");
        assert_eq!(parsed.command_file.as_deref(), Some("script.sh"));
        assert_eq!(parsed.command, "");
    }

    #[test]
    fn parse_exec_rejects_mixed_command_sources() {
        let err = parse_execute_args(vec![
            "--connection".into(),
            "server".into(),
            "--command".into(),
            "pwd".into(),
            "--command-file".into(),
            "script.sh".into(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("--command 和 --command-file"));
    }

    #[test]
    fn resolve_exec_reads_multiline_command_file() {
        let original_dir = env::current_dir().unwrap();
        let dir = tempdir().unwrap();
        let command_file = dir.path().join("script.sh");
        fs::write(&command_file, "echo start\necho end\n").unwrap();
        env::set_current_dir(dir.path()).unwrap();
        let connection = normalize_entry(
            serde_json::from_str(
                r#"{"name":"server","host":"127.0.0.1","username":"root","password":"p"}"#,
            )
            .unwrap(),
            0,
        )
        .unwrap();
        let parsed = parse_execute_args(vec![
            "--connection".into(),
            "server".into(),
            "--command-file".into(),
            "script.sh".into(),
        ])
        .unwrap();
        let command = resolve_execute_command(&[connection], &parsed).unwrap();
        env::set_current_dir(original_dir).unwrap();
        assert_eq!(command, "echo start\necho end\n");
    }

    #[test]
    fn socks_proxy_supports_host_port_without_scheme() {
        let proxy = parse_socks_proxy("127.0.0.1:1080").unwrap();
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
    }

    #[test]
    fn daemon_response_round_trips_exec_fields() {
        // exec 专用字段（exit_code/stderr）序列化往返一致，防协议回归。
        let response = DaemonResponse {
            ok: true,
            message: None,
            stdout: Some("out".to_string()),
            exit_code: Some(3),
            stderr: Some("err".to_string()),
            ..Default::default()
        };
        let mut bytes = Vec::new();
        write_daemon_response(&mut bytes, &response).unwrap();
        let parsed = read_daemon_response(&mut bytes.as_slice()).unwrap();
        assert_eq!(parsed.exit_code, Some(3));
        assert_eq!(parsed.stderr.as_deref(), Some("err"));
        assert_eq!(parsed.stdout.as_deref(), Some("out"));
    }

    #[test]
    fn daemon_response_frame_round_trips_large_stdout() {
        let response = DaemonResponse {
            ok: true,
            message: None,
            stdout: Some("A".repeat(200_000)),
            ..Default::default()
        };
        let mut bytes = Vec::new();
        write_daemon_response(&mut bytes, &response).unwrap();
        let parsed = read_daemon_response(&mut bytes.as_slice()).unwrap();
        assert_eq!(parsed.stdout.as_deref(), response.stdout.as_deref());
    }

    #[cfg(unix)]
    #[test]
    fn daemon_start_lock_serializes_concurrent_starters() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");
        let first_lock = DaemonStartLock::acquire(&socket_path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            let _second_lock = DaemonStartLock::acquire(&socket_path).unwrap();
            sender.send(()).unwrap();
        });

        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        drop(first_lock);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DaemonRequest {
    operation: String,
    config_path: PathBuf,
    cwd: PathBuf,
    connection_name: String,
    command: Option<String>,
    directory: Option<String>,
    timeout: Option<u64>,
    local_path: Option<String>,
    remote_path: Option<String>,
    cache_ttl_ms: Option<u64>,
    pty: Option<bool>,
    recursive: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DaemonResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout: Option<String>,
    // exec 专用：命令真实退出码与 stderr（成功路径也可能非零，如 exit 1 的命令）。
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
}

struct PoolEntry {
    session: client::Handle<RusshClient>,
    last_used_at: Instant,
    ttl_ms: u64,
}

struct DaemonState {
    runtime: tokio::runtime::Runtime,
    config_snapshot: ConfigSnapshot,
    configs: Vec<Connection>,
    connections: HashMap<String, PoolEntry>,
}

impl DaemonState {
    fn new(config_path: &Path) -> AppResult<Self> {
        Ok(Self {
            runtime: tokio::runtime::Runtime::new()
                .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?,
            config_snapshot: ConfigSnapshot::read(config_path)?,
            configs: load_config(config_path)?,
            connections: HashMap::new(),
        })
    }

    fn run_with_timeout<T, F>(&self, timeout_ms: u64, future: F) -> AppResult<T>
    where
        F: std::future::Future<Output = AppResult<T>>,
    {
        block_with_timeout(&self.runtime, timeout_ms, future)
    }
}

fn cache_ttl(global: &GlobalArgs) -> u64 {
    global.cache_ttl_ms.unwrap_or(DEFAULT_CACHE_TTL_MS)
}

fn request_stop_daemon(config_path: &Path) -> AppResult<()> {
    let config_path = path_absolute(config_path)?;
    let socket_path = get_socket_path(&config_path)?;
    let mut stream = connect_socket(&socket_path, DAEMON_REQUEST_TIMEOUT_MS)?;
    let request = serde_json::json!({
        "operation": "stop",
        "configPath": config_path,
        "cwd": env::current_dir()?,
        "connectionName": "__daemon__"
    });
    let line = format!("{}\n", serde_json::to_string(&request)?);
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    validate_daemon_response(read_daemon_response(&mut stream)?)?;
    Ok(())
}

fn request_daemon_execute(parsed: &ExecuteArgs, command: &str) -> AppResult<DaemonResponse> {
    let config_path = path_absolute(&parsed.global.config_path)?;
    let request = serde_json::json!({
        "operation": "execute",
        "configPath": config_path,
        "cwd": env::current_dir()?,
        "connectionName": parsed.connection_name,
        "command": command,
        "directory": parsed.directory,
        "timeout": parsed.timeout_ms,
        "cacheTtlMs": cache_ttl(&parsed.global),
        "pty": parsed.pty,
    });
    request_daemon(&config_path, &request)
}

fn request_daemon_transfer(parsed: &TransferArgs, operation: &str) -> AppResult<()> {
    let config_path = path_absolute(&parsed.global.config_path)?;
    let request = serde_json::json!({
        "operation": operation,
        "configPath": config_path,
        "cwd": env::current_dir()?,
        "connectionName": parsed.connection_name,
        "localPath": parsed.local_path,
        "remotePath": parsed.remote_path,
        "timeout": parsed.timeout_ms,
        "recursive": parsed.recursive,
        "cacheTtlMs": cache_ttl(&parsed.global),
    });
    request_daemon(&config_path, &request)?;
    Ok(())
}

fn request_daemon(config_path: &Path, request: &serde_json::Value) -> AppResult<DaemonResponse> {
    let socket_path = get_socket_path(config_path)?;
    ensure_daemon(&socket_path, config_path)?;
    let mut stream = connect_socket(&socket_path, DAEMON_REQUEST_TIMEOUT_MS)?;
    let line = format!("{}\n", serde_json::to_string(request)?);
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    let response = read_daemon_response(&mut stream);
    if matches_empty_daemon_response(&response) {
        ensure_daemon(&socket_path, config_path)?;
        let mut retry_stream = connect_socket(&socket_path, DAEMON_REQUEST_TIMEOUT_MS)?;
        retry_stream.write_all(line.as_bytes())?;
        retry_stream.flush()?;
        let retry_response = read_daemon_response(&mut retry_stream)?;
        return validate_daemon_response(retry_response);
    }
    validate_daemon_response(response?)
}

fn validate_daemon_response(response: DaemonResponse) -> AppResult<DaemonResponse> {
    if !response.ok {
        return Err(AppError::new(
            response
                .message
                .unwrap_or_else(|| "SSH 缓存进程执行失败".to_string()),
        ));
    }
    Ok(response)
}

fn matches_empty_daemon_response(response: &AppResult<DaemonResponse>) -> bool {
    matches!(response, Err(error) if error.to_string() == "SSH 缓存进程提前关闭连接")
}

struct DaemonStartLock {
    file: File,
}

impl DaemonStartLock {
    fn acquire(socket_path: &Path) -> AppResult<Self> {
        let lock_path = socket_path.with_extension("lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)?;
        lock_file_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for DaemonStartLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

fn daemon_is_healthy(socket_path: &Path) -> bool {
    let Ok(mut stream) = connect_socket(socket_path, 500) else {
        return false;
    };
    if stream.write_all(b"{\"operation\":\"ping\"}\n").is_err() {
        return false;
    }
    matches!(read_line_from_socket(&mut stream), Ok(line) if !line.is_empty())
}

fn ensure_daemon(socket_path: &Path, config_path: &Path) -> AppResult<()> {
    if daemon_is_healthy(socket_path) {
        return Ok(());
    }

    // daemon 冷启动必须跨进程串行化；持锁后再次探活，避免并发方重复拉起进程。
    let _start_lock = DaemonStartLock::acquire(socket_path)?;
    if daemon_is_healthy(socket_path) {
        return Ok(());
    }

    unlink_socket_path(socket_path)?;
    let log_path = daemon_log_path(config_path)?;
    spawn_daemon(socket_path, config_path, &log_path)?;
    wait_for_daemon(socket_path, &log_path)
}

fn spawn_daemon(socket_path: &Path, config_path: &Path, log_path: &Path) -> AppResult<()> {
    let exe = env::current_exe()?;
    let _ = fs::remove_file(log_path);
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|error| {
            AppError::new(format!(
                "打开 SSH 缓存进程日志失败: {}，{}",
                log_path.display(),
                error
            ))
        })?;
    let mut command = Command::new(exe);
    command
        .arg("__daemon")
        .arg("--socket")
        .arg(socket_path)
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .current_dir(project_root()?);
    command.spawn()?;
    Ok(())
}

fn wait_for_daemon(socket_path: &Path, log_path: &Path) -> AppResult<()> {
    let start = Instant::now();
    let mut last_error = None;
    while start.elapsed() < Duration::from_millis(DAEMON_START_TIMEOUT_MS) {
        match connect_socket(socket_path, 500).and_then(|mut stream| {
            stream.write_all(b"{\"operation\":\"ping\"}\n")?;
            stream.flush()?;
            let line = read_line_from_socket(&mut stream)?;
            if line.is_empty() {
                Err(AppError::new("SSH 缓存进程提前关闭连接"))
            } else {
                Ok(())
            }
        }) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error.to_string());
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let mut message = format!(
        "启动 SSH 缓存进程失败: {}，日志: {}",
        last_error.unwrap_or_else(|| "未知错误".to_string()),
        log_path.display()
    );
    if let Some(stderr) = read_daemon_log_tail(log_path) {
        message.push_str(&format!("，stderr: {}", stderr));
    }
    Err(AppError::new(message))
}

fn get_daemon_dir() -> AppResult<PathBuf> {
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() }.to_string();
    #[cfg(not(unix))]
    let uid = "nouid".to_string();
    let dir = env::temp_dir().join(format!("agent-ssh-cli-{}", uid));
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn daemon_log_path(config_path: &Path) -> AppResult<PathBuf> {
    let resolved = path_absolute(config_path)?;
    let parent = resolved
        .parent()
        .ok_or_else(|| AppError::new("配置文件路径缺少父目录，无法创建 SSH 缓存进程日志"))?;
    let mut hasher = Sha256::new();
    hasher.update(resolved.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    Ok(parent.join(format!("agentsshcli-daemon-{}.log", &digest[..12])))
}

fn read_daemon_log_tail(log_path: &Path) -> Option<String> {
    let raw = fs::read_to_string(log_path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    const MAX_LOG_CHARS: usize = 1200;
    let tail: String = trimmed
        .chars()
        .rev()
        .take(MAX_LOG_CHARS)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    Some(tail)
}

fn get_socket_path(config_path: &Path) -> AppResult<PathBuf> {
    let resolved = path_absolute(config_path)?;
    let mut hasher = Sha256::new();
    hasher.update(resolved.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    #[cfg(windows)]
    {
        let user_key = env::var("USERPROFILE")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| {
                home_dir()
                    .unwrap_or_else(|| PathBuf::from("nouser"))
                    .display()
                    .to_string()
            });
        let mut user_hasher = Sha256::new();
        user_hasher.update(user_key.as_bytes());
        let user_digest = format!("{:x}", user_hasher.finalize());
        return Ok(PathBuf::from(format!(
            "agent-ssh-cli-{}-{}",
            &user_digest[..12],
            &digest[..24]
        )));
    }
    #[cfg(unix)]
    {
        Ok(get_daemon_dir()?.join(format!("{}.sock", &digest[..24])))
    }
}

fn unlink_socket_path(socket_path: &Path) -> AppResult<()> {
    #[cfg(windows)]
    {
        let _ = socket_path;
        return Ok(());
    }
    #[cfg(unix)]
    match fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn connect_socket(socket_path: &Path, timeout_ms: u64) -> AppResult<UnixStream> {
    let stream = UnixStream::connect(socket_path)?;
    let timeout = Some(Duration::from_millis(timeout_ms));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    Ok(stream)
}

#[cfg(windows)]
fn connect_socket(socket_path: &Path, _timeout_ms: u64) -> AppResult<LocalSocketStream> {
    let pipe_name = windows_pipe_name_from_path(socket_path);
    let name = pipe_name
        .as_str()
        .to_ns_name::<GenericNamespaced>()
        .map_err(|error| AppError::new(format!("Windows named pipe 名称非法: {}", error)))?;
    LocalSocketStream::connect(name).map_err(|error| AppError::new(error.to_string()))
}

#[cfg(windows)]
fn windows_pipe_name_from_path(socket_path: &Path) -> String {
    socket_path
        .to_string_lossy()
        .replace('\\', "-")
        .replace(':', "")
        .replace('/', "-")
}

fn read_line_from_socket<S: Read>(stream: &mut S) -> AppResult<String> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    loop {
        let count = stream.read(&mut one)?;
        if count == 0 {
            break;
        }
        if one[0] == b'\n' {
            break;
        }
        bytes.push(one[0]);
    }
    String::from_utf8(bytes)
        .map_err(|error| AppError::new(format!("SSH 缓存进程响应非法: {}", error)))
}

fn read_daemon_response<S: Read>(stream: &mut S) -> AppResult<DaemonResponse> {
    let mut header = [0_u8; DAEMON_RESPONSE_LENGTH_BYTES];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(AppError::new("SSH 缓存进程提前关闭连接"));
        }
        Err(error) => return Err(error.into()),
    }
    let length_text = std::str::from_utf8(&header)
        .map_err(|error| AppError::new(format!("SSH 缓存进程响应长度非法: {}", error)))?;
    let length = usize::from_str_radix(length_text, 16)
        .map_err(|error| AppError::new(format!("SSH 缓存进程响应长度非法: {}", error)))?;
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| AppError::new(format!("SSH 缓存进程响应未读完整: {}", error)))?;
    serde_json::from_slice(&body)
        .map_err(|error| AppError::new(format!("SSH 缓存进程响应非法: {}", error)))
}

fn write_daemon_response<S: Write>(stream: &mut S, response: &DaemonResponse) -> AppResult<()> {
    let body = serde_json::to_vec(response)?;
    if body.len() > u32::MAX as usize {
        return Err(AppError::new("SSH 缓存进程响应过大"));
    }
    // 响应使用固定 8 字节十六进制长度前缀，客户端按长度读满后再解析 JSON。
    let header = format!("{:08x}", body.len());
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

#[cfg(unix)]
fn run_daemon(argv: Vec<String>) -> AppResult<()> {
    let (socket_path, config_path) = parse_daemon_args(argv)?;
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    let bound_config_path = path_absolute(&config_path)?;
    let mut state = DaemonState::new(&bound_config_path)?;
    let mut last_activity_at = Instant::now();
    loop {
        let wait_ms = next_daemon_wait_ms(&state.connections, last_activity_at);
        listener.set_nonblocking(true)?;
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                last_activity_at = Instant::now();
                let response =
                    match handle_daemon_stream(&mut stream, &bound_config_path, &mut state) {
                        Ok(response) => response,
                        Err(error) => DaemonResponse {
                            ok: false,
                            message: Some(error.to_string()),
                            stdout: None,
                            ..Default::default()
                        },
                    };
                let should_stop = response.stdout.as_deref() == Some("stop");
                write_daemon_response(&mut stream, &response)?;
                if should_stop {
                    break;
                }
                expire_connections(&mut state.connections);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(wait_ms.min(100)));
                expire_connections(&mut state.connections);
                if state.connections.is_empty()
                    && last_activity_at.elapsed() >= Duration::from_millis(DEFAULT_CACHE_TTL_MS)
                {
                    break;
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    unlink_socket_path(&socket_path)?;
    Ok(())
}

#[cfg(windows)]
fn run_daemon(argv: Vec<String>) -> AppResult<()> {
    let (socket_path, config_path) = parse_daemon_args(argv)?;
    let pipe_name = windows_pipe_name_from_path(&socket_path);
    let name = pipe_name
        .as_str()
        .to_ns_name::<GenericNamespaced>()
        .map_err(|error| AppError::new(format!("Windows named pipe 名称非法: {}", error)))?;
    let listener = ListenerOptions::new().name(name).create_sync()?;
    let bound_config_path = path_absolute(&config_path)?;
    let mut state = DaemonState::new(&bound_config_path)?;
    let mut last_activity_at = Instant::now();
    loop {
        match listener.accept() {
            Ok(mut stream) => {
                last_activity_at = Instant::now();
                let response =
                    match handle_daemon_stream(&mut stream, &bound_config_path, &mut state) {
                        Ok(response) => response,
                        Err(error) => DaemonResponse {
                            ok: false,
                            message: Some(error.to_string()),
                            stdout: None,
                            ..Default::default()
                        },
                    };
                let should_stop = response.stdout.as_deref() == Some("stop");
                write_daemon_response(&mut stream, &response)?;
                if should_stop {
                    break;
                }
                expire_connections(&mut state.connections);
            }
            Err(error) => return Err(AppError::new(error.to_string())),
        }
        if state.connections.is_empty()
            && last_activity_at.elapsed() >= Duration::from_millis(DEFAULT_CACHE_TTL_MS)
        {
            break;
        }
    }
    Ok(())
}

fn parse_daemon_args(argv: Vec<String>) -> AppResult<(PathBuf, PathBuf)> {
    let mut socket_path = None;
    let mut config_path = None;
    let mut iter = argv.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--socket" => socket_path = iter.next().map(PathBuf::from),
            "--config" => config_path = iter.next().map(PathBuf::from),
            _ => {}
        }
    }
    let socket_path = socket_path.ok_or_else(|| AppError::new("daemon 缺少 --socket 参数"))?;
    let config_path = config_path.ok_or_else(|| AppError::new("daemon 缺少 --config 参数"))?;
    Ok((socket_path, config_path))
}

fn next_daemon_wait_ms(connections: &HashMap<String, PoolEntry>, last_activity_at: Instant) -> u64 {
    if connections.is_empty() {
        return DEFAULT_CACHE_TTL_MS
            .saturating_sub(last_activity_at.elapsed().as_millis() as u64)
            .max(100);
    }
    connections
        .values()
        .map(|entry| {
            entry
                .ttl_ms
                .saturating_sub(entry.last_used_at.elapsed().as_millis() as u64)
                .max(100)
        })
        .min()
        .unwrap_or(DEFAULT_CACHE_TTL_MS)
}

fn expire_connections(connections: &mut HashMap<String, PoolEntry>) {
    let expired: Vec<String> = connections
        .iter()
        .filter_map(|(key, entry)| {
            (entry.last_used_at.elapsed() >= Duration::from_millis(entry.ttl_ms))
                .then(|| key.clone())
        })
        .collect();
    for key in expired {
        connections.remove(&key);
    }
}

fn handle_daemon_stream<S: Read + Write>(
    stream: &mut S,
    bound_config_path: &Path,
    state: &mut DaemonState,
) -> AppResult<DaemonResponse> {
    let line = read_line_from_socket(stream)?;
    let raw_value: serde_json::Value = serde_json::from_str(&line)?;
    if raw_value.get("operation").and_then(|item| item.as_str()) == Some("ping") {
        return Ok(DaemonResponse {
            ok: true,
            message: None,
            stdout: None,
            ..Default::default()
        });
    }
    if raw_value.get("operation").and_then(|item| item.as_str()) == Some("stop") {
        return Ok(DaemonResponse {
            ok: true,
            message: None,
            stdout: Some("stop".to_string()),
            ..Default::default()
        });
    }
    let request: DaemonRequest = serde_json::from_value(raw_value)?;
    let request_config_path = path_absolute(&request.config_path)?;
    if request_config_path != bound_config_path {
        return Err(AppError::new("SSH 缓存进程拒绝访问非绑定配置文件"));
    }
    let ttl_ms = request.cache_ttl_ms.unwrap_or(DEFAULT_CACHE_TTL_MS);
    if ttl_ms == 0 {
        return Err(AppError::new("cache-ttl 必须是正整数毫秒值"));
    }
    reload_daemon_config_if_changed(bound_config_path, state)?;
    resolve_password_ref_for_connection(
        bound_config_path,
        &mut state.configs,
        &request.connection_name,
    )?;
    resolve_jump_password_refs(
        bound_config_path,
        &mut state.configs,
        &request.connection_name,
    )?;
    validate_jump_hosts(&state.configs)?;
    let connection = find_connection(&state.configs, &request.connection_name)?.clone();
    if request.operation == "execute" {
        let command = request
            .command
            .as_deref()
            .ok_or_else(|| AppError::new("daemon execute 缺少 command"))?;
        validate_command(&connection, command)?;
    }
    let key = build_connection_key(bound_config_path, &state.configs, &connection);
    if !state.connections.contains_key(&key) {
        let session = state.run_with_timeout(
            request.timeout.unwrap_or(30000),
            connect_russh(&state.configs, &connection),
        )?;
        state.connections.insert(
            key.clone(),
            PoolEntry {
                session,
                last_used_at: Instant::now(),
                ttl_ms,
            },
        );
    }
    let mut entry = state
        .connections
        .remove(&key)
        .ok_or_else(|| AppError::new("SSH 缓存连接状态异常"))?;
    entry.ttl_ms = ttl_ms;
    entry.last_used_at = Instant::now();
    let result = match request.operation.as_str() {
        "execute" => {
            let command = request
                .command
                .ok_or_else(|| AppError::new("daemon execute 缺少 command"))?;
            let remote_command = match request.directory {
                Some(directory) => {
                    format!("cd -- {} && {}", shell_json_quote(&directory)?, command)
                }
                None => command,
            };
            let pty = resolve_pty(&connection, request.pty);
            let execute_result = state.run_with_timeout(
                request.timeout.unwrap_or(30000),
                execute_remote_command_with_session_async(
                    &entry.session,
                    &connection,
                    &remote_command,
                    pty,
                ),
            );
            // 仅当会话异常/连接失败（Err）时重连重试；命令非零退出（Ok 且 exit_code != 0）不重试。
            let output = match execute_result {
                Ok(output) => output,
                Err(error) => {
                    let _ = state.run_with_timeout(request.timeout.unwrap_or(30000), async {
                        entry
                            .session
                            .disconnect(Disconnect::ByApplication, "", "English")
                            .await
                            .map_err(|error| {
                                AppError::new(format!("断开失效 SSH 缓存连接失败: {}", error))
                            })
                    });
                    let session = state.run_with_timeout(
                        request.timeout.unwrap_or(30000),
                        connect_russh(&state.configs, &connection),
                    )?;
                    let output = state
                        .run_with_timeout(
                            request.timeout.unwrap_or(30000),
                            execute_remote_command_with_session_async(
                                &session,
                                &connection,
                                &remote_command,
                                pty,
                            ),
                        )
                        .map_err(|retry_error| {
                            AppError::new(format!("{}；已重连重试仍失败: {}", error, retry_error))
                        })?;
                    entry.session = session;
                    output
                }
            };
            DaemonResponse {
                ok: true,
                message: None,
                stdout: Some(output.stdout),
                exit_code: Some(output.exit_code),
                stderr: Some(output.stderr),
            }
        }
        "upload" => {
            let local = request
                .local_path
                .ok_or_else(|| AppError::new("daemon upload 缺少 localPath"))?;
            let remote = request
                .remote_path
                .ok_or_else(|| AppError::new("daemon upload 缺少 remotePath"))?;
            let local_path = path_absolute_from(Path::new(&local), &request.cwd)?;
            let session_ref = &entry.session;
            let connection_ref = &connection;
            let upload_future = Box::pin(async move {
                if request.recursive.unwrap_or(false) {
                    upload_dir_with_session_async(
                        session_ref,
                        connection_ref,
                        &local_path,
                        &remote,
                    )
                    .await
                } else {
                    upload_file_with_session_async(
                        session_ref,
                        connection_ref,
                        &local_path,
                        &remote,
                    )
                    .await
                }
            });
            let upload_result = match request.timeout {
                Some(timeout_ms) => state.run_with_timeout(timeout_ms, upload_future),
                None => state.runtime.block_on(upload_future),
            };
            if let Err(error) = upload_result {
                return Err(error);
            }
            DaemonResponse {
                ok: true,
                message: None,
                stdout: None,
                ..Default::default()
            }
        }
        "download" => {
            let local = request
                .local_path
                .ok_or_else(|| AppError::new("daemon download 缺少 localPath"))?;
            let remote = request
                .remote_path
                .ok_or_else(|| AppError::new("daemon download 缺少 remotePath"))?;
            let local_path = path_absolute_from(Path::new(&local), &request.cwd)?;
            if let Some(parent) = local_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let session_ref = &entry.session;
            let connection_ref = &connection;
            let download_future = Box::pin(async move {
                if request.recursive.unwrap_or(false) {
                    download_dir_with_session_async(
                        session_ref,
                        connection_ref,
                        &remote,
                        &local_path,
                    )
                    .await
                } else {
                    download_file_with_session_async(
                        session_ref,
                        connection_ref,
                        &remote,
                        &local_path,
                    )
                    .await
                }
            });
            let download_result = match request.timeout {
                Some(timeout_ms) => state.run_with_timeout(timeout_ms, download_future),
                None => state.runtime.block_on(download_future),
            };
            if let Err(error) = download_result {
                return Err(error);
            }
            DaemonResponse {
                ok: true,
                message: None,
                stdout: None,
                ..Default::default()
            }
        }
        _ => {
            return Err(AppError::new(format!(
                "不支持的 daemon 操作: {}",
                request.operation
            )))
        }
    };
    entry.last_used_at = Instant::now();
    state.connections.insert(key, entry);
    Ok(result)
}

fn reload_daemon_config_if_changed(config_path: &Path, state: &mut DaemonState) -> AppResult<()> {
    if state.config_snapshot.metadata_matches(config_path)? {
        return Ok(());
    }
    let current_snapshot = ConfigSnapshot::read(config_path)?;
    if current_snapshot.hash == state.config_snapshot.hash {
        state.config_snapshot = current_snapshot;
        return Ok(());
    }
    let configs = load_config(config_path)?;
    state.config_snapshot = current_snapshot;
    state.configs = configs;
    state.connections.clear();
    Ok(())
}

fn build_connection_key(
    config_path: &Path,
    configs: &[Connection],
    connection: &Connection,
) -> String {
    let auth = if let Some(private_key) = &connection.private_key {
        format!(
            "privateKey:{}:{}",
            private_key,
            sensitive_hash(connection.passphrase.as_deref().unwrap_or(""))
        )
    } else {
        format!(
            "password:{}",
            sensitive_hash(connection.password.as_deref().unwrap_or(""))
        )
    };
    let jump = connection
        .jump_host
        .as_deref()
        .and_then(|name| find_connection(configs, name).ok())
        .map(connection_fingerprint)
        .unwrap_or_else(|| "no-jump".to_string());
    let raw = format!(
        "{}|{}|{}|{}|{}|{:?}|{:?}|{}|{}",
        path_absolute(config_path)
            .unwrap_or_else(|_| canonical_or_absolute(config_path.to_path_buf()))
            .display(),
        connection.name,
        connection.host,
        connection.port,
        connection.username,
        connection.socks_proxy,
        connection.jump_host,
        jump,
        auth
    );
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn connection_fingerprint(connection: &Connection) -> String {
    let auth = if let Some(private_key) = &connection.private_key {
        format!(
            "privateKey:{}:{}",
            private_key,
            sensitive_hash(connection.passphrase.as_deref().unwrap_or(""))
        )
    } else {
        format!(
            "password:{}",
            sensitive_hash(connection.password.as_deref().unwrap_or(""))
        )
    };
    format!(
        "{}|{}|{}|{}|{:?}|{}",
        connection.name,
        connection.host,
        connection.port,
        connection.username,
        connection.socks_proxy,
        auth
    )
}

fn sensitive_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}
