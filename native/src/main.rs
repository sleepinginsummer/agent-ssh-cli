mod daemon;
mod exec;
mod privilege;
mod runtime;
mod ssh;
mod transfer;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
#[cfg(windows)]
use interprocess::local_socket::{
    prelude::*, GenericNamespaced, ListenerOptions, Stream as LocalSocketStream,
};
use daemon::{request_daemon_execute, request_daemon_transfer, request_stop_daemon, run_daemon};
use exec::{execute_remote_command, ExecOutput};
use transfer::{download_dir, download_file, upload_dir, upload_file};
use privilege::{credential_fields, validate_unix_username, PrivilegeMode};
use rand_core::{OsRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

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

const HELP_AGENTSSHCLI: &str = r#"
用法:
  agentsshcli list [--config <path>] [--json]
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] [--sudo|--su] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] [--sudo|--su] --connection <name> (--command <command>|--command-file <path>) [--directory <dir>] [--timeout <ms>]
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
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] [--sudo|--su] [--json] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] [--sudo|--su] [--json] --connection <name> (--command <command>|--command-file <path>) [--directory <dir>] [--timeout <ms>]
  agentsshcli help exec
  agentsshcli --version

说明:
  在远端执行命令。默认不分配伪终端，可通过 --pty 临时开启。
  --sudo/--su: 使用配置中的 sudo 或 su 凭据提权执行，两者互斥且要求 privilegeEnabled=true。
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
    privilege_enabled: Option<bool>,
    sudo_user: Option<String>,
    sudo_password: Option<String>,
    sudo_password_ref: Option<String>,
    su_user: Option<String>,
    su_password: Option<String>,
    su_password_ref: Option<String>,
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
    privilege_enabled: bool,
    sudo_user: String,
    sudo_password: Option<String>,
    sudo_password_ref: Option<String>,
    su_user: String,
    su_password: Option<String>,
    su_password_ref: Option<String>,
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
    privilege: Option<PrivilegeMode>,
    json_output: bool,
}

// 传输子命令模式：决定位置参数顺序（upload 为 local → remote，download 为 remote → local）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferMode {
    Upload,
    Download,
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

fn normalize_privilege_user(
    value: Option<String>,
    default: &str,
    field_name: &str,
    index: usize,
) -> AppResult<String> {
    let user = value.unwrap_or_else(|| default.to_string());
    if !validate_unix_username(&user) {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 {} 不是合法的 Unix 用户名",
            index + 1,
            field_name
        )));
    }
    Ok(user)
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
    for (value, field_name) in [
        (&entry.sudo_password_ref, "sudoPasswordRef"),
        (&entry.su_password_ref, "suPasswordRef"),
    ] {
        if value.as_ref().is_some_and(|item| item.trim().is_empty()) {
            return Err(AppError::new(format!(
                "ssh-config.json 第 {} 项的 {} 必须是非空字符串",
                index + 1,
                field_name
            )));
        }
    }
    let sudo_user = normalize_privilege_user(entry.sudo_user, "root", "sudoUser", index)?;
    let su_user = normalize_privilege_user(entry.su_user, "root", "suUser", index)?;
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
        privilege_enabled: entry.privilege_enabled.unwrap_or(false),
        sudo_user,
        sudo_password: entry.sudo_password.filter(|value| !value.trim().is_empty()),
        sudo_password_ref: entry.sudo_password_ref,
        su_user,
        su_password: entry.su_password.filter(|value| !value.trim().is_empty()),
        su_password_ref: entry.su_password_ref,
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

fn load_config_for_execute(
    config_path: &Path,
    connection_name: &str,
    privilege: Option<PrivilegeMode>,
) -> AppResult<Vec<Connection>> {
    let mut configs = load_config_for_connection(config_path, connection_name)?;
    if let Some(mode) = privilege {
        resolve_privilege_credentials(config_path, &mut configs, connection_name, mode)?;
    }
    Ok(configs)
}

fn ensure_privilege_enabled(config_path: &Path, connection_name: &str) -> AppResult<()> {
    let configs = load_config(config_path)?;
    let connection = find_connection(&configs, connection_name)?;
    if !connection.privilege_enabled {
        return Err(AppError::new(format!(
            "连接 {} 未开启 privilegeEnabled，拒绝提权执行",
            connection_name
        )));
    }
    Ok(())
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

fn resolve_privilege_credentials(
    config_path: &Path,
    configs: &mut [Connection],
    connection_name: &str,
    mode: PrivilegeMode,
) -> AppResult<()> {
    let connection = configs
        .iter_mut()
        .find(|item| item.name == connection_name)
        .ok_or_else(|| AppError::new(format!("未找到连接配置: {}", connection_name)))?;
    if !connection.privilege_enabled {
        return Err(AppError::new(format!(
            "连接 {} 未开启 privilegeEnabled，拒绝提权执行",
            connection_name
        )));
    }
    match mode {
        PrivilegeMode::Sudo => {
            if connection.sudo_password.is_none() {
                connection.sudo_password = match connection.sudo_password_ref.as_deref() {
                    Some(password_ref) => Some(decrypt_password(config_path, password_ref)?),
                    None => connection.password.clone(),
                };
            }
            if connection.sudo_password.is_none() {
                return Err(AppError::new(format!(
                    "连接 {} 缺少 sudoPassword/sudoPasswordRef，且 SSH 认证密码不可复用",
                    connection_name
                )));
            }
        }
        PrivilegeMode::Su => {
            if connection.su_password.is_none() {
                if let Some(password_ref) = connection.su_password_ref.as_deref() {
                    connection.su_password = Some(decrypt_password(config_path, password_ref)?);
                }
            }
            if connection.su_password.is_none() {
                return Err(AppError::new(format!(
                    "连接 {} 缺少 suPassword 或 suPasswordRef",
                    connection_name
                )));
            }
        }
    }
    Ok(())
}

fn prepare_privilege_config(
    config_path: &Path,
    connection_name: &str,
    mode: PrivilegeMode,
) -> AppResult<()> {
    let fields = credential_fields(mode);
    let default_ref = format!(
        "{}{}{}",
        PASSWORD_REF_PREFIX, connection_name, fields.reference_suffix
    );
    let _ = migrate_plain_credential_for_connection(
        config_path,
        connection_name,
        fields.password,
        fields.password_ref,
        &default_ref,
    )?;
    Ok(())
}

fn password_ref_for(connection_name: &str) -> String {
    format!("{}{}", PASSWORD_REF_PREFIX, connection_name)
}

fn migrate_plain_credential_for_connection(
    config_path: &Path,
    connection_name: &str,
    password_field: &str,
    password_ref_field: &str,
    default_password_ref: &str,
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
        let Some(password) = object.get(password_field).and_then(|item| item.as_str()) else {
            return Ok(false);
        };
        if password.trim().is_empty() {
            return Ok(false);
        }
        let password = password.to_string();
        let password_ref = object
            .get(password_ref_field)
            .and_then(|item| item.as_str())
            .filter(|item| !item.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| default_password_ref.to_string());
        encrypt_password(config_path, &password_ref, &password)?;
        object.insert(
            password_field.to_string(),
            serde_json::Value::String(String::new()),
        );
        object.insert(
            password_ref_field.to_string(),
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

fn migrate_plain_password_for_connection(
    config_path: &Path,
    connection_name: &str,
) -> AppResult<bool> {
    migrate_plain_credential_for_connection(
        config_path,
        connection_name,
        "password",
        "passwordRef",
        &password_ref_for(connection_name),
    )
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
            privilege: None,
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
    let sudo = take_bool_flag(&mut args, "--sudo")?;
    let su = take_bool_flag(&mut args, "--su")?;
    let privilege = match (sudo, su) {
        (true, true) => return Err(AppError::new("--sudo 和 --su 只能选择一个")),
        (true, false) => Some(PrivilegeMode::Sudo),
        (false, true) => Some(PrivilegeMode::Su),
        (false, false) => None,
    };
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
        privilege,
        json_output,
    })
}

fn parse_transfer_args(argv: Vec<String>, mode: TransferMode) -> AppResult<TransferArgs> {
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
    // 命名参数始终按字面语义解析：--local 进本地字段，--remote 进远端字段。
    // 两个子命令的差异只在位置参数顺序（见下方 take_positional 调用）。
    let local_named = take_option(&mut args, &["--local", "-l"])?;
    let remote_named = take_option(&mut args, &["--remote", "-r"])?;
    let json_output = take_bool_flag(&mut args, "--json")?;
    let recursive = take_bool_flag(&mut args, "--recursive")?;
    // 位置参数按字段顺序解析：upload 为 connection → local → remote，
    // download 为 connection → remote → local（与 CLI 语义一致），命名参数已占用时跳过。
    let connection_name = match connection_named {
        Some(name) => Some(name),
        None => take_positional(&mut args, "connectionName")?,
    };
    let (local_path, remote_path) = match mode {
        TransferMode::Upload => {
            let local_path = match local_named {
                Some(path) => Some(path),
                None => take_positional(&mut args, "localPath")?,
            };
            let remote_path = match remote_named {
                Some(path) => Some(path),
                None => take_positional(&mut args, "remotePath")?,
            };
            (local_path, remote_path)
        }
        TransferMode::Download => {
            let remote_path = match remote_named {
                Some(path) => Some(path),
                None => take_positional(&mut args, "remotePath")?,
            };
            let local_path = match local_named {
                Some(path) => Some(path),
                None => take_positional(&mut args, "localPath")?,
            };
            (local_path, remote_path)
        }
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
    if parsed.privilege.is_some() {
        ensure_privilege_enabled(&parsed.global.config_path, &parsed.connection_name)?;
    }
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    if let Some(mode) = parsed.privilege {
        prepare_privilege_config(&parsed.global.config_path, &parsed.connection_name, mode)?;
    }
    let configs = load_config_for_execute(
        &parsed.global.config_path,
        &parsed.connection_name,
        parsed.privilege,
    )?;
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
            parsed.privilege,
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
    let parsed = parse_transfer_args(argv, TransferMode::Upload)?;
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
    let parsed = parse_transfer_args(argv, TransferMode::Download)?;
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
    use std::time::{Duration, Instant};
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
    fn parse_exec_supports_privilege_modes_and_rejects_conflict() {
        let sudo = parse_execute_args(vec!["--sudo".into(), "server".into(), "id".into()]).unwrap();
        assert_eq!(sudo.privilege, Some(PrivilegeMode::Sudo));

        let su = parse_execute_args(vec!["--su".into(), "server".into(), "id".into()]).unwrap();
        assert_eq!(su.privilege, Some(PrivilegeMode::Su));

        let error = parse_execute_args(vec![
            "--sudo".into(),
            "--su".into(),
            "server".into(),
            "id".into(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("--sudo 和 --su"));
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
            TransferMode::Upload,
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
            TransferMode::Upload,
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
            TransferMode::Upload,
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
            TransferMode::Download,
        )
        .unwrap();
        assert_eq!(parsed.remote_path, "/remote/file");
        assert_eq!(parsed.local_path, "/local/file");
    }

    #[test]
    fn parse_transfer_named_args_keep_semantics_for_both_modes() {
        // --remote 必须落在 remote_path、--local 落在 local_path；download 曾把两者互换，
        // 导致远端 stat 打到本地路径上（表现为「读取远端文件信息失败: No such file」）。
        let download = parse_transfer_args(
            vec![
                "--connection".into(),
                "server".into(),
                "--remote".into(),
                "/remote/file".into(),
                "--local".into(),
                "/local/file".into(),
            ],
            TransferMode::Download,
        )
        .unwrap();
        assert_eq!(download.remote_path, "/remote/file");
        assert_eq!(download.local_path, "/local/file");

        let upload = parse_transfer_args(
            vec![
                "--connection".into(),
                "server".into(),
                "--local".into(),
                "/local/file".into(),
                "--remote".into(),
                "/remote/file".into(),
            ],
            TransferMode::Upload,
        )
        .unwrap();
        assert_eq!(upload.remote_path, "/remote/file");
        assert_eq!(upload.local_path, "/local/file");
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
            TransferMode::Upload,
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
            TransferMode::Upload,
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
            TransferMode::Download,
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
            TransferMode::Upload,
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
    fn privilege_is_disabled_by_default_and_must_be_enabled() {
        let (_dir, path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","username":"user","password":"ssh-secret"}]"#,
        );
        let error =
            load_config_for_execute(&path, "server", Some(PrivilegeMode::Sudo)).unwrap_err();
        assert!(error.to_string().contains("未开启 privilegeEnabled"));

        let (_dir, path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","username":"user","password":"ssh-secret","privilegeEnabled":true}]"#,
        );
        let configs = load_config_for_execute(&path, "server", Some(PrivilegeMode::Sudo)).unwrap();
        let connection = find_connection(&configs, "server").unwrap();
        assert_eq!(connection.sudo_password.as_deref(), Some("ssh-secret"));
    }

    #[test]
    fn privilege_credentials_migrate_to_isolated_secret_keys() {
        let (_dir, path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","username":"user","password":"ssh","privilegeEnabled":true,"sudoPassword":"sudo-secret","suPassword":"su-secret"}]"#,
        );
        assert!(migrate_plain_password_for_connection(&path, "server").unwrap());
        prepare_privilege_config(&path, "server", PrivilegeMode::Sudo).unwrap();
        prepare_privilege_config(&path, "server", PrivilegeMode::Su).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sudo-secret"));
        assert!(!raw.contains("su-secret"));
        assert!(raw.contains(r#""sudoPasswordRef": "agentsshcli:server:sudo""#));
        assert!(raw.contains(r#""suPasswordRef": "agentsshcli:server:su""#));

        let secrets = load_secrets(&path).unwrap();
        assert!(secrets.items.contains_key("agentsshcli:server"));
        assert!(secrets.items.contains_key("agentsshcli:server:sudo"));
        assert!(secrets.items.contains_key("agentsshcli:server:su"));
    }

    #[test]
    fn su_requires_an_explicit_target_password() {
        let (_dir, path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","username":"user","password":"ssh-secret","privilegeEnabled":true}]"#,
        );
        let error = load_config_for_execute(&path, "server", Some(PrivilegeMode::Su)).unwrap_err();
        assert!(error.to_string().contains("缺少 suPassword"));
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
}
