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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
  agentsshcli help [list|exec|upload|download]
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
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] [--pty|--no-pty] --connection <name> (--command <command>|--command-file <path>) [--directory <dir>] [--timeout <ms>]
  agentsshcli help exec
  agentsshcli --version

说明:
  在远端执行命令。默认不分配伪终端，可通过 --pty 临时开启。
"#;

const HELP_UPLOAD: &str = r#"
用法:
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <localPath> <remotePath>
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --local <path> --remote <path>
  agentsshcli help upload
  agentsshcli --version

说明:
  上传本地文件到远端。默认使用 daemon 缓存，可通过 --no-cache 直连。
"#;

const HELP_DOWNLOAD: &str = r#"
用法:
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <remotePath> <localPath>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --remote <path> --local <path>
  agentsshcli help download
  agentsshcli --version

说明:
  下载远端文件到本地。默认使用 daemon 缓存，可通过 --no-cache 直连。
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
    pty: Option<bool>,
    allowed_local_paths: Vec<String>,
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
}

#[derive(Debug)]
struct TransferArgs {
    global: GlobalArgs,
    connection_name: String,
    local_path: String,
    remote_path: String,
}

#[derive(Debug)]
struct SocksProxy {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("{}", error);
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
        pty: entry.pty,
        allowed_local_paths: ensure_string_array(
            entry.allowed_local_paths,
            "allowedLocalPaths",
            index,
        )?,
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
    Ok(configs)
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
            "获取本地密码迁移锁失败: {}",
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
            "释放本地密码迁移锁失败: {}",
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
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn canonical_or_absolute(path: PathBuf) -> PathBuf {
    path.canonicalize().unwrap_or(path)
}

fn validate_local_path(
    configs: &[Connection],
    local_path: &str,
    base_cwd: &Path,
) -> AppResult<PathBuf> {
    let resolved_cwd = canonical_or_absolute(base_cwd.to_path_buf());
    let candidate = Path::new(local_path);
    let resolved_path = if candidate.is_absolute() {
        canonical_or_absolute(candidate.to_path_buf())
    } else {
        canonical_or_absolute(resolved_cwd.join(candidate))
    };
    let mut allowed_roots = vec![resolved_cwd, project_root()?];
    for config in configs {
        for allowed_path in &config.allowed_local_paths {
            allowed_roots.push(canonical_or_absolute(PathBuf::from(allowed_path)));
        }
    }
    if allowed_roots
        .iter()
        .any(|root| resolved_path == *root || resolved_path.starts_with(root))
    {
        return Ok(resolved_path);
    }
    Err(AppError::new(
        "本地路径不允许访问，必须位于当前工作目录、项目目录或显式允许的路径内",
    ))
}

fn parse_global_args(argv: Vec<String>) -> AppResult<GlobalArgs> {
    let mut args = argv.into_iter().peekable();
    let mut config_path = default_config_path();
    let mut help = false;
    let mut version = false;
    let mut no_cache = false;
    let mut cache_ttl_ms = None;
    let mut remaining = Vec::new();
    while let Some(current) = args.next() {
        match current.as_str() {
            "--help" | "-h" => help = true,
            "--version" | "-v" => version = true,
            "--json" => {}
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
            _ => {
                remaining.push(current);
                remaining.extend(args);
                break;
            }
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
        });
    }
    let mut args = global.args.clone();
    let connection_option = take_option(&mut args, &["--connection", "-c"])?;
    let command_option = take_option(&mut args, &["--command"])?;
    let command_file = take_option(&mut args, &["--command-file"])?;
    let directory = take_option(&mut args, &["--directory", "-d"])?;
    let timeout_value = take_option(&mut args, &["--timeout", "-t"])?;
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
    })
}

fn take_bool_flag_pair(
    args: &mut Vec<String>,
    true_name: &str,
    false_name: &str,
) -> AppResult<Option<bool>> {
    let true_count = args
        .iter()
        .filter(|item| item.as_str() == true_name)
        .count();
    let false_count = args
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
    if let Some(index) = args.iter().position(|item| item == true_name) {
        args.remove(index);
        return Ok(Some(true));
    }
    if let Some(index) = args.iter().position(|item| item == false_name) {
        args.remove(index);
        return Ok(Some(false));
    }
    Ok(None)
}

fn resolve_value(
    args: &mut Vec<String>,
    names: &[&str],
    field_name: &str,
) -> AppResult<Option<String>> {
    match take_option(args, names)? {
        Some(value) => Ok(Some(value)),
        None => take_positional(args, field_name),
    }
}

fn parse_transfer_args(argv: Vec<String>, mode: &str) -> AppResult<TransferArgs> {
    let global = parse_global_args(argv)?;
    if global.help || global.version {
        return Ok(TransferArgs {
            global,
            connection_name: String::new(),
            local_path: String::new(),
            remote_path: String::new(),
        });
    }
    let mut args = global.args.clone();
    let connection_name = resolve_value(&mut args, &["--connection", "-c"], "connectionName")?;
    let (local_path, remote_path) = if mode == "upload" {
        (
            resolve_value(&mut args, &["--local", "-l"], "localPath")?,
            resolve_value(&mut args, &["--remote", "-r"], "remotePath")?,
        )
    } else {
        let remote = resolve_value(&mut args, &["--remote", "-r"], "remotePath")?;
        let local = resolve_value(&mut args, &["--local", "-l"], "localPath")?;
        (local, remote)
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
    Ok(TransferArgs {
        global,
        connection_name,
        local_path,
        remote_path,
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
    if !global.args.is_empty() {
        return Err(AppError::new(format!(
            "agentsshcli list 不接受位置参数: {}",
            global.args.join(" ")
        )));
    }
    let configs = load_config(&global.config_path)?;
    let output: Vec<serde_json::Value> = configs
        .iter()
        .map(|item| {
            serde_json::json!({
                "name": item.name,
                "host": item.host,
                "port": item.port,
                "username": item.username,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&output)?);
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
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    let configs = load_config_for_connection(&parsed.global.config_path, &parsed.connection_name)?;
    let connection = find_connection(&configs, &parsed.connection_name)?;
    let command = resolve_execute_command(&configs, &parsed)?;
    validate_command(connection, &command)?;
    let remote_command = match parsed.directory {
        Some(ref directory) => format!("cd -- {} && {}", shell_json_quote(directory)?, command),
        None => command.clone(),
    };
    let result = if parsed.global.no_cache {
        execute_remote_command(
            connection,
            &remote_command,
            parsed.timeout_ms,
            resolve_pty(connection, parsed.pty),
        )?
    } else {
        request_daemon_execute(&parsed, &command)?
    };
    if !result.is_empty() {
        println!("{}", result);
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
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    let configs = load_config_for_connection(&parsed.global.config_path, &parsed.connection_name)?;
    let connection = find_connection(&configs, &parsed.connection_name)?;
    if parsed.global.no_cache {
        let local_path = validate_local_path(&configs, &parsed.local_path, &env::current_dir()?)?;
        upload_file(connection, &local_path, &parsed.remote_path, 30000)?;
    } else {
        request_daemon_transfer(&parsed, "upload")?;
    }
    println!("File uploaded successfully");
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
    prepare_connection_config(&parsed.global.config_path, &parsed.connection_name)?;
    let configs = load_config_for_connection(&parsed.global.config_path, &parsed.connection_name)?;
    let connection = find_connection(&configs, &parsed.connection_name)?;
    if parsed.global.no_cache {
        let local_path = validate_local_path(&configs, &parsed.local_path, &env::current_dir()?)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        download_file(connection, &parsed.remote_path, &local_path, 30000)?;
    } else {
        request_daemon_transfer(&parsed, "download")?;
    }
    println!("File downloaded successfully");
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

async fn connect_russh(connection: &Connection) -> AppResult<client::Handle<RusshClient>> {
    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
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
    let stream = if connection.socks_proxy.is_some() {
        connect_socks_proxy(connection).await?
    } else {
        tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?
    };
    let mut session = client::connect_stream(Arc::new(config), stream, RusshClient)
        .await
        .map_err(|error| {
            AppError::new(format!("连接 {} 建立 SSH 失败: {}", connection.name, error))
        })?;
    authenticate_russh(connection, &mut session).await?;
    Ok(session)
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

async fn execute_remote_command_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_command: &str,
    pty: bool,
) -> AppResult<String> {
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
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            _ => {}
        }
    }
    let stdout = String::from_utf8_lossy(&stdout).trim_end().to_string();
    let stderr = String::from_utf8_lossy(&stderr).trim_end().to_string();
    let code = exit_status.unwrap_or(0);
    if code != 0 {
        let mut parts = Vec::new();
        if !stdout.is_empty() {
            parts.push(stdout);
        }
        if !stderr.is_empty() {
            parts.push(format!("[stderr]\n{}", stderr));
        }
        parts.push(format!("[exit code] {}", code));
        return Err(AppError::new(parts.join("\n")));
    }
    Ok(stdout)
}

async fn execute_remote_command_async(
    connection: &Connection,
    remote_command: &str,
    pty: bool,
) -> AppResult<String> {
    let session = connect_russh(connection).await?;
    let result =
        execute_remote_command_with_session_async(&session, connection, remote_command, pty).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

fn execute_remote_command(
    connection: &Connection,
    remote_command: &str,
    timeout_ms: u64,
    pty: bool,
) -> AppResult<String> {
    run_with_timeout(
        timeout_ms,
        execute_remote_command_async(connection, remote_command, pty),
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

async fn upload_file_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
) -> AppResult<()> {
    let sftp = open_sftp_session(session, connection).await?;
    let mut local_file = tokio::fs::File::open(local_path).await?;
    let mut remote_file = sftp
        .create(remote_path.to_string())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 创建远端文件失败: {}",
                connection.name, error
            ))
        })?;
    tokio::io::copy(&mut local_file, &mut remote_file).await?;
    remote_file.shutdown().await?;
    let _ = sftp.close().await;
    Ok(())
}

async fn download_file_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
) -> AppResult<()> {
    let sftp = open_sftp_session(session, connection).await?;
    let mut remote_file = sftp.open(remote_path.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 打开远端文件失败: {}",
            connection.name, error
        ))
    })?;
    let mut local_file = tokio::fs::File::create(local_path).await?;
    tokio::io::copy(&mut remote_file, &mut local_file).await?;
    local_file.shutdown().await?;
    let _ = sftp.close().await;
    Ok(())
}

async fn upload_file_async(
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
) -> AppResult<()> {
    let session = connect_russh(connection).await?;
    let result =
        upload_file_with_session_async(&session, connection, local_path, remote_path).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

async fn download_file_async(
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
) -> AppResult<()> {
    let session = connect_russh(connection).await?;
    let result =
        download_file_with_session_async(&session, connection, remote_path, local_path).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

fn upload_file(
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
    timeout_ms: u64,
) -> AppResult<()> {
    run_with_timeout(
        timeout_ms,
        upload_file_async(connection, local_path, remote_path),
    )
}

fn download_file(
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
    timeout_ms: u64,
) -> AppResult<()> {
    run_with_timeout(
        timeout_ms,
        download_file_async(connection, remote_path, local_path),
    )
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

fn resolve_execute_command(configs: &[Connection], parsed: &ExecuteArgs) -> AppResult<String> {
    let Some(command_file) = parsed.command_file.as_ref() else {
        return Ok(parsed.command.clone());
    };
    let path = validate_local_path(configs, command_file, &env::current_dir()?)?;
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
    fn daemon_response_frame_round_trips_large_stdout() {
        let response = DaemonResponse {
            ok: true,
            message: None,
            stdout: Some("A".repeat(200_000)),
        };
        let mut bytes = Vec::new();
        write_daemon_response(&mut bytes, &response).unwrap();
        let parsed = read_daemon_response(&mut bytes.as_slice()).unwrap();
        assert_eq!(parsed.stdout.as_deref(), response.stdout.as_deref());
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
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout: Option<String>,
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

fn request_daemon_execute(parsed: &ExecuteArgs, command: &str) -> AppResult<String> {
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
    let response = request_daemon(&config_path, &request)?;
    Ok(response.stdout.unwrap_or_default())
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
        unlink_socket_path(&socket_path)?;
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

fn ensure_daemon(socket_path: &Path, config_path: &Path) -> AppResult<()> {
    match connect_socket(socket_path, 500) {
        Ok(mut stream) => {
            let _ = stream.write_all(b"{\"operation\":\"ping\"}\n");
            match read_line_from_socket(&mut stream) {
                Ok(line) if !line.is_empty() => return Ok(()),
                _ => unlink_socket_path(socket_path)?,
            }
        }
        Err(_) => unlink_socket_path(socket_path)?,
    }
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
    unlink_socket_path(&socket_path)?;
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
                        },
                    };
                write_daemon_response(&mut stream, &response)?;
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
                        },
                    };
                write_daemon_response(&mut stream, &response)?;
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
    let connection = find_connection(&state.configs, &request.connection_name)?.clone();
    if request.operation == "execute" {
        let command = request
            .command
            .as_deref()
            .ok_or_else(|| AppError::new("daemon execute 缺少 command"))?;
        validate_command(&connection, command)?;
    }
    let key = build_connection_key(bound_config_path, &connection);
    if !state.connections.contains_key(&key) {
        let session =
            state.run_with_timeout(request.timeout.unwrap_or(30000), connect_russh(&connection))?;
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
            let stdout_result = state.run_with_timeout(
                request.timeout.unwrap_or(30000),
                execute_remote_command_with_session_async(
                    &entry.session,
                    &connection,
                    &remote_command,
                    pty,
                ),
            );
            let stdout = match stdout_result {
                Ok(stdout) => stdout,
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
                        connect_russh(&connection),
                    )?;
                    let stdout = state
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
                    stdout
                }
            };
            DaemonResponse {
                ok: true,
                message: None,
                stdout: Some(stdout),
            }
        }
        "upload" => {
            let local = request
                .local_path
                .ok_or_else(|| AppError::new("daemon upload 缺少 localPath"))?;
            let remote = request
                .remote_path
                .ok_or_else(|| AppError::new("daemon upload 缺少 remotePath"))?;
            let local_path = validate_local_path(&state.configs, &local, &request.cwd)?;
            if let Err(error) = state.run_with_timeout(
                request.timeout.unwrap_or(30000),
                upload_file_with_session_async(&entry.session, &connection, &local_path, &remote),
            ) {
                return Err(error);
            }
            DaemonResponse {
                ok: true,
                message: None,
                stdout: None,
            }
        }
        "download" => {
            let local = request
                .local_path
                .ok_or_else(|| AppError::new("daemon download 缺少 localPath"))?;
            let remote = request
                .remote_path
                .ok_or_else(|| AppError::new("daemon download 缺少 remotePath"))?;
            let local_path = validate_local_path(&state.configs, &local, &request.cwd)?;
            if let Some(parent) = local_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Err(error) = state.run_with_timeout(
                request.timeout.unwrap_or(30000),
                download_file_with_session_async(&entry.session, &connection, &remote, &local_path),
            ) {
                return Err(error);
            }
            DaemonResponse {
                ok: true,
                message: None,
                stdout: None,
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

fn build_connection_key(config_path: &Path, connection: &Connection) -> String {
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
    let raw = format!(
        "{}|{}|{}|{}|{}|{:?}|{}",
        path_absolute(config_path)
            .unwrap_or_else(|_| canonical_or_absolute(config_path.to_path_buf()))
            .display(),
        connection.name,
        connection.host,
        connection.port,
        connection.username,
        connection.socks_proxy,
        auth
    );
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sensitive_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}
