// 配置与凭据：连接配置读写与校验、secret 密钥库、明文凭据迁移、配置快照与命令黑白名单。

use crate::privilege::{credential_fields, validate_unix_username, PrivilegeMode};
use crate::{AppError, AppResult};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
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
use std::time::SystemTime;

const DEFAULT_CONFIG_DIR: &str = ".agent-ssh-cli";
const DEFAULT_CONFIG_FILE: &str = "config.json";
const SECRET_KEY_FILE: &str = "secret.key";
const SECRETS_FILE: &str = "secrets.json";
const MIGRATION_LOCK_FILE: &str = ".password-migration.lock";
const SECRETS_VERSION: u8 = 1;
const PASSWORD_REF_PREFIX: &str = "agentsshcli:";

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
pub(crate) struct Connection {
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password: Option<String>,
    password_ref: Option<String>,
    pub(crate) private_key: Option<String>,
    pub(crate) passphrase: Option<String>,
    pub(crate) socks_proxy: Option<String>,
    pub(crate) jump_host: Option<String>,
    pty: Option<bool>,
    privilege_enabled: bool,
    pub(crate) sudo_user: String,
    pub(crate) sudo_password: Option<String>,
    sudo_password_ref: Option<String>,
    pub(crate) su_user: String,
    pub(crate) su_password: Option<String>,
    su_password_ref: Option<String>,
    command_whitelist: Vec<PatternRule>,
    command_blacklist: Vec<PatternRule>,
}

pub(crate) fn default_config_path() -> PathBuf {
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

// home_dir 仅由 windows 分支的 socket 目录逻辑跨模块使用。
pub(crate) fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
}

pub(crate) fn project_root() -> AppResult<PathBuf> {
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

pub(crate) fn init_config() -> AppResult<()> {
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

// 连接归一化按「端点 / 认证 / 可选引用 / 提权」分组，helper 各自负责字段校验与错误信息，
// normalize_entry 只做组装，避免单个函数堆叠十余个分支。
struct NormalizedEndpoint {
    name: String,
    host: String,
    port: u16,
    username: String,
}

struct NormalizedAuth {
    password: Option<String>,
    password_ref: Option<String>,
    private_key: Option<String>,
}

struct NormalizedPrivilege {
    enabled: bool,
    sudo_user: String,
    sudo_password: Option<String>,
    sudo_password_ref: Option<String>,
    su_user: String,
    su_password: Option<String>,
    su_password_ref: Option<String>,
}

fn normalize_entry(entry: RawConnection, index: usize) -> AppResult<Connection> {
    let endpoint = normalize_endpoint(&entry, index)?;
    let auth = normalize_auth(&entry, index)?;
    validate_optional_refs(&entry, index, &endpoint.name)?;
    let privilege = normalize_privilege(&entry, index)?;
    let _ = ensure_string_array(entry.allowed_local_paths, "allowedLocalPaths", index)?;
    Ok(Connection {
        name: endpoint.name,
        host: endpoint.host,
        port: endpoint.port,
        username: endpoint.username,
        password: auth.password,
        password_ref: auth.password_ref,
        private_key: auth.private_key,
        passphrase: entry.passphrase,
        socks_proxy: entry.socks_proxy,
        jump_host: entry.jump_host,
        pty: entry.pty,
        privilege_enabled: privilege.enabled,
        sudo_user: privilege.sudo_user,
        sudo_password: privilege.sudo_password,
        sudo_password_ref: privilege.sudo_password_ref,
        su_user: privilege.su_user,
        su_password: privilege.su_password,
        su_password_ref: privilege.su_password_ref,
        command_whitelist: ensure_regex_array(entry.command_whitelist, "commandWhitelist", index)?,
        command_blacklist: ensure_regex_array(entry.command_blacklist, "commandBlacklist", index)?,
    })
}

fn normalize_endpoint(entry: &RawConnection, index: usize) -> AppResult<NormalizedEndpoint> {
    let required = |value: &Option<String>, field: &str| -> AppResult<String> {
        value
            .clone()
            .filter(|item| !item.trim().is_empty())
            .ok_or_else(|| {
                AppError::new(format!(
                    "ssh-config.json 第 {} 项缺少合法的 {}",
                    index + 1,
                    field
                ))
            })
    };
    let port = entry.port.unwrap_or(22);
    if port == 0 {
        return Err(AppError::new(format!(
            "ssh-config.json 第 {} 项的 port 非法",
            index + 1
        )));
    }
    Ok(NormalizedEndpoint {
        name: required(&entry.name, "name")?,
        host: required(&entry.host, "host")?,
        port,
        username: required(&entry.username, "username")?,
    })
}

fn normalize_auth(entry: &RawConnection, index: usize) -> AppResult<NormalizedAuth> {
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
    Ok(NormalizedAuth {
        password: entry.password.clone().filter(|_| has_password),
        password_ref: entry.password_ref.clone().filter(|_| has_password_ref),
        private_key: entry.private_key.clone().filter(|_| has_private_key),
    })
}

fn validate_optional_refs(entry: &RawConnection, index: usize, name: &str) -> AppResult<()> {
    for (value, field_name) in [
        (&entry.passphrase, "passphrase"),
        (&entry.socks_proxy, "socksProxy"),
        (&entry.jump_host, "jumpHost"),
    ] {
        if value.as_ref().is_some_and(|item| item.trim().is_empty()) {
            return Err(AppError::new(format!(
                "ssh-config.json 第 {} 项的 {} 必须是非空字符串",
                index + 1,
                field_name
            )));
        }
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
    Ok(())
}

fn normalize_privilege(entry: &RawConnection, index: usize) -> AppResult<NormalizedPrivilege> {
    let non_blank = |value: &Option<String>| {
        value
            .clone()
            .filter(|item| !item.trim().is_empty())
    };
    Ok(NormalizedPrivilege {
        enabled: entry.privilege_enabled.unwrap_or(false),
        sudo_user: normalize_privilege_user(entry.sudo_user.clone(), "root", "sudoUser", index)?,
        sudo_password: non_blank(&entry.sudo_password),
        sudo_password_ref: entry.sudo_password_ref.clone(),
        su_user: normalize_privilege_user(entry.su_user.clone(), "root", "suUser", index)?,
        su_password: non_blank(&entry.su_password),
        su_password_ref: entry.su_password_ref.clone(),
    })
}

pub(crate) fn load_config(config_path: &Path) -> AppResult<Vec<Connection>> {
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

pub(crate) fn load_config_for_connection(
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

pub(crate) fn load_config_for_execute(
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

pub(crate) fn ensure_privilege_enabled(config_path: &Path, connection_name: &str) -> AppResult<()> {
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

pub(crate) fn validate_jump_hosts(configs: &[Connection]) -> AppResult<()> {
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
pub(crate) fn lock_file_exclusive(file: &File) -> AppResult<()> {
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
pub(crate) fn unlock_file(file: &File) -> AppResult<()> {
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
pub(crate) fn lock_file_exclusive(_file: &File) -> AppResult<()> {
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn unlock_file(_file: &File) -> AppResult<()> {
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

pub(crate) fn resolve_password_ref_for_connection(
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

pub(crate) fn resolve_jump_password_refs(
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

pub(crate) fn resolve_privilege_credentials(
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

pub(crate) fn prepare_privilege_config(
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

pub(crate) fn prepare_connection_config(config_path: &Path, connection_name: &str) -> AppResult<()> {
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
pub(crate) struct ConfigSnapshot {
    modified: Option<SystemTime>,
    len: u64,
    pub(crate) hash: String,
}

impl ConfigSnapshot {
    pub(crate) fn read(path: &Path) -> AppResult<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            modified: metadata.modified().ok(),
            len: metadata.len(),
            hash: hash_file(path)?,
        })
    }

    pub(crate) fn metadata_matches(&self, path: &Path) -> AppResult<bool> {
        let metadata = fs::metadata(path)?;
        Ok(self.modified == metadata.modified().ok() && self.len == metadata.len())
    }
}

pub(crate) fn find_connection<'a>(
    configs: &'a [Connection],
    connection_name: &str,
) -> AppResult<&'a Connection> {
    configs
        .iter()
        .find(|item| item.name == connection_name)
        .ok_or_else(|| AppError::new(format!("未找到连接配置: {}", connection_name)))
}

pub(crate) fn path_absolute(path: &Path) -> AppResult<PathBuf> {
    path_absolute_from(path, &env::current_dir()?)
}

pub(crate) fn path_absolute_from(path: &Path, base_cwd: &Path) -> AppResult<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(base_cwd.join(path))
    }
}

pub(crate) fn canonical_or_absolute(path: PathBuf) -> PathBuf {
    path.canonicalize().unwrap_or(path)
}

pub(crate) fn validate_command(connection: &Connection, command: &str) -> AppResult<()> {
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

// 伪终端开关：命令行显式指定优先，其次连接配置，默认不分配。
pub(crate) fn resolve_pty(connection: &Connection, override_pty: Option<bool>) -> bool {
    override_pty.or(connection.pty).unwrap_or(false)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::write_config;
    use std::time::Duration;


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
        let (_dir, path) = write_config(
            r#"[
              {"name":"a","host":"127.0.0.1","username":"root","password":"p","pty":true},
              {"name":"b","host":"127.0.0.1","username":"root","password":"p"}
            ]"#,
        );
        let configs = load_config(&path).unwrap();
        assert!(resolve_pty(&configs[0], None));
        assert!(!resolve_pty(&configs[0], Some(false)));
        assert!(!resolve_pty(&configs[1], None));
        assert!(resolve_pty(&configs[1], Some(true)));
    }
}
