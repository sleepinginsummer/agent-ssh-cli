// daemon 与连接缓存：Unix socket / Windows 命名管道协议、进程生命周期、连接池与请求分发。
//
// 依赖 `ssh`/`exec`/`transfer`/`runtime` 完成实际动作；CLI 侧只通过下方四个 pub(crate) 入口交互。

use crate::exec::execute_remote_command_with_privilege_async;
use crate::runtime::block_with_timeout;
use crate::ssh::{connect_russh, RusshClient};
use crate::transfer::{
    download_dir_with_session_async, download_file_with_session_async,
    upload_dir_with_session_async, upload_file_with_session_async,
};
use crate::{
    canonical_or_absolute, find_connection, load_config, lock_file_exclusive, path_absolute,
    path_absolute_from, project_root, resolve_jump_password_refs, resolve_password_ref_for_connection,
    resolve_privilege_credentials, resolve_pty, shell_json_quote, unlock_file, validate_command,
    validate_jump_hosts, AppError, AppResult, ConfigSnapshot, Connection,
    ExecuteArgs, GlobalArgs, PrivilegeMode, TransferArgs, DAEMON_REQUEST_TIMEOUT_MS,
    DAEMON_RESPONSE_LENGTH_BYTES, DAEMON_START_TIMEOUT_MS, DEFAULT_CACHE_TTL_MS,
};
use russh::{client, Disconnect};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
#[cfg(windows)]
use crate::home_dir;
#[cfg(windows)]
use interprocess::local_socket::{
    prelude::*, GenericNamespaced, ListenerOptions, Stream as LocalSocketStream,
};

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
    privilege: Option<PrivilegeMode>,
    recursive: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct DaemonResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stdout: Option<String>,
    // exec 专用：命令真实退出码与 stderr（成功路径也可能非零，如 exit 1 的命令）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exit_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stderr: Option<String>,
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

pub(crate) fn request_stop_daemon(config_path: &Path) -> AppResult<()> {
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

pub(crate) fn request_daemon_execute(parsed: &ExecuteArgs, command: &str) -> AppResult<DaemonResponse> {
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
        "privilege": parsed.privilege,
    });
    request_daemon(&config_path, &request)
}

pub(crate) fn request_daemon_transfer(parsed: &TransferArgs, operation: &str) -> AppResult<()> {
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
pub(crate) fn run_daemon(argv: Vec<String>) -> AppResult<()> {
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
pub(crate) fn run_daemon(argv: Vec<String>) -> AppResult<()> {
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

#[derive(Clone, Copy)]
struct DaemonExecuteOptions {
    pty: bool,
    privilege: Option<PrivilegeMode>,
    timeout_ms: u64,
}
fn handle_daemon_execute(
    state: &DaemonState,
    entry: &mut PoolEntry,
    connection: &Connection,
    remote_command: &str,
    options: DaemonExecuteOptions,
) -> AppResult<DaemonResponse> {
    let execute_result = state.run_with_timeout(
        options.timeout_ms,
        execute_remote_command_with_privilege_async(
            &entry.session,
            connection,
            remote_command,
            options.pty,
            options.privilege,
        ),
    );
    // 仅当会话异常/连接失败（Err）时重连重试；远端非零退出码不会重试。
    let output = match execute_result {
        Ok(output) => output,
        Err(error) => {
            let _ = state.run_with_timeout(options.timeout_ms, async {
                entry
                    .session
                    .disconnect(Disconnect::ByApplication, "", "English")
                    .await
                    .map_err(|error| AppError::new(format!("断开失效 SSH 缓存连接失败: {}", error)))
            });
            let session = state.run_with_timeout(
                options.timeout_ms,
                connect_russh(&state.configs, connection),
            )?;
            let output = state
                .run_with_timeout(
                    options.timeout_ms,
                    execute_remote_command_with_privilege_async(
                        &session,
                        connection,
                        remote_command,
                        options.pty,
                        options.privilege,
                    ),
                )
                .map_err(|retry_error| {
                    AppError::new(format!("{}；已重连重试仍失败: {}", error, retry_error))
                })?;
            entry.session = session;
            output
        }
    };
    Ok(DaemonResponse {
        ok: true,
        message: None,
        stdout: Some(output.stdout),
        exit_code: Some(output.exit_code),
        stderr: Some(output.stderr),
    })
}

fn handle_daemon_stream<S: Read + Write>(
    stream: &mut S,
    bound_config_path: &Path,
    state: &mut DaemonState,
) -> AppResult<DaemonResponse> {
    let raw_value = read_request_value(stream)?;
    match raw_value.get("operation").and_then(|item| item.as_str()) {
        Some("ping") => {
            return Ok(DaemonResponse {
                ok: true,
                ..Default::default()
            })
        }
        Some("stop") => {
            return Ok(DaemonResponse {
                ok: true,
                stdout: Some("stop".to_string()),
                ..Default::default()
            })
        }
        _ => {}
    }
    let request: DaemonRequest = serde_json::from_value(raw_value)?;
    let ttl_ms = request_ttl_ms(&request)?;
    let connection = prepare_daemon_request(state, bound_config_path, &request)?;
    let key = build_connection_key(bound_config_path, &state.configs, &connection);
    let mut entry = acquire_pool_entry(state, &key, &connection, &request, ttl_ms)?;
    let result = dispatch_daemon_operation(state, &mut entry, &connection, &request)?;
    // 连接条目用完回存缓存池，刷新活跃时间后再执行 ttl 驱逐判定。
    entry.last_used_at = Instant::now();
    state.connections.insert(key, entry);
    Ok(result)
}

fn read_request_value<S: Read>(stream: &mut S) -> AppResult<serde_json::Value> {
    let line = read_line_from_socket(stream)?;
    Ok(serde_json::from_str(&line)?)
}

fn request_ttl_ms(request: &DaemonRequest) -> AppResult<u64> {
    let ttl_ms = request.cache_ttl_ms.unwrap_or(DEFAULT_CACHE_TTL_MS);
    if ttl_ms == 0 {
        return Err(AppError::new("cache-ttl 必须是正整数毫秒值"));
    }
    Ok(ttl_ms)
}

// 校验请求作用域并刷新配置/凭据，返回本次操作使用的连接快照。
fn prepare_daemon_request(
    state: &mut DaemonState,
    bound_config_path: &Path,
    request: &DaemonRequest,
) -> AppResult<Connection> {
    let request_config_path = path_absolute(&request.config_path)?;
    if request_config_path != bound_config_path {
        return Err(AppError::new("SSH 缓存进程拒绝访问非绑定配置文件"));
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
    if let Some(mode) = request.privilege {
        resolve_privilege_credentials(
            bound_config_path,
            &mut state.configs,
            &request.connection_name,
            mode,
        )?;
    }
    validate_jump_hosts(&state.configs)?;
    let connection = find_connection(&state.configs, &request.connection_name)?.clone();
    if request.operation == "execute" {
        let command = request
            .command
            .as_deref()
            .ok_or_else(|| AppError::new("daemon execute 缺少 command"))?;
        validate_command(&connection, command)?;
    }
    Ok(connection)
}

// 从缓存池取连接；未命中时按请求超时新建并入库。
fn acquire_pool_entry(
    state: &mut DaemonState,
    key: &str,
    connection: &Connection,
    request: &DaemonRequest,
    ttl_ms: u64,
) -> AppResult<PoolEntry> {
    if !state.connections.contains_key(key) {
        let session = state.run_with_timeout(
            request.timeout.unwrap_or(30000),
            connect_russh(&state.configs, connection),
        )?;
        state.connections.insert(
            key.to_string(),
            PoolEntry {
                session,
                last_used_at: Instant::now(),
                ttl_ms,
            },
        );
    }
    let mut entry = state
        .connections
        .remove(key)
        .ok_or_else(|| AppError::new("SSH 缓存连接状态异常"))?;
    entry.ttl_ms = ttl_ms;
    entry.last_used_at = Instant::now();
    Ok(entry)
}

fn dispatch_daemon_operation(
    state: &mut DaemonState,
    entry: &mut PoolEntry,
    connection: &Connection,
    request: &DaemonRequest,
) -> AppResult<DaemonResponse> {
    match request.operation.as_str() {
        "execute" => {
            let command = request
                .command
                .as_deref()
                .ok_or_else(|| AppError::new("daemon execute 缺少 command"))?;
            let remote_command = match request.directory.as_deref() {
                Some(directory) => {
                    format!("cd -- {} && {}", shell_json_quote(directory)?, command)
                }
                None => command.to_string(),
            };
            handle_daemon_execute(
                state,
                entry,
                connection,
                &remote_command,
                DaemonExecuteOptions {
                    pty: resolve_pty(connection, request.pty),
                    privilege: request.privilege,
                    timeout_ms: request.timeout.unwrap_or(30000),
                },
            )
        }
        "upload" => handle_daemon_upload(state, entry, connection, request),
        "download" => handle_daemon_download(state, entry, connection, request),
        _ => Err(AppError::new(format!(
            "不支持的 daemon 操作: {}",
            request.operation
        ))),
    }
}

fn handle_daemon_upload(
    state: &mut DaemonState,
    entry: &mut PoolEntry,
    connection: &Connection,
    request: &DaemonRequest,
) -> AppResult<DaemonResponse> {
    let local = request
        .local_path
        .as_deref()
        .ok_or_else(|| AppError::new("daemon upload 缺少 localPath"))?;
    let remote = request
        .remote_path
        .as_deref()
        .ok_or_else(|| AppError::new("daemon upload 缺少 remotePath"))?;
    let local_path = path_absolute_from(Path::new(local), &request.cwd)?;
    let recursive = request.recursive.unwrap_or(false);
    let session_ref = &entry.session;
    let upload_future = Box::pin(async move {
        if recursive {
            upload_dir_with_session_async(session_ref, connection, &local_path, remote).await
        } else {
            upload_file_with_session_async(session_ref, connection, &local_path, remote).await
        }
    });
    match request.timeout {
        Some(timeout_ms) => state.run_with_timeout(timeout_ms, upload_future)?,
        None => state.runtime.block_on(upload_future)?,
    }
    Ok(DaemonResponse {
        ok: true,
        ..Default::default()
    })
}

fn handle_daemon_download(
    state: &mut DaemonState,
    entry: &mut PoolEntry,
    connection: &Connection,
    request: &DaemonRequest,
) -> AppResult<DaemonResponse> {
    let local = request
        .local_path
        .as_deref()
        .ok_or_else(|| AppError::new("daemon download 缺少 localPath"))?;
    let remote = request
        .remote_path
        .as_deref()
        .ok_or_else(|| AppError::new("daemon download 缺少 remotePath"))?;
    let local_path = path_absolute_from(Path::new(local), &request.cwd)?;
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let recursive = request.recursive.unwrap_or(false);
    let session_ref = &entry.session;
    let download_future = Box::pin(async move {
        if recursive {
            download_dir_with_session_async(session_ref, connection, remote, &local_path).await
        } else {
            download_file_with_session_async(session_ref, connection, remote, &local_path).await
        }
    });
    match request.timeout {
        Some(timeout_ms) => state.run_with_timeout(timeout_ms, download_future)?,
        None => state.runtime.block_on(download_future)?,
    }
    Ok(DaemonResponse {
        ok: true,
        ..Default::default()
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;


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
