// 编辑器进程层：启动锁、状态文件、子进程生命周期与浏览器打开。

use super::http::send_request;
use crate::config::{canonical_or_absolute, lock_file_exclusive, path_absolute, unlock_file};
use crate::{AppError, AppResult};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const EDITOR_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct EditorState {
    pub(super) port: u16,
    pub(super) token: String,
    pub(super) pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnectionOutcome {
    Activity,
    Ignored,
    Stop,
}

struct EditorIdleTimer {
    last_activity: Instant,
    timeout: Duration,
}

impl EditorIdleTimer {
    fn new(timeout: Duration) -> Self {
        Self {
            last_activity: Instant::now(),
            timeout,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_activity) >= self.timeout
    }

    fn observe(&mut self, outcome: ConnectionOutcome, now: Instant) -> bool {
        match outcome {
            ConnectionOutcome::Activity => self.last_activity = now,
            ConnectionOutcome::Ignored => {}
            ConnectionOutcome::Stop => return true,
        }
        false
    }

    fn remaining(&self, now: Instant) -> Duration {
        self.timeout
            .saturating_sub(now.duration_since(self.last_activity))
    }
}

pub(super) struct StateGuard {
    path: PathBuf,
    owner: EditorState,
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        if matches!(read_state_path(&self.path), Ok(ref state) if state == &self.owner) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) fn run_editor_process<F>(
    config_path: &Path,
    idle_timeout: Duration,
    mut handle_connection: F,
) -> AppResult<()>
where
    F: FnMut(&mut TcpStream, u16, &str) -> AppResult<ConnectionOutcome>,
{
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let state = EditorState {
        port,
        token: random_token(),
        pid: std::process::id(),
    };
    let _guard = publish_state(config_path, &state)?;
    eprintln!("配置编辑器监听 127.0.0.1:{}", port);
    listener.set_nonblocking(true)?;
    let mut idle_timer = EditorIdleTimer::new(idle_timeout);

    loop {
        let now = Instant::now();
        if idle_timer.is_expired(now) {
            eprintln!("配置编辑器空闲超时，进程自动退出");
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                match handle_connection(&mut stream, port, &state.token) {
                    Ok(outcome) => {
                        if idle_timer.observe(outcome, Instant::now()) {
                            return Ok(());
                        }
                    }
                    Err(error) => eprintln!("配置编辑器请求失败: {}", error),
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let remaining = idle_timer.remaining(Instant::now());
                thread::sleep(ACCEPT_POLL_INTERVAL.min(remaining));
            }
            Err(error) => eprintln!("配置编辑器接收连接失败: {}", error),
        }
    }
}

struct StartLock {
    file: File,
}

impl StartLock {
    fn acquire(config_path: &Path) -> AppResult<Self> {
        let path = state_path(config_path)?.with_extension("start.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        lock_file_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for StartLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

pub(crate) fn start_editor(config_path: &Path) -> AppResult<()> {
    let config_path = canonical_config_path(config_path)?;
    let _start_lock = StartLock::acquire(&config_path)?;
    if let Ok(state) = read_state(&config_path) {
        if editor_is_healthy(&state) {
            let url = editor_url(&state);
            open_browser(&url)?;
            println!("配置编辑器已打开: {}", url);
            return Ok(());
        }
        remove_state_if_owned(&config_path, &state)?;
    }

    let mut child = spawn_editor(&config_path)?;
    let state = wait_for_editor(&config_path, &mut child)?;
    let url = editor_url(&state);
    open_browser(&url)?;
    println!("配置编辑器已打开: {}", url);
    Ok(())
}

pub(crate) fn stop_editor(config_path: &Path) -> AppResult<()> {
    let config_path = canonical_config_path(config_path)?;
    let state = read_state(&config_path).map_err(|_| AppError::new("配置编辑器未运行"))?;
    let status = send_request(state.port, "POST", "/api/stop", &state.token, b"{}")?;
    if status != 200 {
        return Err(AppError::new("配置编辑器拒绝停止请求"));
    }
    let path = state_path(&config_path)?;
    let start = Instant::now();
    while path.exists() && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(50));
    }
    if path.exists() {
        return Err(AppError::new("配置编辑器停止超时，状态文件仍存在"));
    }
    println!("配置编辑器已停止");
    Ok(())
}

pub(super) fn canonical_config_path(config_path: &Path) -> AppResult<PathBuf> {
    Ok(canonical_or_absolute(path_absolute(config_path)?))
}

pub(super) fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub(super) fn publish_state(config_path: &Path, state: &EditorState) -> AppResult<StateGuard> {
    let path = state_path(config_path)?;
    write_state(&path, state)?;
    Ok(StateGuard {
        path,
        owner: state.clone(),
    })
}

fn spawn_editor(config_path: &Path) -> AppResult<Child> {
    let exe = env::current_exe()?;
    let log_path = log_path(config_path)?;
    let _ = fs::remove_file(&log_path);
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    #[cfg(unix)]
    fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))?;
    Ok(Command::new(exe)
        .arg("__editor")
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()?)
}

fn wait_for_editor(config_path: &Path, child: &mut Child) -> AppResult<EditorState> {
    let start = Instant::now();
    while start.elapsed() < START_TIMEOUT {
        if let Some(status) = child.try_wait()? {
            return Err(AppError::new(format!(
                "配置编辑器进程提前退出（{}），日志: {}",
                status,
                log_path(config_path)?.display()
            )));
        }
        if let Ok(state) = read_state(config_path) {
            if state.pid == child.id() && editor_is_healthy(&state) {
                return Ok(state);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(AppError::new(format!(
        "启动配置编辑器超时，日志: {}",
        log_path(config_path)?.display()
    )))
}

fn editor_is_healthy(state: &EditorState) -> bool {
    send_request(state.port, "GET", "/api/status", &state.token, b"")
        .map(|status| status == 200)
        .unwrap_or(false)
}

fn editor_url(state: &EditorState) -> String {
    format!("http://127.0.0.1:{}/#t={}", state.port, state.token)
}

fn state_path(config_path: &Path) -> AppResult<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(config_path.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    let dir = env::temp_dir().join("agent-ssh-cli-editor");
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir.join(format!("{}.json", &digest[..16])))
}

fn log_path(config_path: &Path) -> AppResult<PathBuf> {
    Ok(state_path(config_path)?.with_extension("log"))
}

fn write_state(path: &Path, state: &EditorState) -> AppResult<()> {
    let tmp = path.with_extension(format!("{}.tmp", state.pid));
    fs::write(&tmp, serde_json::to_vec(state)?)?;
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn read_state(config_path: &Path) -> AppResult<EditorState> {
    read_state_path(&state_path(config_path)?)
}

fn read_state_path(path: &Path) -> AppResult<EditorState> {
    let raw = fs::read(path)?;
    Ok(serde_json::from_slice(&raw)?)
}

fn remove_state_if_owned(config_path: &Path, expected: &EditorState) -> AppResult<()> {
    let path = state_path(config_path)?;
    if matches!(read_state_path(&path), Ok(ref state) if state == expected) {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn open_browser(url: &str) -> AppResult<()> {
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(url).status()?;
    #[cfg(target_os = "windows")]
    let status = Command::new("cmd")
        .args(["/C", "start", "", url])
        .status()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(url).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::new(format!("浏览器打开失败，请手动访问 {}", url)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn state_guard_only_removes_its_own_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let first = EditorState {
            port: 1001,
            token: "first".to_string(),
            pid: 1,
        };
        let second = EditorState {
            port: 1002,
            token: "second".to_string(),
            pid: 2,
        };
        write_state(&path, &first).unwrap();
        let guard = StateGuard {
            path: path.clone(),
            owner: first,
        };
        write_state(&path, &second).unwrap();
        drop(guard);
        assert_eq!(read_state_path(&path).unwrap(), second);
    }

    #[test]
    fn idle_timer_refreshes_only_for_activity() {
        let mut timer = EditorIdleTimer::new(Duration::from_secs(600));
        let started = timer.last_activity;
        assert!(!timer.observe(
            ConnectionOutcome::Ignored,
            started + Duration::from_secs(599),
        ));
        assert!(timer.is_expired(started + Duration::from_secs(600)));

        let mut timer = EditorIdleTimer::new(Duration::from_secs(600));
        let started = timer.last_activity;
        assert!(!timer.observe(
            ConnectionOutcome::Activity,
            started + Duration::from_secs(599),
        ));
        assert!(!timer.is_expired(started + Duration::from_secs(1198)));
        assert!(timer.is_expired(started + Duration::from_secs(1199)));
        assert!(timer.observe(ConnectionOutcome::Stop, started + Duration::from_secs(1199),));
    }

    #[test]
    fn editor_process_cleans_state_after_injected_idle_timeout() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let state_file = state_path(&config_path).unwrap();
        let service_path = config_path.clone();
        let service = std::thread::spawn(move || {
            run_editor_process(&service_path, Duration::from_millis(100), |_, _, _| {
                Ok(ConnectionOutcome::Ignored)
            })
        });

        let wait_started = Instant::now();
        while !state_file.exists() && wait_started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(state_file.exists(), "服务启动后应发布状态文件");
        service.join().unwrap().unwrap();
        assert!(!state_file.exists(), "空闲退出后应清理状态文件");
    }

    #[test]
    fn editor_process_restores_accepted_stream_to_blocking_mode() {
        use std::io::{Read, Write};

        let directory = tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let state_file = state_path(&config_path).unwrap();
        let service_path = config_path.clone();
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let service = std::thread::spawn(move || {
            run_editor_process(
                &service_path,
                Duration::from_secs(1),
                move |stream, _, _| {
                    ready_sender.send(()).unwrap();
                    let mut byte = [0_u8; 1];
                    stream.read_exact(&mut byte)?;
                    Ok(ConnectionOutcome::Stop)
                },
            )
        });

        let wait_started = Instant::now();
        while !state_file.exists() && wait_started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let state = read_state_path(&state_file).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", state.port)).unwrap();
        ready_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        client.write_all(b"x").unwrap();
        service.join().unwrap().unwrap();
        assert!(!state_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn start_lock_serializes_same_config_path() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let first = StartLock::acquire(&config_path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _second = StartLock::acquire(&config_path).unwrap();
            sender.send(()).unwrap();
        });

        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        drop(first);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}
