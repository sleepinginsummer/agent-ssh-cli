// 本地配置编辑器：编排回环 HTTP 路由、配置 API 与服务生命周期。

mod http;
mod process;

use self::http::{
    read_request, validate_origin, validate_token, write_json, write_json_error, write_response,
};
use self::process::{
    canonical_config_path, run_editor_process, ConnectionOutcome, EDITOR_IDLE_TIMEOUT,
};
pub(crate) use self::process::{start_editor, stop_editor};
use crate::config::{
    find_connection, prepare_editor_config, prepare_editor_test_connections, read_editor_config,
    reveal_connection_secret, save_editor_config, SaveEditorError,
};
use crate::runtime::run_with_timeout;
use crate::ssh::connect_russh;
use crate::{AppError, AppResult};
use russh::Disconnect;
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const EDITOR_HTML: &str = include_str!("../web/editor.html");
const EDITOR_DEFAULTS: &str = include_str!("../web/editor-defaults.json");
// 单进程编辑器最多运行一次 SSH 测试；工作线程持有槽位直到响应写完。
static TEST_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

struct TestSlot;

impl TestSlot {
    fn acquire() -> Option<Self> {
        TEST_IN_PROGRESS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for TestSlot {
    fn drop(&mut self) {
        TEST_IN_PROGRESS.store(false, Ordering::Release);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevealRequest {
    connection: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordUpdate {
    connection: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveRequest {
    connections: serde_json::Value,
    expected_hash: String,
    #[serde(default)]
    password_updates: Vec<PasswordUpdate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestConnectionRequest {
    connections: serde_json::Value,
    connection: String,
    #[serde(default)]
    password_updates: Vec<PasswordUpdate>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EditorDefaults {
    command_blacklist: Vec<String>,
}

fn parse_editor_defaults() -> AppResult<EditorDefaults> {
    serde_json::from_str(EDITOR_DEFAULTS)
        .map_err(|error| AppError::new(format!("编辑器默认策略格式错误: {}", error)))
}

#[derive(Debug)]
enum ApiAction {
    Json(serde_json::Value),
    Stop(serde_json::Value),
}

#[derive(Debug)]
struct ApiDispatch {
    result: Result<ApiAction, ApiFailure>,
    activity: bool,
}

#[derive(Debug)]
struct ApiFailure {
    status: u16,
    message: String,
}

impl ApiFailure {
    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: 400,
            message: error.to_string(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            message: "接口不存在".to_string(),
        }
    }
}
pub(crate) fn run_editor_service_args(args: Vec<String>) -> AppResult<()> {
    let mut config_path = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                config_path = args.get(index).map(PathBuf::from);
            }
            value => return Err(AppError::new(format!("编辑器内部参数无效: {}", value))),
        }
        index += 1;
    }
    let config_path = config_path.ok_or_else(|| AppError::new("编辑器缺少 --config"))?;
    run_editor_service(&canonical_config_path(&config_path)?)
}

fn run_editor_service(config_path: &Path) -> AppResult<()> {
    prepare_editor_config(config_path)?;
    let defaults = parse_editor_defaults()?;
    run_editor_process(config_path, EDITOR_IDLE_TIMEOUT, |stream, port, token| {
        handle_editor_stream(stream, port, token, config_path, &defaults)
    })
}

fn handle_editor_stream(
    stream: &mut TcpStream,
    port: u16,
    token: &str,
    config_path: &Path,
    defaults: &EditorDefaults,
) -> AppResult<ConnectionOutcome> {
    match handle_connection(stream, port, token, config_path, defaults) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            eprintln!("配置编辑器请求失败: {}", error);
            let _ = write_json_error(stream, 400, &error.to_string());
            Ok(ConnectionOutcome::Ignored)
        }
    }
}

fn handle_config_read(
    config_path: &Path,
    defaults: &EditorDefaults,
) -> Result<ApiAction, ApiFailure> {
    let document = read_editor_config(config_path).map_err(ApiFailure::bad_request)?;
    Ok(ApiAction::Json(serde_json::json!({
        "path": config_path.to_string_lossy(),
        "connections": document.connections,
        "defaults": defaults,
        "hash": document.hash
    })))
}

fn handle_secret_reveal(body: &[u8], config_path: &Path) -> Result<ApiAction, ApiFailure> {
    let payload: RevealRequest = serde_json::from_slice(body).map_err(ApiFailure::bad_request)?;
    let secret =
        reveal_connection_secret(config_path, payload.connection.trim(), payload.kind.trim())
            .map_err(ApiFailure::bad_request)?;
    Ok(ApiAction::Json(
        serde_json::json!({"secret": secret, "expiresIn": 15}),
    ))
}

fn handle_config_save(body: &[u8], config_path: &Path) -> Result<ApiAction, ApiFailure> {
    let payload: SaveRequest = serde_json::from_slice(body).map_err(ApiFailure::bad_request)?;
    let updates: Vec<(String, String)> = payload
        .password_updates
        .into_iter()
        .map(|item| (item.connection, item.password))
        .collect();
    match save_editor_config(
        config_path,
        payload.connections,
        &payload.expected_hash,
        &updates,
    ) {
        Ok(hash) => Ok(ApiAction::Json(
            serde_json::json!({"ok": true, "hash": hash}),
        )),
        Err(SaveEditorError::Conflict) => Err(ApiFailure {
            status: 409,
            message: "配置文件已被其他进程修改，请重新载入后再保存".to_string(),
        }),
        Err(SaveEditorError::App(error)) => Err(ApiFailure::bad_request(error)),
    }
}

fn handle_connection_test(
    body: &[u8],
    config_path: &Path,
) -> Result<serde_json::Value, ApiFailure> {
    let payload: TestConnectionRequest =
        serde_json::from_slice(body).map_err(ApiFailure::bad_request)?;
    let updates: Vec<(String, String)> = payload
        .password_updates
        .into_iter()
        .map(|item| (item.connection, item.password))
        .collect();
    let name = payload.connection.as_str();
    let configs =
        prepare_editor_test_connections(config_path, &payload.connections, name, &updates)
            .map_err(ApiFailure::bad_request)?;
    let target = find_connection(&configs, name).map_err(ApiFailure::bad_request)?;
    eprintln!("配置编辑器测试 SSH 连接: {}", name);
    let result = run_with_timeout(15_000, async {
        let session = connect_russh(&configs, target).await?;
        if let Err(error) = session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
        {
            eprintln!("配置编辑器 SSH 测试断开连接失败: {}", error);
        }
        Ok(())
    });
    Ok(match result {
        Ok(()) => serde_json::json!({"ok": true}),
        Err(error) => {
            eprintln!("配置编辑器 SSH 测试失败: {}", error);
            serde_json::json!({"ok": false, "error": error.to_string()})
        }
    })
}

fn dispatch_api(
    request: &http::HttpRequest,
    config_path: &Path,
    defaults: &EditorDefaults,
) -> ApiDispatch {
    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/status") => Ok(ApiAction::Json(serde_json::json!({"ok": true}))),
        ("GET", "/api/config") => handle_config_read(config_path, defaults),
        ("POST", "/api/activity") => Ok(ApiAction::Json(serde_json::json!({"ok": true}))),
        ("POST", "/api/secrets/reveal") => handle_secret_reveal(&request.body, config_path),
        ("POST", "/api/config") => handle_config_save(&request.body, config_path),
        ("POST", "/api/stop") => Ok(ApiAction::Stop(serde_json::json!({"ok": true}))),
        _ => {
            return ApiDispatch {
                result: Err(ApiFailure::not_found()),
                activity: false,
            };
        }
    };
    ApiDispatch {
        result,
        activity: true,
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    port: u16,
    token: &str,
    config_path: &Path,
    defaults: &EditorDefaults,
) -> AppResult<ConnectionOutcome> {
    let request = read_request(stream)?;
    eprintln!("配置编辑器请求 {} {}", request.method, request.path);
    if let Err(error) = validate_origin(&request, port) {
        write_json_error(stream, 403, &error.to_string())?;
        return Ok(ConnectionOutcome::Ignored);
    }
    if request.method == "GET" && request.path == "/" {
        write_response(
            stream,
            200,
            "text/html; charset=utf-8",
            EDITOR_HTML.as_bytes(),
        )?;
        return Ok(ConnectionOutcome::Ignored);
    }
    if let Err(error) = validate_token(&request, token) {
        write_json_error(stream, 403, &error.to_string())?;
        return Ok(ConnectionOutcome::Ignored);
    }

    // SSH 握手可能等待网络超时，复制响应流交给线程，避免阻塞串行 accept 循环。
    if request.method == "POST" && request.path == "/api/connections/test" {
        let Some(slot) = TestSlot::acquire() else {
            write_json_error(stream, 409, "已有连接正在测试，请稍后再试")?;
            return Ok(ConnectionOutcome::Activity);
        };
        let mut worker_stream = stream.try_clone()?;
        let path = config_path.to_path_buf();
        std::thread::Builder::new()
            .name("editor-ssh-test".to_string())
            .spawn(move || {
                let _slot = slot;
                let response = match handle_connection_test(&request.body, &path) {
                    Ok(value) => write_json(&mut worker_stream, 200, &value),
                    Err(error) => {
                        write_json_error(&mut worker_stream, error.status, &error.message)
                    }
                };
                if let Err(error) = response {
                    eprintln!("配置编辑器 SSH 测试响应失败: {}", error);
                }
            })?;
        return Ok(ConnectionOutcome::Activity);
    }

    let dispatch = dispatch_api(&request, config_path, defaults);
    let outcome = if dispatch.activity {
        ConnectionOutcome::Activity
    } else {
        ConnectionOutcome::Ignored
    };
    match dispatch.result {
        Ok(ApiAction::Json(value)) => write_json(stream, 200, &value)?,
        Ok(ApiAction::Stop(value)) => {
            write_json(stream, 200, &value)?;
            return Ok(ConnectionOutcome::Stop);
        }
        Err(error) => write_json_error(stream, error.status, &error.message)?,
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_request_accepts_frontend_password_update_contract() {
        let payload: SaveRequest = serde_json::from_value(serde_json::json!({
            "connections": [{
                "name": "server",
                "host": "127.0.0.1",
                "username": "root",
                "passwordRef": "agentsshcli:server"
            }],
            "expectedHash": "abc123",
            "passwordUpdates": [{
                "connection": "server",
                "password": "new-secret"
            }]
        }))
        .unwrap();

        assert_eq!(payload.expected_hash, "abc123");
        assert_eq!(payload.password_updates.len(), 1);
        assert_eq!(payload.password_updates[0].connection, "server");
        assert_eq!(payload.password_updates[0].password, "new-secret");
    }

    #[test]
    fn connection_test_preserves_whitespace_in_connection_name() {
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::thread::spawn(move || {
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(2) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        drop(stream);
                        return true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("本地监听失败: {}", error),
                }
            }
            false
        });
        let body = serde_json::json!({
            "connection": " server ",
            "connections": [{"name":" server ","host":"127.0.0.1","port":port,"username":"root","passwordRef":"agentsshcli:server"}],
            "passwordUpdates": [{"connection":" server ","password":"draft"}]
        });
        let response = handle_connection_test(&serde_json::to_vec(&body).unwrap(), &path);
        assert!(accepted.join().unwrap());
        assert_eq!(response.unwrap()["ok"], false);
    }

    #[test]
    fn editor_defaults_have_a_typed_valid_contract() {
        let defaults = parse_editor_defaults().unwrap();
        assert_eq!(defaults.command_blacklist.len(), 3);
        assert!(defaults
            .command_blacklist
            .iter()
            .all(|pattern| regex::Regex::new(pattern).is_ok()));
        let value = serde_json::to_value(defaults).unwrap();
        assert!(value.get("commandBlacklist").unwrap().is_array());
        assert!(value.get("command_blacklist").is_none());
    }

    #[test]
    fn config_save_handler_maps_hash_conflict_to_409() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(
            &path,
            r#"[{"name":"server","host":"127.0.0.1","username":"root","privateKey":"/tmp/id"}]"#,
        )
        .unwrap();
        let document = read_editor_config(&path).unwrap();
        std::fs::write(
            &path,
            r#"[{"name":"changed","host":"127.0.0.1","username":"root","privateKey":"/tmp/id"}]"#,
        )
        .unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "connections": document.connections,
            "expectedHash": document.hash,
            "passwordUpdates": []
        }))
        .unwrap();

        let error = handle_config_save(&body, &path).unwrap_err();
        assert_eq!(error.status, 409);
    }

    #[test]
    fn secret_handler_rejects_malformed_payload_without_socket_io() {
        let error = handle_secret_reveal(b"not-json", Path::new("unused")).unwrap_err();
        assert_eq!(error.status, 400);
    }

    #[test]
    fn internal_editor_args_do_not_accept_token() {
        let error =
            run_editor_service_args(vec!["--token".to_string(), "secret".to_string()]).unwrap_err();
        assert!(error.to_string().contains("内部参数无效"));
    }

    fn route_response_with_outcome(
        request: &str,
        config_path: &Path,
    ) -> (String, ConnectionOutcome) {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener, TcpStream};

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let config_path = config_path.to_path_buf();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let defaults = parse_editor_defaults().unwrap();
            handle_editor_stream(&mut stream, port, "test-token", &config_path, &defaults).unwrap()
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .write_all(request.replace("{port}", &port.to_string()).as_bytes())
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        let outcome = server.join().unwrap();
        (response, outcome)
    }

    fn route_response(request: &str, config_path: &Path) -> String {
        route_response_with_outcome(request, config_path).0
    }
    #[test]
    fn connection_test_uses_worker_without_blocking_status_and_rejects_parallel_test() {
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let fake_ssh = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        fake_ssh.set_nonblocking(true).unwrap();
        let ssh_port = fake_ssh.local_addr().unwrap().port();
        std::fs::write(&path, format!(
            r#"[{{"name":"draft","host":"127.0.0.1","port":{},"username":"root","passwordRef":"agentsshcli:draft"}}]"#,
            ssh_port
        )).unwrap();
        let body = serde_json::json!({
            "connection": "draft",
            "connections": [{"name":"draft","host":"127.0.0.1","port":ssh_port,"username":"root","passwordRef":"agentsshcli:draft"}],
            "passwordUpdates": [{"connection":"draft","password":"draft-secret"}]
        }).to_string();
        let request = format!(
            "POST /api/connections/test HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nX-Editor-Token: test-token\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let ssh_worker = std::thread::spawn(move || {
            let started = Instant::now();
            loop {
                match fake_ssh.accept() {
                    Ok((_peer, _)) => {
                        ready_tx.send(()).unwrap();
                        let _ = release_rx.recv_timeout(Duration::from_secs(3));
                        return;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && started.elapsed() < Duration::from_secs(3) =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("本地 SSH 测试监听失败: {}", error),
                }
            }
        });
        let first_path = path.clone();
        let first_request = request.clone();
        let first =
            std::thread::spawn(move || route_response_with_outcome(&first_request, &first_path));
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let status = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: test-token\r\n\r\n";
        assert!(route_response(status, &path).starts_with("HTTP/1.1 200"));
        assert!(route_response(&request, &path).starts_with("HTTP/1.1 409"));
        release_tx.send(()).unwrap();
        let (response, outcome) = first.join().unwrap();
        ssh_worker.join().unwrap();
        assert_eq!(outcome, ConnectionOutcome::Activity);
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("\"ok\":false"));
        let unauthorized = request.replace("X-Editor-Token: test-token", "X-Editor-Token: wrong");
        assert!(route_response(&unauthorized, &path).starts_with("HTTP/1.1 403"));
    }

    #[test]
    fn connection_outcome_distinguishes_activity_ignored_and_stop() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(
            &path,
            r#"[{"name":"server","host":"127.0.0.1","username":"root","privateKey":"/tmp/id"}]"#,
        )
        .unwrap();

        let root = "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n";
        assert_eq!(
            route_response_with_outcome(root, &path).1,
            ConnectionOutcome::Ignored
        );
        let (malformed_response, malformed_outcome) =
            route_response_with_outcome("broken\r\n\r\n", &path);
        assert!(malformed_response.starts_with("HTTP/1.1 400"));
        assert_eq!(malformed_outcome, ConnectionOutcome::Ignored);
        let activity = "POST /api/activity HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: test-token\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            route_response_with_outcome(activity, &path).1,
            ConnectionOutcome::Activity
        );
        let bad_token =
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: wrong\r\n\r\n";
        assert_eq!(
            route_response_with_outcome(bad_token, &path).1,
            ConnectionOutcome::Ignored
        );
        let missing = "GET /api/missing HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: test-token\r\n\r\n";
        assert_eq!(
            route_response_with_outcome(missing, &path).1,
            ConnectionOutcome::Ignored
        );
        let stop = "POST /api/stop HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: test-token\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            route_response_with_outcome(stop, &path).1,
            ConnectionOutcome::Stop
        );
    }

    #[test]
    fn route_boundary_enforces_host_origin_token_and_status_codes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(
            &path,
            r#"[{"name":"server","host":"127.0.0.1","username":"root","privateKey":"/tmp/id"}]"#,
        )
        .unwrap();
        let valid = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: test-token\r\n\r\n";
        assert!(route_response(valid, &path).starts_with("HTTP/1.1 200"));

        let bad_host =
            "GET /api/status HTTP/1.1\r\nHost: evil.test\r\nX-Editor-Token: test-token\r\n\r\n";
        assert!(route_response(bad_host, &path).starts_with("HTTP/1.1 403"));
        let bad_origin = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.test\r\nX-Editor-Token: test-token\r\n\r\n";
        assert!(route_response(bad_origin, &path).starts_with("HTTP/1.1 403"));
        let bad_token =
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: wrong\r\n\r\n";
        assert!(route_response(bad_token, &path).starts_with("HTTP/1.1 403"));
        let missing = "GET /api/missing HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Editor-Token: test-token\r\n\r\n";
        assert!(route_response(missing, &path).starts_with("HTTP/1.1 404"));
    }
}
