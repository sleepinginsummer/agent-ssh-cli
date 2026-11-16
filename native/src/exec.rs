// 远端命令执行通道：负责在已建立的 SSH 会话上执行命令，并编排 sudo/su 提权。
//
// 与 `privilege.rs` 的分工：本模块处理会话、通道与密码写入时序等 I/O 行为，
// `privilege.rs` 只负责生成提权命令行字符串。

use crate::config::Connection;
use crate::privilege::{
    su_command, su_pty_command, sudo_command, sudo_passwordless_command, sudo_requires_tty,
    PrivilegeMode, SUDO_PROMPT_MARKER, SUDO_REQUIRE_TTY_PROBE, SU_PTY_PROBE,
};
use crate::runtime::run_with_timeout;
use crate::ssh::{connect_russh, RusshClient};
use crate::{AppError, AppResult};

use russh::{client, ChannelMsg, Disconnect};
use std::time::Duration;

// 远端命令执行结果：命令正常完成（无论退出码）时的结构化输出；
// 会话异常/连接失败仍以 Err 返回。
pub(crate) struct ExecOutput {
    pub(crate) exit_code: u32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug, Clone)]
struct CommandInput {
    data: Vec<u8>,
    // 部分提权实现（sudo 分配伪终端时）会输出自定义提示标记，
    // 需等到标记出现后再写入密码，避免密码被终端回显或提前丢弃。
    wait_for: Option<Vec<u8>>,
}

fn password_input(password: &str, wait_for: Option<&str>) -> AppResult<CommandInput> {
    if password
        .bytes()
        .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
    {
        return Err(AppError::new("sudo/su 密码不能包含换行符或 NUL"));
    }
    Ok(CommandInput {
        data: format!("{}\n", password).into_bytes(),
        wait_for: wait_for.map(|marker| marker.as_bytes().to_vec()),
    })
}
fn strip_first_marker(buffer: &mut Vec<u8>, marker: &[u8]) -> bool {
    let Some(index) = buffer
        .windows(marker.len())
        .position(|window| window == marker)
    else {
        return false;
    };
    buffer.drain(index..index + marker.len());
    true
}

fn consume_input_marker(input: &CommandInput, stdout: &mut Vec<u8>, stderr: &mut Vec<u8>) -> bool {
    let Some(marker) = input.wait_for.as_deref() else {
        return true;
    };
    strip_first_marker(stdout, marker) || strip_first_marker(stderr, marker)
}

async fn send_command_input(
    channel: &russh::Channel<client::Msg>,
    connection: &Connection,
    data: &[u8],
) -> AppResult<()> {
    channel.data(data).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 写入命令 stdin 失败: {}",
            connection.name, error
        ))
    })?;
    channel.eof().await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 关闭命令 stdin 失败: {}",
            connection.name, error
        ))
    })?;
    Ok(())
}

struct ChannelOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
}

async fn collect_channel_output(
    mut channel: russh::Channel<client::Msg>,
    connection: &Connection,
    input: Option<CommandInput>,
) -> AppResult<ChannelOutput> {
    let mut input_sent = false;
    if let Some(command_input) = input.as_ref() {
        if command_input.wait_for.is_none() {
            send_command_input(&channel, connection, &command_input.data).await?;
            input_sent = true;
        }
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    // 收到退出状态后只短暂等待 EOF，避免后台进程持有 stdout 导致通道永久不关闭。
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
        // PTY 的 SSH EOF 不等于终端输入 EOF。认证再次提示时不能继续等待，
        // 也不能重复发送同一密码；关闭本次通道并保留认证失败输出。
        if input_sent {
            if let Some(command_input) = input.as_ref().filter(|input| input.wait_for.is_some()) {
                if consume_input_marker(command_input, &mut stdout, &mut stderr) {
                    channel.close().await.map_err(|error| {
                        AppError::new(format!(
                            "连接 {} 关闭认证失败通道失败: {}",
                            connection.name, error
                        ))
                    })?;
                    stderr.extend_from_slice(
                        "\n[remote] 提权认证失败：发送密码后再次收到密码提示".as_bytes(),
                    );
                    exit_status = Some(1);
                    break;
                }
            }
        }
        if !input_sent {
            if let Some(command_input) = input.as_ref() {
                if consume_input_marker(command_input, &mut stdout, &mut stderr) {
                    send_command_input(&channel, connection, &command_input.data).await?;
                    input_sent = true;
                }
            }
        }
    }
    Ok(ChannelOutput {
        stdout,
        stderr,
        exit_status,
    })
}

async fn execute_remote_command_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_command: &str,
    pty: bool,
    input: Option<CommandInput>,
) -> AppResult<ExecOutput> {
    let channel = session.channel_open_session().await.map_err(|error| {
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

    let ChannelOutput {
        stdout,
        stderr,
        exit_status,
    } = collect_channel_output(channel, connection, input).await?;
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

async fn execute_sudo_command_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_command: &str,
    pty: bool,
) -> AppResult<ExecOutput> {
    let mut use_pty = pty;
    if !use_pty {
        let probe = execute_remote_command_with_session_async(
            session,
            connection,
            SUDO_REQUIRE_TTY_PROBE,
            false,
            None,
        )
        .await?;
        use_pty = sudo_requires_tty(&probe.stdout, &probe.stderr);
    }
    let (command, input) = match connection.sudo_password.as_deref() {
        Some(password) => (
            sudo_command(&connection.sudo_user, remote_command, use_pty),
            Some(password_input(
                password,
                use_pty.then_some(SUDO_PROMPT_MARKER),
            )?),
        ),
        // 无密码时不写入 stdin；NOPASSWD 或有效 sudo 缓存由远端自行判断。
        None => (
            sudo_passwordless_command(&connection.sudo_user, remote_command),
            None,
        ),
    };
    execute_remote_command_with_session_async(session, connection, &command, use_pty, input).await
}
// 仅对认证前的明确终端错误重试，普通命令失败与密码错误保持原样返回。
fn su_requires_tty(output: &ExecOutput) -> bool {
    output.exit_code != 0
        && output.stdout.is_empty()
        && matches!(
            output.stderr.trim(),
            "standard in must be a tty" | "su: standard in must be a tty"
        )
}

async fn execute_su_command_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_command: &str,
) -> AppResult<ExecOutput> {
    let password = connection
        .su_password
        .as_deref()
        .ok_or_else(|| AppError::new("su 凭据尚未解密"))?;
    let su_pty_probe =
        execute_remote_command_with_session_async(session, connection, SU_PTY_PROBE, false, None)
            .await?;
    if su_pty_probe.exit_code == 0 {
        let command = su_pty_command(&connection.su_user, remote_command);
        return execute_remote_command_with_session_async(
            session,
            connection,
            &command,
            false,
            Some(password_input(password, None)?),
        )
        .await;
    }
    // 保留旧版 util-linux 可用的管道路径；coreutils su 明确要求 tty 时才重试。
    // 此处尚未通过认证，目标命令未执行，因此重试不会重复执行用户命令。
    let command = su_command(&connection.su_user, remote_command);
    let output = execute_remote_command_with_session_async(
        session,
        connection,
        &command,
        false,
        Some(password_input(password, None)?),
    )
    .await?;
    if !su_requires_tty(&output) {
        return Ok(output);
    }
    // 固定认证提示语言，等 su 关闭回显并输出提示后再送密码，避免终端回显或冲刷输入。
    // /dev/null 重定向仍只在认证成功后的目标 shell 内生效。
    execute_remote_command_with_session_async(
        session,
        connection,
        &format!("LC_ALL=C {}", command),
        true,
        Some(password_input(password, Some("Password:"))?),
    )
    .await
}

pub(crate) async fn execute_remote_command_with_privilege_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_command: &str,
    pty: bool,
    privilege: Option<PrivilegeMode>,
) -> AppResult<ExecOutput> {
    match privilege {
        None => {
            execute_remote_command_with_session_async(
                session,
                connection,
                remote_command,
                pty,
                None,
            )
            .await
        }
        Some(PrivilegeMode::Sudo) => {
            execute_sudo_command_async(session, connection, remote_command, pty).await
        }
        Some(PrivilegeMode::Su) => {
            execute_su_command_async(session, connection, remote_command).await
        }
    }
}

async fn execute_remote_command_async(
    configs: &[Connection],
    connection: &Connection,
    remote_command: &str,
    pty: bool,
    privilege: Option<PrivilegeMode>,
) -> AppResult<ExecOutput> {
    let session = connect_russh(configs, connection).await?;
    let result = execute_remote_command_with_privilege_async(
        &session,
        connection,
        remote_command,
        pty,
        privilege,
    )
    .await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

pub(crate) fn execute_remote_command(
    configs: &[Connection],
    connection: &Connection,
    remote_command: &str,
    timeout_ms: u64,
    pty: bool,
    privilege: Option<PrivilegeMode>,
) -> AppResult<ExecOutput> {
    run_with_timeout(
        timeout_ms,
        execute_remote_command_async(configs, connection, remote_command, pty, privilege),
    )
}

// 组合远端命令：可选的目录切换前缀 + 命令本体。目录名按 JSON 字符串转义，
// 避免带空格/引号的路径破坏 `cd -- <dir> && <command>` 结构。
pub(crate) fn command_with_directory(directory: Option<&str>, command: &str) -> AppResult<String> {
    match directory {
        Some(directory) => Ok(format!(
            "cd -- {} && {}",
            serde_json::to_string(directory)?,
            command
        )),
        None => Ok(command.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn only_explicit_su_terminal_error_requests_retry() {
        let mut output = ExecOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "standard in must be a tty".into(),
        };
        assert!(su_requires_tty(&output));
        output.stderr = "su: Authentication failure".into();
        assert!(!su_requires_tty(&output));
        output.stderr = "standard in must be a tty".into();
        output.exit_code = 0;
        assert!(!su_requires_tty(&output));
        output.exit_code = 1;
        output.stdout = "command already ran".into();
        assert!(!su_requires_tty(&output));
    }

    #[test]
    fn password_prompt_can_span_packets_and_streams() {
        let input = password_input("test-password", Some("Password:")).unwrap();
        let mut stdout = b"Pass".to_vec();
        let mut stderr = Vec::new();
        assert!(!consume_input_marker(&input, &mut stdout, &mut stderr));
        stdout.extend_from_slice(b"word:");
        assert!(consume_input_marker(&input, &mut stdout, &mut stderr));
        assert!(stdout.is_empty());
        stderr.extend_from_slice(b"Password:");
        assert!(consume_input_marker(&input, &mut stdout, &mut stderr));
        assert!(stderr.is_empty());
        assert!(password_input("bad\npassword", None).is_err());
    }

    // 本机 SSH 服务模拟旧 su 的终端要求和认证提示，验证实际 channel 的时序及退出行为。
    struct AuthServer {
        mode: PrivilegeMode,
        reject: bool,
        terminals: HashSet<russh::ChannelId>,
        waiting: HashSet<russh::ChannelId>,
    }

    fn finish(
        session: &mut russh::server::Session,
        channel: russh::ChannelId,
        code: u32,
    ) -> Result<(), russh::Error> {
        session.exit_status_request(channel, code)?;
        session.eof(channel)?;
        session.close(channel)
    }

    impl russh::server::Handler for AuthServer {
        type Error = russh::Error;

        async fn auth_none(&mut self, _: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _: russh::Channel<russh::server::Msg>,
            _: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn pty_request(
            &mut self,
            channel: russh::ChannelId,
            _: &str,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.terminals.insert(channel);
            session.channel_success(channel)
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let command = std::str::from_utf8(data).unwrap();
            if command == SU_PTY_PROBE {
                return finish(session, channel, 1);
            }
            if !self.terminals.contains(&channel) {
                assert_eq!(command, su_command("root", "id -u"));
                session.extended_data(channel, 1, "standard in must be a tty\n")?;
                return finish(session, channel, 1);
            }
            let prompt = match self.mode {
                PrivilegeMode::Su => {
                    assert_eq!(command, format!("LC_ALL=C {}", su_command("root", "id -u")));
                    "Password:"
                }
                PrivilegeMode::Sudo => {
                    assert_eq!(command, sudo_command("root", "id -u", true));
                    SUDO_PROMPT_MARKER
                }
            };
            self.waiting.insert(channel);
            session.data(channel, &prompt.as_bytes()[..4])?;
            session.data(channel, &prompt.as_bytes()[4..])?;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            // 管道探测可能在报错关闭前收到密码；PTY 路径必须已发出提示且只能发送一次。
            if !self.terminals.contains(&channel) {
                return Ok(());
            }
            assert!(self.waiting.remove(&channel));
            assert_eq!(data, b"test-password\n");
            if self.reject {
                let prompt = match self.mode {
                    PrivilegeMode::Su => "Password:",
                    PrivilegeMode::Sudo => SUDO_PROMPT_MARKER,
                };
                session.data(channel, format!("Sorry, try again.\n{}", prompt))?;
                // 故意不退出，确保客户端能识别二次提示并及时关闭通道。
                Ok(())
            } else {
                session.data(channel, "0\n")?;
                finish(session, channel, 0)
            }
        }
    }

    #[test]
    fn ssh_channels_support_legacy_su_and_stop_repeated_password_prompts() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for (mode, reject) in [
                (PrivilegeMode::Su, false),
                (PrivilegeMode::Su, true),
                (PrivilegeMode::Sudo, false),
                (PrivilegeMode::Sudo, true),
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let mut config = russh::server::Config::default();
                config.keys.push(
                    russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into(),
                );
                let known_hosts_dir = tempfile::tempdir().unwrap();
                let known_hosts_path = known_hosts_dir.path().join("known_hosts");
                std::fs::write(
                    &known_hosts_path,
                    format!(
                        "[127.0.0.1]:{} {}\n",
                        address.port(),
                        config.keys[0].public_key().to_openssh().unwrap()
                    ),
                )
                .unwrap();
                let server_task = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    russh::server::run_stream(
                        Arc::new(config),
                        stream,
                        AuthServer {
                            mode,
                            reject,
                            terminals: HashSet::new(),
                            waiting: HashSet::new(),
                        },
                    )
                    .await
                    .unwrap()
                    .await
                    .unwrap();
                });
                let mut client = client::connect(
                    Arc::new(client::Config::default()),
                    address,
                    RusshClient::for_test(address.port(), known_hosts_path),
                )
                .await
                .unwrap();
                assert!(client.authenticate_none("test").await.unwrap().success());
                let (_directory, path) = crate::test_support::write_config(
                    r#"[{"name":"test","host":"127.0.0.1","username":"test","password":"test-password"}]"#,
                );
                let mut connections = crate::config::load_config(&path).unwrap();
                let connection = &mut connections[0];
                connection.su_password = Some("test-password".into());
                connection.sudo_password = Some("test-password".into());
                let output = tokio::time::timeout(
                    Duration::from_secs(3),
                    execute_remote_command_with_privilege_async(
                        &client,
                        connection,
                        "id -u",
                        true,
                        Some(mode),
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(output.exit_code, u32::from(reject));
                if reject {
                    assert!(output.stderr.contains("再次收到密码提示"));
                } else {
                    assert_eq!(output.stdout, "0");
                    assert!(!output.stdout.contains("test-password"));
                }
                client
                    .disconnect(Disconnect::ByApplication, "", "")
                    .await
                    .unwrap();
                drop(client);
                tokio::time::timeout(Duration::from_secs(3), server_task)
                    .await
                    .unwrap()
                    .unwrap();
            }
        });
    }
}
