// 远端命令执行通道：负责在已建立的 SSH 会话上执行命令，并编排 sudo/su 提权。
//
// 与 `privilege.rs` 的分工：本模块处理会话、通道与密码写入时序等 I/O 行为，
// `privilege.rs` 只负责生成提权命令行字符串。

use crate::privilege::{
    su_command, su_pty_command, sudo_command, sudo_requires_tty, PrivilegeMode, SUDO_PROMPT_MARKER,
    SUDO_REQUIRE_TTY_PROBE, SU_PTY_PROBE,
};
use crate::runtime::run_with_timeout;
use crate::ssh::{connect_russh, RusshClient};
use crate::{AppError, AppResult, Connection};
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
    let password = connection
        .sudo_password
        .as_deref()
        .ok_or_else(|| AppError::new("sudo 凭据尚未解密"))?;
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
    let command = sudo_command(&connection.sudo_user, remote_command, use_pty);
    let input = password_input(password, use_pty.then_some(SUDO_PROMPT_MARKER))?;
    execute_remote_command_with_session_async(session, connection, &command, use_pty, Some(input))
        .await
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
    // 无 -P/--pty 能力的旧版 su（CentOS 7 util-linux 2.23 等）：直接用管道 stdin 传密码，
    // 与 -P 路径及 sudo -S 路径一致，PAM 从非 tty stdin 逐字节读取密码，不受终端缓冲影响。
    // 不能改用 `script` 包一层 pty：script 在 stdin 非 tty 时 openpty 会拿到未初始化的
    // termios（实测 -icanon min=0 time=0），而 PAM 读取前执行 tcsetattr(TCSAFLUSH)
    // 会丢弃提示符之前到达的密码，su 只能收到空密码；同时该 pty 会话在 stdin EOF 时
    // 被 script 立即关闭并以状态 0 退出，表现为只有 Password: 的静默假成功。
    let command = su_command(&connection.su_user, remote_command);
    execute_remote_command_with_session_async(
        session,
        connection,
        &command,
        false,
        Some(password_input(password, None)?),
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
