// CLI 层：参数结构体、help 文本、参数解析与子命令调度。
//
// 依赖方向：cli → config / daemon / exec / transfer；daemon 等下层模块不反向依赖本模块。

use crate::config::{
    default_config_path, ensure_privilege_enabled, find_connection, init_config, load_config,
    load_config_for_connection, load_config_for_execute, path_absolute_from,
    prepare_connection_config, prepare_privilege_config, resolve_pty, validate_command, Connection,
};
use crate::daemon::{
    request_daemon_execute, request_daemon_transfer, request_stop_daemon, run_daemon,
    DaemonClientConfig, DaemonExecRequest, DaemonTransferOperation, DaemonTransferRequest,
};
use crate::exec::{command_with_directory, execute_remote_command, ExecOutput};
use crate::privilege::PrivilegeMode;
use crate::transfer::{download_dir, download_file, upload_dir, upload_file};
use crate::{AppError, AppResult, JSON_OUTPUT_MODE};
// CLI 解析结果 → daemon 客户端配置（daemon 只接收自己的 DTO，不认识 CLI 类型）。
fn daemon_client_config(global: &GlobalArgs) -> DaemonClientConfig {
    DaemonClientConfig {
        config_path: global.config_path.clone(),
        cache_ttl_ms: global.cache_ttl_ms,
    }
}

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::Ordering;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

pub(crate) fn run(argv: Vec<String>) -> AppResult<()> {
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
        Some(ref directory) => command_with_directory(Some(directory), &command)?,
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
        let response = request_daemon_execute(&DaemonExecRequest {
            client: daemon_client_config(&parsed.global),
            connection_name: parsed.connection_name.clone(),
            command: command.clone(),
            directory: parsed.directory.clone(),
            timeout_ms: Some(parsed.timeout_ms),
            pty: parsed.pty,
            privilege: parsed.privilege,
        })?;
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
        request_daemon_transfer(&DaemonTransferRequest {
            client: daemon_client_config(&parsed.global),
            operation: DaemonTransferOperation::Upload,
            connection_name: parsed.connection_name.clone(),
            local_path: parsed.local_path.clone(),
            remote_path: parsed.remote_path.clone(),
            timeout_ms: parsed.timeout_ms,
            recursive: parsed.recursive,
        })?;
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
        request_daemon_transfer(&DaemonTransferRequest {
            client: daemon_client_config(&parsed.global),
            operation: DaemonTransferOperation::Download,
            connection_name: parsed.connection_name.clone(),
            local_path: parsed.local_path.clone(),
            remote_path: parsed.remote_path.clone(),
            timeout_ms: parsed.timeout_ms,
            recursive: parsed.recursive,
        })?;
    }
    if parsed.json_output {
        println!("{}", serde_json::json!({"exitCode": 0, "stdout": "File downloaded successfully", "stderr": ""}));
    } else {
        println!("File downloaded successfully");
    }
    Ok(())
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
        let parsed = parse_execute_args(vec![
            "--connection".into(),
            "server".into(),
            "--command-file".into(),
            "script.sh".into(),
        ])
        .unwrap();
        let command = resolve_execute_command(&[], &parsed).unwrap();
        env::set_current_dir(original_dir).unwrap();
        assert_eq!(command, "echo start\necho end\n");
    }
}
