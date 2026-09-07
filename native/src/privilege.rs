use serde::{Deserialize, Serialize};

pub const SUDO_PROMPT_MARKER: &str = "__AGENTSSHCLI_SUDO_PASSWORD__";
pub const SU_READY_MARKER: &str = "__AGENTSSHCLI_SU_READY__";
pub const SUDO_REQUIRE_TTY_PROBE: &str = "sudo -n true";
pub const SU_PTY_PROBE: &str =
    "su --help 2>&1 | grep -Eq -- '(^|[[:space:],])-P([,[:space:]]|$)|--pty'";
pub const SCRIPT_FALLBACK_PROBE: &str =
    "script --help 2>&1 | grep -q -- '--command' && script --help 2>&1 | grep -q -- '--return'";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeMode {
    Sudo,
    Su,
}

pub struct CredentialFields {
    pub password: &'static str,
    pub password_ref: &'static str,
    pub reference_suffix: &'static str,
}

pub fn credential_fields(mode: PrivilegeMode) -> CredentialFields {
    match mode {
        PrivilegeMode::Sudo => CredentialFields {
            password: "sudoPassword",
            password_ref: "sudoPasswordRef",
            reference_suffix: ":sudo",
        },
        PrivilegeMode::Su => CredentialFields {
            password: "suPassword",
            password_ref: "suPasswordRef",
            reference_suffix: ":su",
        },
    }
}

pub fn validate_unix_username(user: &str) -> bool {
    let mut chars = user.chars();
    let valid_start = chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase());
    valid_start
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

pub fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn inner_command(command: &str) -> String {
    // 提权命令不支持交互 stdin。主动关闭 stdin 可避免 NOPASSWD 时密码流入目标程序。
    format!("exec </dev/null; {}", command)
}

pub fn sudo_command(user: &str, command: &str, use_pty: bool) -> String {
    let prompt = if use_pty { SUDO_PROMPT_MARKER } else { "" };
    format!(
        "sudo -S -p {} -u {} -- sh -c {}",
        shell_single_quote(prompt),
        user,
        shell_single_quote(&inner_command(command))
    )
}

pub fn su_pty_command(user: &str, command: &str) -> String {
    format!(
        "su -P -c {} {}",
        shell_single_quote(&inner_command(command)),
        user
    )
}

pub fn su_script_command(user: &str, command: &str) -> String {
    let su_command = format!(
        "su -c {} {}",
        shell_single_quote(&inner_command(command)),
        user
    );
    // script 的子终端先关闭 ECHO 并输出同步标记，调用方看到标记后才发送密码。
    let script_inner = format!(
        "stty -echo; printf %s {}; exec {}",
        shell_single_quote(SU_READY_MARKER),
        su_command
    );
    format!(
        "script -q -e -c {} /dev/null",
        shell_single_quote(&script_inner)
    )
}

pub fn sudo_requires_tty(stdout: &str, stderr: &str) -> bool {
    let message = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
    message.contains("requiretty")
        || message.contains("must have a tty")
        || message.contains("terminal is required")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_supported_unix_usernames() {
        assert!(validate_unix_username("root"));
        assert!(validate_unix_username("app-user_2"));
        assert!(!validate_unix_username("Root"));
        assert!(!validate_unix_username("root; id"));
        assert!(!validate_unix_username(""));
    }

    #[test]
    fn quotes_single_quotes_as_one_shell_argument() {
        assert_eq!(
            shell_single_quote("echo 'hello'"),
            "'echo '\"'\"'hello'\"'\"''"
        );
    }

    #[test]
    fn sudo_wraps_the_complete_command() {
        let command = sudo_command("root", "id && cat /root/file", false);
        assert_eq!(
            command,
            "sudo -S -p '' -u root -- sh -c 'exec </dev/null; id && cat /root/file'"
        );
    }

    #[test]
    fn su_script_waits_until_echo_is_disabled() {
        let command = su_script_command("oracle", "echo 'hello'");
        assert!(command.contains("stty -echo; printf %s"));
        assert!(command.contains(SU_READY_MARKER));
        assert!(command.contains("su -c"));
    }
}
