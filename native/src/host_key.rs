// 主机密钥登记：独立核实指纹后，通过 SSH 握手取得公钥并写入 known_hosts。
// SSH 通道与握手配置仍由 ssh 模块负责；此处不认证目标机或执行命令。

use crate::config::{home_dir, Connection};
use crate::ssh::{open_connection_stream, ssh_client_config};
use crate::{AppError, AppResult};
use russh::client;
use russh::keys::ssh_key::{Fingerprint, HashAlg, PublicKey};
use std::path::Path;
use std::sync::Arc;

struct HostKeyProbe {
    key_sender: Option<tokio::sync::oneshot::Sender<PublicKey>>,
}

impl client::Handler for HostKeyProbe {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .key_sender
            .take()
            .is_some_and(|sender| sender.send(server_public_key.clone()).is_ok()))
    }
}

fn register_host_key(
    connection: &Connection,
    key: &PublicKey,
    known_hosts_path: &Path,
) -> AppResult<bool> {
    // 不覆盖已有记录，也不默默接受同一主机的其他算法公钥。
    let recorded = russh::keys::known_hosts::known_host_keys_path(
        &connection.host,
        connection.port,
        known_hosts_path,
    )
    .map_err(|error| AppError::new(format!("读取 known_hosts 失败: {}", error)))?;
    if recorded.iter().any(|(_, saved)| saved != key) {
        return Err(AppError::new(format!(
            "连接 {} 在 {} 已有不同的公钥；未覆盖旧记录",
            connection.name,
            known_hosts_path.display()
        )));
    }
    if recorded.is_empty() {
        russh::keys::known_hosts::learn_known_hosts_path(
            &connection.host,
            connection.port,
            key,
            known_hosts_path,
        )
        .map_err(|error| AppError::new(format!("写入 known_hosts 失败: {}", error)))?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn trust_host(
    configs: &[Connection],
    connection: &Connection,
    expected: &str,
) -> AppResult<String> {
    let known_hosts_path = home_dir()
        .ok_or_else(|| AppError::new("无法确定用户主目录，不能登记 SSH 服务器公钥"))?
        .join(".ssh")
        .join("known_hosts");
    trust_host_at_path(configs, connection, expected, &known_hosts_path)
}

fn trust_host_at_path(
    configs: &[Connection],
    connection: &Connection,
    expected: &str,
    known_hosts_path: &Path,
) -> AppResult<String> {
    let expected: Fingerprint = expected
        .parse()
        .map_err(|_| AppError::new("--fingerprint 必须是有效的 SHA256:<digest> 指纹"))?;
    if expected.algorithm() != HashAlg::Sha256 {
        return Err(AppError::new("--fingerprint 仅支持 SHA256 指纹"));
    }
    crate::runtime::run_with_timeout(15000, async {
        // 跳板机仍走现有的已受信任连接；目标机不进行认证。
        let stream = open_connection_stream(configs, connection).await?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let session = client::connect_stream(
            Arc::new(ssh_client_config()),
            stream,
            HostKeyProbe {
                key_sender: Some(sender),
            },
        )
        .await
        .map_err(|error| {
            AppError::new(format!(
                "读取 {} 的 SSH 公钥失败: {}",
                connection.name, error
            ))
        })?;
        let key = receiver
            .await
            .map_err(|_| AppError::new("SSH 握手未返回服务器公钥"))?;
        session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(|error| AppError::new(format!("关闭 SSH 探测连接失败: {}", error)))?;
        let actual = key.fingerprint(HashAlg::Sha256);
        if actual != expected {
            return Err(AppError::new(format!(
                "连接 {} 的公钥指纹不符：期望 {}，收到 {}；未登记",
                connection.name, expected, actual
            )));
        }
        let added = register_host_key(connection, &key, known_hosts_path)?;
        Ok(format!(
            "连接 {} 的公钥指纹 {} {} {}",
            connection.name,
            actual,
            if added { "已登记到" } else { "已在" },
            known_hosts_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config;
    use crate::test_support::write_config;
    use std::time::Duration;

    #[test]
    fn registration_is_idempotent_and_rejects_changed_key() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = directory.path().join(".ssh").join("known_hosts");
        let (_config_dir, config_path) = write_config(
            r#"[{"name":"server","host":"127.0.0.1","port":9988,"username":"test","password":"test"}]"#,
        );
        let configs = load_config(&config_path).unwrap();
        let connection = &configs[0];
        let key = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]);
        let key: russh::keys::ssh_key::PrivateKey = key.into();
        let other: russh::keys::ssh_key::PrivateKey =
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[8; 32]).into();
        assert!(register_host_key(connection, key.public_key(), &known_hosts).unwrap());
        let content = std::fs::read_to_string(&known_hosts).unwrap();
        assert!(content
            .trim_start()
            .starts_with("[127.0.0.1]:9988 ssh-ed25519 "));
        assert!(!register_host_key(connection, key.public_key(), &known_hosts).unwrap());
        assert_eq!(std::fs::read_to_string(&known_hosts).unwrap(), content);
        assert!(
            register_host_key(connection, other.public_key(), &known_hosts)
                .unwrap_err()
                .to_string()
                .contains("已有不同的公钥")
        );
        assert_eq!(std::fs::read_to_string(&known_hosts).unwrap(), content);
        assert!(trust_host_at_path(&configs, connection, "SHA256:invalid", &known_hosts).is_err());
        assert_eq!(std::fs::read_to_string(&known_hosts).unwrap(), content);
    }

    struct ProbeServer;

    impl russh::server::Handler for ProbeServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _username: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            panic!("主机密钥探测不应进行目标机认证");
        }
    }

    #[test]
    fn trust_host_checks_fingerprint_before_recording_without_authenticating() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = directory.path().join("known_hosts");
        let private_key: russh::keys::PrivateKey =
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into();
        let expected = private_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let wrong: russh::keys::PrivateKey =
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[10; 32]).into();
        let wrong_fingerprint = wrong.public_key().fingerprint(HashAlg::Sha256).to_string();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let mut server_config = russh::server::Config::default();
                server_config.keys.push(private_key);
                let server_config = Arc::new(server_config);
                for _ in 0..3 {
                    let (stream, _) =
                        tokio::time::timeout(Duration::from_secs(5), listener.accept())
                            .await
                            .unwrap()
                            .unwrap();
                    let session =
                        russh::server::run_stream(server_config.clone(), stream, ProbeServer)
                            .await
                            .unwrap();
                    // 无认证探测主动断开时，服务端可能以 IO 断开错误结束。
                    match tokio::time::timeout(Duration::from_secs(5), session)
                        .await
                        .unwrap()
                    {
                        Ok(()) | Err(russh::Error::IO(_)) => {}
                        Err(error) => panic!("探测服务端错误: {}", error),
                    }
                }
            });
        });
        let (_config_dir, config_path) = write_config(&format!(
            r#"[{{"name":"test","host":"127.0.0.1","port":{},"username":"test-user","password":"test-password"}}]"#,
            port
        ));
        let configs = load_config(&config_path).unwrap();
        let connection = &configs[0];
        let mismatch =
            trust_host_at_path(&configs, connection, &wrong_fingerprint, &known_hosts).unwrap_err();
        assert!(mismatch.to_string().contains("指纹不符"));
        assert!(!known_hosts.exists());
        assert!(
            trust_host_at_path(&configs, connection, &expected, &known_hosts)
                .unwrap()
                .contains("已登记")
        );
        let content = std::fs::read_to_string(&known_hosts).unwrap();
        assert!(content
            .trim_start()
            .starts_with(&format!("[127.0.0.1]:{} ", port)));
        assert!(
            trust_host_at_path(&configs, connection, &expected, &known_hosts)
                .unwrap()
                .contains("已在")
        );
        assert_eq!(std::fs::read_to_string(&known_hosts).unwrap(), content);
        server.join().unwrap();
    }
}
