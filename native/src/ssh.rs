// SSH 传输层：建立到目标机的连接（直连 / SOCKS5 代理 / 跳板机直连通道）并完成认证。
//
// 与 `exec.rs` 的分工：本模块只负责把会话建好，命令执行与提权编排由 `exec.rs` 负责。

use crate::config::{find_connection, home_dir, Connection};
use crate::{AppError, AppResult};

use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{client, Preferred};
use std::borrow::Cow;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

#[derive(Debug)]
struct SocksProxy {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

trait SshStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> SshStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

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

pub(crate) struct RusshClient {
    host: String,
    port: u16,
    known_hosts_path: PathBuf,
}

impl client::Handler for RusshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // 在密码或私钥认证前核对目标与跳板机各自的主机公钥；未知主机不得自动信任。
        russh::keys::known_hosts::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts_path,
        )
        .map_err(Into::into)
    }
}

pub(crate) async fn connect_russh(
    configs: &[Connection],
    connection: &Connection,
) -> AppResult<client::Handle<RusshClient>> {
    let stream = open_connection_stream(configs, connection).await?;
    connect_russh_over_stream(connection, stream).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectConnectionTransport {
    Direct,
    TargetSocks,
}

// 直连只考虑当前连接自身的 SOCKS5；用于跳板机时不会递归处理其 jumpHost。
fn direct_connection_transport(connection: &Connection) -> DirectConnectionTransport {
    if connection.socks_proxy.is_some() {
        DirectConnectionTransport::TargetSocks
    } else {
        DirectConnectionTransport::Direct
    }
}

#[derive(Debug, Clone, Copy)]
enum ConnectionTransport<'a> {
    Direct,
    TargetSocks,
    Jump {
        connection: &'a Connection,
        transport: DirectConnectionTransport,
    },
}

// 目标 jumpHost 优先于目标 socksProxy，返回值同时驱动真实建连与共享契约测试。
fn connection_transport<'a>(
    configs: &'a [Connection],
    connection: &Connection,
) -> AppResult<ConnectionTransport<'a>> {
    if let Some(jump_name) = connection.jump_host.as_deref() {
        let jump = find_connection(configs, jump_name)?;
        return Ok(ConnectionTransport::Jump {
            connection: jump,
            transport: direct_connection_transport(jump),
        });
    }
    Ok(match direct_connection_transport(connection) {
        DirectConnectionTransport::Direct => ConnectionTransport::Direct,
        DirectConnectionTransport::TargetSocks => ConnectionTransport::TargetSocks,
    })
}

async fn connect_russh_direct(
    connection: &Connection,
    transport: DirectConnectionTransport,
) -> AppResult<client::Handle<RusshClient>> {
    let stream: Box<dyn SshStream> = match transport {
        DirectConnectionTransport::TargetSocks => Box::new(connect_socks_proxy(connection).await?),
        DirectConnectionTransport::Direct => Box::new(
            tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?,
        ),
    };
    connect_russh_over_stream(connection, stream).await
}

async fn connect_russh_over_stream(
    connection: &Connection,
    stream: Box<dyn SshStream>,
) -> AppResult<client::Handle<RusshClient>> {
    let config = client::Config {
        // SSH 连接空闲超时：30s 过短，慢速大文件传输或长任务可能被误断，放宽到 5 分钟。
        inactivity_timeout: Some(Duration::from_secs(300)),
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
    let known_hosts_path = home_dir()
        .ok_or_else(|| AppError::new("无法确定用户主目录，不能校验 SSH 服务器公钥"))?
        .join(".ssh")
        .join("known_hosts");
    let handler = RusshClient {
        host: connection.host.clone(),
        port: connection.port,
        known_hosts_path: known_hosts_path.clone(),
    };
    let mut session = client::connect_stream(Arc::new(config), stream, handler)
        .await
        .map_err(|error| match error {
            russh::Error::UnknownKey => AppError::new(format!(
                "连接 {} 的服务器公钥未在 {} 登记（{}:{}）；请先独立核实服务器指纹并登记",
                connection.name,
                known_hosts_path.display(),
                connection.host,
                connection.port
            )),
            russh::Error::Keys(russh::keys::Error::KeyChanged { line }) => AppError::new(format!(
                "连接 {} 的服务器公钥与 {} 第 {} 行不符；请先核实服务器身份，勿直接覆盖旧记录",
                connection.name,
                known_hosts_path.display(),
                line
            )),
            _ => AppError::new(format!("连接 {} 建立 SSH 失败: {}", connection.name, error)),
        })?;
    authenticate_russh(connection, &mut session).await?;
    Ok(session)
}

async fn open_connection_stream(
    configs: &[Connection],
    connection: &Connection,
) -> AppResult<Box<dyn SshStream>> {
    match connection_transport(configs, connection)? {
        ConnectionTransport::Jump {
            connection: jump,
            transport,
        } => {
            let jump_session = connect_russh_direct(jump, transport).await?;
            let channel = jump_session
                .channel_open_direct_tcpip(
                    connection.host.clone(),
                    u32::from(connection.port),
                    "127.0.0.1",
                    0,
                )
                .await
                .map_err(|error| {
                    AppError::new(format!(
                        "连接 {} 通过跳板机 {} 打开直连通道失败: {}",
                        connection.name, jump.name, error
                    ))
                })?;
            Ok(Box::new(channel.into_stream()))
        }
        ConnectionTransport::TargetSocks => Ok(Box::new(connect_socks_proxy(connection).await?)),
        ConnectionTransport::Direct => Ok(Box::new(
            tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?,
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::load_config;
    use crate::test_support::write_config;
    use serde::Deserialize;

    #[test]
    fn server_key_requires_matching_known_host_and_port() {
        use russh::client::Handler as _;

        let directory = tempfile::tempdir().unwrap();
        let known_hosts_path = directory.path().join("known_hosts");
        let trusted = russh::keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .unwrap();
        let changed = russh::keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        std::fs::write(
            &known_hosts_path,
            format!("[localhost]:13265 {}\n", trusted.to_openssh().unwrap()),
        )
        .unwrap();
        let mut handler = RusshClient {
            host: "localhost".into(),
            port: 13265,
            known_hosts_path,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(runtime
            .block_on(handler.check_server_key(&trusted))
            .unwrap());
        assert!(runtime
            .block_on(handler.check_server_key(&changed))
            .is_err());
        handler.port = 22;
        assert!(!runtime
            .block_on(handler.check_server_key(&trusted))
            .unwrap());
        handler.port = 13265;
        handler.host = "different-host".into();
        assert!(!runtime
            .block_on(handler.check_server_key(&trusted))
            .unwrap());
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RouteCase {
        name: String,
        target: String,
        connections: serde_json::Value,
        expected_transport: String,
        expected_jump_transport: Option<String>,
    }

    fn direct_transport_name(transport: DirectConnectionTransport) -> &'static str {
        match transport {
            DirectConnectionTransport::Direct => "direct",
            DirectConnectionTransport::TargetSocks => "targetSocks",
        }
    }

    #[test]
    fn connection_transport_matches_shared_editor_contract() {
        let cases: Vec<RouteCase> =
            serde_json::from_str(include_str!("../testdata/editor-route-cases.json",)).unwrap();
        for case in cases {
            let raw = serde_json::to_string(&case.connections).unwrap();
            let (_dir, path) = write_config(&raw);
            let configs = load_config(&path).unwrap();
            let target = find_connection(&configs, &case.target).unwrap();
            let transport = connection_transport(&configs, target).unwrap();
            let (actual, jump_transport) = match transport {
                ConnectionTransport::Direct => ("direct", None),
                ConnectionTransport::TargetSocks => ("targetSocks", None),
                ConnectionTransport::Jump { transport, .. } => {
                    ("jump", Some(direct_transport_name(transport)))
                }
            };
            assert_eq!(actual, case.expected_transport, "{}", case.name);
            assert_eq!(
                jump_transport,
                case.expected_jump_transport.as_deref(),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn socks_proxy_supports_host_port_without_scheme() {
        let proxy = parse_socks_proxy("127.0.0.1:1080").unwrap();
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
    }

    struct PasswordServer;

    impl russh::server::Handler for PasswordServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            username: &str,
            password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            if username == "test-user" && password == "test-password" {
                Ok(russh::server::Auth::Accept)
            } else {
                Ok(russh::server::Auth::reject())
            }
        }
    }

    #[test]
    fn registered_server_key_allows_password_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts_path = directory.path().join("known_hosts");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let private_key: russh::keys::PrivateKey =
                russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]).into();
            std::fs::write(
                &known_hosts_path,
                format!(
                    "[127.0.0.1]:{} {}\n",
                    port,
                    private_key.public_key().to_openssh().unwrap()
                ),
            )
            .unwrap();
            let mut server_config = russh::server::Config::default();
            server_config.keys.push(private_key);
            let server_config = Arc::new(server_config);
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let session = russh::server::run_stream(server_config, stream, PasswordServer)
                    .await
                    .unwrap();
                session.await.unwrap();
            });
            let (_dir, config_path) = write_config(&format!(
                r#"[{{"name":"test","host":"127.0.0.1","port":{},"username":"test-user","password":"test-password"}}]"#,
                port
            ));
            let configs = load_config(&config_path).unwrap();
            let connection = &configs[0];
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let handler = RusshClient {
                host: connection.host.clone(),
                port: connection.port,
                known_hosts_path,
            };
            let mut client = client::connect_stream(Arc::new(client::Config::default()), stream, handler)
                .await
                .unwrap();
            authenticate_russh(connection, &mut client).await.unwrap();
            client
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await
                .unwrap();
            drop(client);
            tokio::time::timeout(Duration::from_secs(3), server_task)
                .await
                .unwrap()
                .unwrap();
        });
    }
}
