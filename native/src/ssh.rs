// SSH 传输层：建立到目标机的连接（直连 / SOCKS5 代理 / 跳板机直连通道）并完成认证。
//
// 与 `exec.rs` 的分工：本模块只负责把会话建好，命令执行与提权编排由 `exec.rs` 负责。

use crate::{find_connection, AppError, AppResult, Connection};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{client, Preferred};
use std::borrow::Cow;
use std::net::IpAddr;
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

pub(crate) struct RusshClient;

impl client::Handler for RusshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub(crate) async fn connect_russh(
    configs: &[Connection],
    connection: &Connection,
) -> AppResult<client::Handle<RusshClient>> {
    let stream = open_connection_stream(configs, connection).await?;
    connect_russh_over_stream(connection, stream).await
}

async fn connect_russh_direct(connection: &Connection) -> AppResult<client::Handle<RusshClient>> {
    let stream: Box<dyn SshStream> = if connection.socks_proxy.is_some() {
        Box::new(connect_socks_proxy(connection).await?)
    } else {
        Box::new(tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?)
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
    let mut session = client::connect_stream(Arc::new(config), stream, RusshClient)
        .await
        .map_err(|error| {
            AppError::new(format!("连接 {} 建立 SSH 失败: {}", connection.name, error))
        })?;
    authenticate_russh(connection, &mut session).await?;
    Ok(session)
}

async fn open_connection_stream(
    configs: &[Connection],
    connection: &Connection,
) -> AppResult<Box<dyn SshStream>> {
    if let Some(jump_name) = connection.jump_host.as_deref() {
        let jump = find_connection(configs, jump_name)?;
        let jump_session = connect_russh_direct(jump).await?;
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
        return Ok(Box::new(channel.into_stream()));
    }
    if connection.socks_proxy.is_some() {
        return Ok(Box::new(connect_socks_proxy(connection).await?));
    }
    Ok(Box::new(
        tokio::net::TcpStream::connect((connection.host.as_str(), connection.port)).await?,
    ))
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

    #[test]
    fn socks_proxy_supports_host_port_without_scheme() {
        let proxy = parse_socks_proxy("127.0.0.1:1080").unwrap();
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
    }
}
