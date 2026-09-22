// 编辑器 HTTP 层：请求解析、响应编码、安全校验与本地客户端请求。

use crate::{AppError, AppResult};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct HttpRequest {
    pub(super) method: String,
    pub(super) path: String,
    headers: HashMap<String, String>,
    pub(super) body: Vec<u8>,
}

#[derive(Debug)]
struct ParsedRequestHead {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    content_length: usize,
}

pub(super) fn read_request(stream: &mut TcpStream) -> AppResult<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (head_bytes, initial_body) = read_head_bytes(stream)?;
    let parsed = parse_request_head(&head_bytes)?;
    let body = read_body(stream, initial_body, parsed.content_length)?;
    Ok(HttpRequest {
        method: parsed.method,
        path: parsed.path,
        headers: parsed.headers,
        body,
    })
}

fn read_head_bytes(stream: &mut TcpStream) -> AppResult<(Vec<u8>, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(AppError::new("HTTP 请求提前结束"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_bytes(&buffer, b"\r\n\r\n") {
            let header_end = index + 4;
            if header_end > MAX_HEADER_BYTES {
                return Err(AppError::new("HTTP 请求头过大"));
            }
            let body = buffer.split_off(header_end);
            return Ok((buffer, body));
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(AppError::new("HTTP 请求头过大"));
        }
    }
}

fn parse_request_head(head: &[u8]) -> AppResult<ParsedRequestHead> {
    let header = std::str::from_utf8(head).map_err(|_| AppError::new("HTTP 请求头不是 UTF-8"))?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| AppError::new("HTTP 请求行缺失"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || target.is_empty() || version != "HTTP/1.1" || parts.next().is_some() {
        return Err(AppError::new("HTTP 请求行无效"));
    }

    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| AppError::new("HTTP 请求头格式无效"))?;
        let name = name.trim().to_ascii_lowercase();
        if headers.insert(name, value.trim().to_string()).is_some() {
            return Err(AppError::new("HTTP 请求头重复"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(AppError::new("不支持 Transfer-Encoding"));
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| AppError::new("Content-Length 无效"))?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(AppError::new("HTTP 请求体过大"));
    }
    Ok(ParsedRequestHead {
        method,
        path: target.split('?').next().unwrap_or_default().to_string(),
        headers,
        content_length,
    })
}

fn read_body(
    stream: &mut TcpStream,
    mut body: Vec<u8>,
    content_length: usize,
) -> AppResult<Vec<u8>> {
    let mut chunk = [0_u8; 4096];
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(AppError::new("HTTP 请求体提前结束"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(body)
}

pub(super) fn validate_origin(request: &HttpRequest, port: u16) -> AppResult<()> {
    let host = request
        .headers
        .get("host")
        .map(String::as_str)
        .unwrap_or_default();
    let allowed = [format!("127.0.0.1:{}", port), format!("localhost:{}", port)];
    if !allowed.iter().any(|item| item == host) {
        return Err(AppError::new("拒绝非回环 Host"));
    }
    if let Some(origin) = request.headers.get("origin") {
        let allowed_origins = [
            format!("http://127.0.0.1:{}", port),
            format!("http://localhost:{}", port),
        ];
        if !allowed_origins.iter().any(|item| item == origin) {
            return Err(AppError::new("拒绝跨来源请求"));
        }
    }
    Ok(())
}

pub(super) fn validate_token(request: &HttpRequest, expected: &str) -> AppResult<()> {
    let actual = request
        .headers
        .get("x-editor-token")
        .map(String::as_str)
        .unwrap_or_default();
    if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        return Err(AppError::new("编辑器令牌无效"));
    }
    Ok(())
}

pub(super) fn write_json(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
) -> AppResult<()> {
    let body = serde_json::to_vec(value)?;
    write_response(stream, status, "application/json; charset=utf-8", &body)
}

pub(super) fn write_json_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> AppResult<()> {
    write_json(stream, status, &serde_json::json!({"error": message}))
}

pub(super) fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> AppResult<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

pub(super) fn send_request(
    port: u16,
    method: &str,
    path: &str,
    token: &str,
    body: &[u8],
) -> AppResult<u16> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port)
            .parse()
            .map_err(|_| AppError::new("编辑器地址无效"))?,
        Duration::from_secs(1),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Editor-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        path,
        port,
        token,
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    parse_response_status(&response)
}

fn parse_response_status(response: &str) -> AppResult<u16> {
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| AppError::new("编辑器 HTTP 响应缺少状态行"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(AppError::new("编辑器 HTTP 响应版本无效"));
    }
    status
        .parse::<u16>()
        .map_err(|_| AppError::new("编辑器 HTTP 响应状态码无效"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_comparison_requires_equal_content_and_length() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"other"));
        assert!(!constant_time_eq(b"token", b"token-long"));
    }

    #[test]
    fn finds_http_header_boundary() {
        assert_eq!(find_bytes(b"GET / HTTP/1.1\r\n\r\n", b"\r\n\r\n"), Some(14));
    }

    #[test]
    fn parses_client_response_status() {
        assert_eq!(
            parse_response_status("HTTP/1.1 200 OK\r\n\r\n").unwrap(),
            200
        );
        assert!(parse_response_status("not-http").is_err());
    }

    #[test]
    fn parses_request_head_without_socket_io() {
        let parsed = parse_request_head(
            b"POST /api/config?ignored=1 HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nContent-Length: 7\r\n\r\n",
        )
        .unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/api/config");
        assert_eq!(parsed.content_length, 7);
    }

    #[test]
    fn rejects_duplicate_and_chunked_request_headers() {
        let duplicate = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
        assert!(parse_request_head(duplicate)
            .unwrap_err()
            .to_string()
            .contains("重复"));
        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_request_head(chunked)
            .unwrap_err()
            .to_string()
            .contains("Transfer-Encoding"));
    }

    #[test]
    fn rejects_invalid_origin_and_token() {
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/config".to_string(),
            headers: HashMap::from([
                ("host".to_string(), "evil.test".to_string()),
                ("x-editor-token".to_string(), "wrong".to_string()),
            ]),
            body: Vec::new(),
        };
        assert!(validate_origin(&request, 1234).is_err());
        assert!(validate_token(&request, "expected").is_err());
    }
}
