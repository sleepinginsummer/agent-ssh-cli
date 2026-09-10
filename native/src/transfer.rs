// 文件传输：SFTP 上传/下载、断点续传元数据、递归目录传输与进度输出。
//
// 依赖 `ssh` 提供的会话与 `runtime` 的超时封装；CLI 与 daemon 两条路径复用同一实现。

use crate::runtime::{block_with_timeout, run_with_timeout};
use crate::ssh::{connect_russh, RusshClient};
use crate::{AppError, AppResult};
use crate::config::{Connection};

use russh::{client, Disconnect};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadResumeMeta {
    file_size: u64,
    modified_ms: u64,
    chunk_bytes: usize,
}

const TRANSFER_CHUNK_BYTES: usize = 1024 * 1024;
const TRANSFER_MAX_RETRIES: usize = 3;

async fn open_sftp_session(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
) -> AppResult<SftpSession> {
    let channel = session.channel_open_session().await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 打开 SFTP 会话失败: {}",
            connection.name, error
        ))
    })?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 请求 SFTP 子系统失败: {}",
                connection.name, error
            ))
        })?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 初始化 SFTP 失败: {}",
                connection.name, error
            ))
        })
}

// 取远端路径的父目录；路径不含目录分隔符时返回 None（等价于 SFTP 会话当前工作目录，无需检查）。
fn remote_parent_path(remote_path: &str) -> Option<String> {
    let trimmed = remote_path.trim_end_matches('/');
    let index = trimmed.rfind('/')?;
    if index == 0 {
        return Some("/".to_string());
    }
    Some(trimmed[..index].to_string())
}

// 单文件上传前确认父目录可用：远端目录不存在时会报“创建远端续传元数据失败: No such file”，
// 指向性差且会白白重试 3 次，这里提前失败并给出可操作提示。
async fn ensure_remote_parent_dir(sftp: &SftpSession, remote_path: &str) -> AppResult<()> {
    let Some(parent) = remote_parent_path(remote_path) else {
        return Ok(());
    };
    // metadata 成功不等于父路径就是目录（同名文件会挡住），必须显式判断类型。
    let parent_is_dir = sftp
        .metadata(parent.clone())
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    if parent_is_dir {
        return Ok(());
    }
    Err(AppError::new(format!(
        "远端目录不存在或不可访问: {}（单文件上传不会自动创建目录，请先创建该目录，或改用 --recursive 上传整个目录）",
        parent
    )))
}

fn temporary_remote_path(remote_path: &str) -> String {
    format!("{}.part", remote_path)
}

fn temporary_remote_meta_path(remote_path: &str) -> String {
    format!("{}.part.meta", remote_path)
}

fn build_upload_resume_meta(metadata: &std::fs::Metadata) -> UploadResumeMeta {
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    UploadResumeMeta {
        file_size: metadata.len(),
        modified_ms,
        chunk_bytes: TRANSFER_CHUNK_BYTES,
    }
}

pub(crate) async fn upload_file_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
) -> AppResult<()> {
    let local_metadata = fs::metadata(local_path)?;
    let resume_meta = build_upload_resume_meta(&local_metadata);
    let file_size = resume_meta.file_size;
    let temp_remote_path = temporary_remote_path(remote_path);
    let temp_remote_meta_path = temporary_remote_meta_path(remote_path);
    let mut last_error: Option<AppError> = None;

    // SFTP 传输不再设置总超时：大文件允许长时间运行，失败时按整次上传重试。
    for attempt in 1..=TRANSFER_MAX_RETRIES {
        let sftp = open_sftp_session(session, connection).await?;
        if attempt == 1 {
            // 父目录缺失属确定性失败（单文件上传不会自动创建目录），
            // 复用本次会话提前失败：既给出可操作报错，也不额外开 SFTP subsystem、不做无谓重试。
            if let Err(error) = ensure_remote_parent_dir(&sftp, remote_path).await {
                let _ = sftp.close().await;
                return Err(error);
            }
        }
        let upload_result = upload_file_once(
            &sftp,
            connection,
            local_path,
            remote_path,
            &temp_remote_path,
            &temp_remote_meta_path,
            &resume_meta,
            file_size,
            attempt,
        )
        .await;
        let _ = sftp.close().await;

        match upload_result {
            Ok(()) => return Ok(()),
            Err(error) if attempt < TRANSFER_MAX_RETRIES => {
                eprintln!(
                    "上传失败，准备重试 {}/{}: {}",
                    attempt + 1,
                    TRANSFER_MAX_RETRIES,
                    error
                );
                last_error = Some(error);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(AppError::new(format!(
        "上传失败，已重试 {} 次: {}",
        TRANSFER_MAX_RETRIES,
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "未知错误".to_string())
    )))
}

async fn upload_file_once(
    sftp: &SftpSession,
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
    temp_remote_path: &str,
    temp_remote_meta_path: &str,
    resume_meta: &UploadResumeMeta,
    file_size: u64,
    attempt: usize,
) -> AppResult<()> {
    ensure_upload_resume_meta(sftp, temp_remote_path, temp_remote_meta_path, resume_meta).await?;
    let resume_offset = resolve_upload_resume_offset(sftp, temp_remote_path, file_size).await?;
    let mut local_file = tokio::fs::File::open(local_path).await?;
    if resume_offset > 0 {
        local_file.seek(SeekFrom::Start(resume_offset)).await?;
        eprintln!(
            "发现远端临时文件，断点续传: {}/{} bytes",
            resume_offset, file_size
        );
    }

    let open_flags = if resume_offset > 0 {
        OpenFlags::CREATE | OpenFlags::APPEND | OpenFlags::WRITE
    } else {
        OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
    };
    let mut remote_file = sftp
        .open_with_flags(temp_remote_path.to_string(), open_flags)
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 打开远端临时文件失败: {}",
                connection.name, error
            ))
        })?;

    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    let mut uploaded = resume_offset;
    // 起点输出（0% 或续传点）；空文件场景也在这里显示 100%。
    print_upload_progress(uploaded, file_size, attempt)?;
    let mut last_percent = u64::MAX;
    loop {
        let read_bytes = local_file.read(&mut buffer).await?;
        if read_bytes == 0 {
            break;
        }
        remote_file.write_all(&buffer[..read_bytes]).await?;
        remote_file.flush().await?;
        uploaded += read_bytes as u64;
        // 仅在百分比变化时输出，避免大文件逐 chunk 刷屏。
        let percent = if file_size == 0 {
            100
        } else {
            uploaded.saturating_mul(100) / file_size
        };
        if percent != last_percent {
            last_percent = percent;
            print_upload_progress(uploaded, file_size, attempt)?;
        }
    }

    remote_file.shutdown().await?;
    verify_remote_temp_size(sftp, temp_remote_path, file_size).await?;
    // 尽量先删除目标文件，兼容不支持覆盖 rename 的 SFTP 服务端。
    let _ = sftp.remove_file(remote_path.to_string()).await;
    sftp.rename(temp_remote_path.to_string(), remote_path.to_string())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 替换远端文件失败: {}",
                connection.name, error
            ))
        })?;
    let _ = sftp.remove_file(temp_remote_meta_path.to_string()).await;
    eprintln!("上传完成: {} bytes", file_size);
    Ok(())
}

async fn ensure_upload_resume_meta(
    sftp: &SftpSession,
    temp_remote_path: &str,
    temp_remote_meta_path: &str,
    resume_meta: &UploadResumeMeta,
) -> AppResult<()> {
    let expected = serde_json::to_vec(resume_meta)?;
    let current = match sftp.read(temp_remote_meta_path.to_string()).await {
        Ok(bytes) => Some(bytes),
        Err(_) => None,
    };
    if current.as_deref() == Some(expected.as_slice()) {
        return Ok(());
    }

    // 本地文件特征变化时，旧 .part 不能安全续传，必须删除后重建元数据。
    let _ = sftp.remove_file(temp_remote_path.to_string()).await;
    let _ = sftp.remove_file(temp_remote_meta_path.to_string()).await;
    let mut meta_file = sftp
        .open_with_flags(
            temp_remote_meta_path.to_string(),
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .map_err(|error| AppError::new(format!("创建远端续传元数据失败: {}", error)))?;
    meta_file
        .write_all(&expected)
        .await
        .map_err(|error| AppError::new(format!("写入远端续传元数据失败: {}", error)))?;
    meta_file
        .shutdown()
        .await
        .map_err(|error| AppError::new(format!("关闭远端续传元数据失败: {}", error)))?;
    Ok(())
}

async fn resolve_upload_resume_offset(
    sftp: &SftpSession,
    temp_remote_path: &str,
    file_size: u64,
) -> AppResult<u64> {
    let metadata = match sftp.metadata(temp_remote_path.to_string()).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(0),
    };
    let remote_size = metadata.size.unwrap_or(0);
    if remote_size == file_size {
        return Ok(remote_size);
    }
    if remote_size < file_size {
        return Ok(remote_size);
    }
    // 远端临时文件比本地还大，说明它不属于当前上传内容，删除后重传。
    let _ = sftp.remove_file(temp_remote_path.to_string()).await;
    Ok(0)
}

async fn verify_remote_temp_size(
    sftp: &SftpSession,
    temp_remote_path: &str,
    expected_size: u64,
) -> AppResult<()> {
    let metadata = sftp
        .metadata(temp_remote_path.to_string())
        .await
        .map_err(|error| AppError::new(format!("读取远端临时文件大小失败: {}", error)))?;
    let actual_size = metadata.size.unwrap_or(0);
    if actual_size != expected_size {
        return Err(AppError::new(format!(
            "远端临时文件大小不一致: 期望 {} bytes，实际 {} bytes",
            expected_size, actual_size
        )));
    }
    Ok(())
}

fn print_upload_progress(uploaded: u64, total: u64, attempt: usize) -> AppResult<()> {
    if total == 0 {
        eprintln!("上传进度: 100% (0/0 bytes, 第 {} 次)", attempt);
        return Ok(());
    }
    let percent = uploaded.saturating_mul(100) / total;
    eprintln!(
        "上传进度: {}% ({}/{} bytes, 第 {} 次)",
        percent, uploaded, total, attempt
    );
    Ok(())
}

fn print_download_progress(downloaded: u64, total: u64) -> AppResult<()> {
    if total == 0 {
        eprintln!("下载进度: 100% (0/0 bytes)");
        return Ok(());
    }
    let percent = downloaded.saturating_mul(100) / total;
    eprintln!("下载进度: {}% ({}/{} bytes)", percent, downloaded, total);
    Ok(())
}

fn temporary_local_part_path(local_path: &Path) -> PathBuf {
    let mut name = local_path.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

fn temporary_local_meta_path(local_path: &Path) -> PathBuf {
    let mut name = local_path.as_os_str().to_owned();
    name.push(".part.meta");
    PathBuf::from(name)
}

// 本地 .part 续传判定：meta 内容与远端文件特征一致才续传，否则删除 .part 重新下载。
fn resolve_download_resume_offset(
    part_path: &Path,
    meta_path: &Path,
    resume_meta: &UploadResumeMeta,
) -> AppResult<Option<u64>> {
    let expected = serde_json::to_vec(resume_meta)?;
    let current = match fs::read(meta_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if current != expected {
        let _ = fs::remove_file(part_path);
        let _ = fs::remove_file(meta_path);
        return Ok(None);
    }
    let part_size = match fs::metadata(part_path) {
        Ok(metadata) => metadata.len(),
        Err(_) => return Ok(None),
    };
    if part_size > resume_meta.file_size {
        let _ = fs::remove_file(part_path);
        let _ = fs::remove_file(meta_path);
        return Ok(None);
    }
    Ok(Some(part_size))
}

pub(crate) async fn download_file_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
) -> AppResult<()> {
    let sftp = open_sftp_session(session, connection).await?;
    let remote_metadata = sftp
        .metadata(remote_path.to_string())
        .await
        .map_err(|error| {
            AppError::new(format!(
                "连接 {} 读取远端文件信息失败: {}",
                connection.name, error
            ))
        })?;
    let remote_size = remote_metadata.len();
    let modified_ms = remote_metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    // 复用 UploadResumeMeta 结构：字段与下载续传元数据一致。
    let resume_meta = UploadResumeMeta {
        file_size: remote_size,
        modified_ms,
        chunk_bytes: TRANSFER_CHUNK_BYTES,
    };
    let part_path = temporary_local_part_path(local_path);
    let meta_path = temporary_local_meta_path(local_path);
    let resume_offset =
        resolve_download_resume_offset(&part_path, &meta_path, &resume_meta)?.unwrap_or(0);
    let mut remote_file = sftp.open(remote_path.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 打开远端文件失败: {}",
            connection.name, error
        ))
    })?;
    let mut local_file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&part_path)
        .await?;
    if resume_offset > 0 {
        local_file.seek(SeekFrom::Start(resume_offset)).await?;
        remote_file.seek(SeekFrom::Start(resume_offset)).await?;
        eprintln!(
            "发现本地临时文件，断点续传: {}/{} bytes",
            resume_offset, remote_size
        );
    } else {
        local_file.set_len(0).await?;
    }
    // 下载前写入元数据，中断后下次可据此判定续传。
    fs::write(&meta_path, serde_json::to_vec(&resume_meta)?)?;
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    let mut downloaded = resume_offset;
    print_download_progress(downloaded, remote_size)?;
    let mut last_percent = u64::MAX;
    loop {
        let read_bytes = remote_file.read(&mut buffer).await?;
        if read_bytes == 0 {
            break;
        }
        local_file.write_all(&buffer[..read_bytes]).await?;
        downloaded += read_bytes as u64;
        let percent = if remote_size == 0 {
            100
        } else {
            downloaded.saturating_mul(100) / remote_size
        };
        if percent != last_percent {
            last_percent = percent;
            print_download_progress(downloaded, remote_size)?;
        }
    }
    local_file.shutdown().await?;
    let _ = sftp.close().await;
    if downloaded != remote_size {
        return Err(AppError::new(format!(
            "下载大小不一致: 期望 {} bytes，实际 {} bytes",
            remote_size, downloaded
        )));
    }
    tokio::fs::rename(&part_path, local_path).await?;
    let _ = fs::remove_file(&meta_path);
    Ok(())
}

async fn upload_file_async(
    configs: &[Connection],
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result =
        upload_file_with_session_async(&session, connection, local_path, remote_path).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

async fn download_file_async(
    configs: &[Connection],
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result =
        download_file_with_session_async(&session, connection, remote_path, local_path).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

pub(crate) fn upload_file(
    configs: &[Connection],
    connection: &Connection,
    local_path: &Path,
    remote_path: &str,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
    match timeout_ms {
        Some(timeout_ms) => block_with_timeout(
            &runtime,
            timeout_ms,
            upload_file_async(configs, connection, local_path, remote_path),
        ),
        None => runtime.block_on(upload_file_async(
            configs,
            connection,
            local_path,
            remote_path,
        )),
    }
}

pub(crate) fn download_file(
    configs: &[Connection],
    connection: &Connection,
    remote_path: &str,
    local_path: &Path,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    match timeout_ms {
        Some(timeout_ms) => run_with_timeout(
            timeout_ms,
            download_file_async(configs, connection, remote_path, local_path),
        ),
        None => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
            runtime.block_on(download_file_async(
                configs,
                connection,
                remote_path,
                local_path,
            ))
        }
    }
}

// 远端目录逐级创建，已存在的层级忽略错误。
async fn ensure_remote_dir_all(sftp: &SftpSession, remote_dir: &str) -> AppResult<()> {
    let mut current = String::new();
    if remote_dir.starts_with('/') {
        current.push('/');
    }
    for part in remote_dir.split('/').filter(|part| !part.is_empty()) {
        if !current.is_empty() && !current.ends_with('/') {
            current.push('/');
        }
        current.push_str(part);
        let _ = sftp.create_dir(current.clone()).await;
    }
    Ok(())
}

pub(crate) async fn upload_dir_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    local_dir: &Path,
    remote_dir: &str,
) -> AppResult<()> {
    // daemon 模式也做目录检查（no-cache 侧在 upload_dir 已检查），保证两模式报错一致。
    if !local_dir.is_dir() {
        return Err(AppError::new(format!(
            "--recursive 上传需要本地目录路径，当前为: {}",
            local_dir.display()
        )));
    }
    let sftp = open_sftp_session(session, connection).await?;
    ensure_remote_dir_all(&sftp, remote_dir).await?;
    let _ = sftp.close().await;
    let entries = fs::read_dir(local_dir)?;
    for entry in entries {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|item| item.to_str())
            .ok_or_else(|| AppError::new("本地路径包含非 UTF-8 文件名"))?
            .to_string();
        let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), name);
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_dir() {
            Box::pin(upload_dir_with_session_async(
                session,
                connection,
                &path,
                &remote_child,
            ))
            .await?;
        } else if file_type.is_symlink() {
            // 符号链接不递归跟随（防目录循环）：指向目录的链接跳过，指向文件的链接上传其内容。
            let target_is_dir = fs::metadata(&path)
                .map(|meta| meta.is_dir())
                .unwrap_or(true);
            if target_is_dir {
                continue;
            }
            upload_file_with_session_async(session, connection, &path, &remote_child).await?;
        } else {
            upload_file_with_session_async(session, connection, &path, &remote_child).await?;
        }
    }
    Ok(())
}

pub(crate) async fn download_dir_with_session_async(
    session: &client::Handle<RusshClient>,
    connection: &Connection,
    remote_dir: &str,
    local_dir: &Path,
) -> AppResult<()> {
    fs::create_dir_all(local_dir)?;
    let sftp = open_sftp_session(session, connection).await?;
    let remote_meta = sftp.metadata(remote_dir.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 读取远端目录信息失败: {}",
            connection.name, error
        ))
    })?;
    if !remote_meta.is_dir() {
        let _ = sftp.close().await;
        return Err(AppError::new(format!(
            "--recursive 下载需要远端目录路径: {}",
            remote_dir
        )));
    }
    let entries = sftp.read_dir(remote_dir.to_string()).await.map_err(|error| {
        AppError::new(format!(
            "连接 {} 读取远端目录失败: {}",
            connection.name, error
        ))
    })?;
    let _ = sftp.close().await;
    for entry in entries {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), name);
        let local_child = local_dir.join(&name);
        if entry.file_type().is_dir() {
            Box::pin(download_dir_with_session_async(
                session,
                connection,
                &remote_child,
                &local_child,
            ))
            .await?;
        } else if entry.file_type().is_file() {
            download_file_with_session_async(session, connection, &remote_child, &local_child).await?;
        }
    }
    Ok(())
}

async fn upload_dir_async(
    configs: &[Connection],
    connection: &Connection,
    local_dir: &Path,
    remote_dir: &str,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result = upload_dir_with_session_async(&session, connection, local_dir, remote_dir).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

async fn download_dir_async(
    configs: &[Connection],
    connection: &Connection,
    remote_dir: &str,
    local_dir: &Path,
) -> AppResult<()> {
    let session = connect_russh(configs, connection).await?;
    let result = download_dir_with_session_async(&session, connection, remote_dir, local_dir).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    result
}

pub(crate) fn upload_dir(
    configs: &[Connection],
    connection: &Connection,
    local_dir: &Path,
    remote_dir: &str,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    if !local_dir.is_dir() {
        return Err(AppError::new(format!(
            "--recursive 上传需要本地目录路径，当前为: {}",
            local_dir.display()
        )));
    }
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
    match timeout_ms {
        Some(timeout_ms) => block_with_timeout(
            &runtime,
            timeout_ms,
            upload_dir_async(configs, connection, local_dir, remote_dir),
        ),
        None => runtime.block_on(upload_dir_async(
            configs,
            connection,
            local_dir,
            remote_dir,
        )),
    }
}

pub(crate) fn download_dir(
    configs: &[Connection],
    connection: &Connection,
    remote_dir: &str,
    local_dir: &Path,
    timeout_ms: Option<u64>,
) -> AppResult<()> {
    match timeout_ms {
        Some(timeout_ms) => run_with_timeout(
            timeout_ms,
            download_dir_async(configs, connection, remote_dir, local_dir),
        ),
        None => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| AppError::new(format!("创建 tokio runtime 失败: {}", error)))?;
            runtime.block_on(download_dir_async(
                configs,
                connection,
                remote_dir,
                local_dir,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_parent_path_handles_absolute_relative_and_root() {
        assert_eq!(remote_parent_path("/tmp/a/b.txt").as_deref(), Some("/tmp/a"));
        assert_eq!(remote_parent_path("a/b.txt").as_deref(), Some("a"));
        assert_eq!(remote_parent_path("/b.txt").as_deref(), Some("/"));
        // 不含目录部分：等价于会话当前目录，不需要父目录检查
        assert_eq!(remote_parent_path("b.txt"), None);
        assert_eq!(remote_parent_path("dir/"), None);
        // 尾部斜杠先被裁掉："/tmp/dir/" 视作目录 "/tmp/dir"，其父目录是 "/tmp"
        assert_eq!(remote_parent_path("/tmp/dir/").as_deref(), Some("/tmp"));
    }
}
