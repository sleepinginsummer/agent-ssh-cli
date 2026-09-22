// 编辑器双文件事务：以显式阶段清单协调配置与 secrets.json 的提交和恢复。

use super::replace_file;
use crate::{AppError, AppResult};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Prepared,
    ReplacingSecrets,
    ReplacingConfig,
    Committed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    version: u8,
    id: String,
    phase: Phase,
    secret_existed: bool,
}

struct Paths {
    config_tmp: PathBuf,
    secret_tmp: PathBuf,
    config_backup: PathBuf,
    secret_backup: PathBuf,
    manifest: PathBuf,
}

fn manifest_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("editor-transaction.json")
}

fn transaction_paths(config_path: &Path, secret_path: &Path, transaction_id: &str) -> Paths {
    Paths {
        config_tmp: config_path.with_extension(format!("{}.config-tmp", transaction_id)),
        secret_tmp: secret_path.with_extension(format!("{}.secret-tmp", transaction_id)),
        config_backup: config_path.with_extension(format!("{}.config-backup", transaction_id)),
        secret_backup: secret_path.with_extension(format!("{}.secret-backup", transaction_id)),
        manifest: manifest_path(config_path),
    }
}

fn new_transaction_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn validate_transaction_id(id: &str) -> AppResult<()> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::new("编辑器事务 ID 非法"));
    }
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn copy_backup(source: &Path, backup: &Path) -> AppResult<()> {
    let _ = fs::remove_file(backup);
    fs::copy(source, backup)?;
    File::open(backup)?.sync_all()?;
    Ok(())
}

fn restore_backup(backup: &Path, destination: &Path, transaction_id: &str) -> AppResult<()> {
    let recovery = destination.with_extension(format!("{}.recovery-tmp", transaction_id));
    let _ = fs::remove_file(&recovery);
    fs::copy(backup, &recovery)?;
    File::open(&recovery)?.sync_all()?;
    replace_file(&recovery, destination)
}

fn persist(transaction: &Transaction, paths: &Paths) -> AppResult<()> {
    let manifest_tmp = paths
        .manifest
        .with_extension(format!("{}.manifest-tmp", transaction.id));
    write_synced(&manifest_tmp, &serde_json::to_vec(transaction)?)?;
    replace_file(&manifest_tmp, &paths.manifest)?;
    File::open(&paths.manifest)?.sync_all()?;
    Ok(())
}

fn cleanup(paths: &Paths) -> AppResult<()> {
    for path in [
        &paths.config_tmp,
        &paths.secret_tmp,
        &paths.config_backup,
        &paths.secret_backup,
        &paths.manifest,
    ] {
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub(super) fn recover_locked(config_path: &Path, secret_path: &Path) -> AppResult<()> {
    let manifest_path = manifest_path(config_path);
    if !manifest_path.exists() {
        return Ok(());
    }
    let transaction: Transaction = serde_json::from_slice(&fs::read(&manifest_path)?)
        .map_err(|error| AppError::new(format!("编辑器事务清单损坏: {}", error)))?;
    if transaction.version != 1 {
        return Err(AppError::new("编辑器事务清单版本不支持"));
    }
    validate_transaction_id(&transaction.id)?;
    let paths = transaction_paths(config_path, secret_path, &transaction.id);

    match transaction.phase {
        Phase::Prepared | Phase::Committed => {}
        Phase::ReplacingSecrets | Phase::ReplacingConfig => {
            restore_backup(&paths.config_backup, config_path, &transaction.id)?;
            if transaction.secret_existed {
                restore_backup(&paths.secret_backup, secret_path, &transaction.id)?;
            } else if secret_path.exists() {
                fs::remove_file(secret_path)?;
            }
        }
    }
    cleanup(&paths)
}

fn rollback_error(
    config_path: &Path,
    secret_path: &Path,
    context: &str,
    error: AppError,
) -> AppError {
    match recover_locked(config_path, secret_path) {
        Ok(()) => AppError::new(format!("{}: {}", context, error)),
        Err(recovery_error) => AppError::new(format!(
            "{}: {}；回滚失败: {}",
            context, error, recovery_error
        )),
    }
}

pub(super) fn commit(
    config_path: &Path,
    config_bytes: &[u8],
    secret_path: &Path,
    secret_bytes: &[u8],
) -> AppResult<()> {
    let transaction_id = new_transaction_id();
    let paths = transaction_paths(config_path, secret_path, &transaction_id);
    let mut transaction = Transaction {
        version: 1,
        id: transaction_id,
        phase: Phase::Prepared,
        secret_existed: secret_path.exists(),
    };
    persist(&transaction, &paths)?;
    write_synced(&paths.config_tmp, config_bytes)?;
    write_synced(&paths.secret_tmp, secret_bytes)?;
    copy_backup(config_path, &paths.config_backup)?;
    if transaction.secret_existed {
        copy_backup(secret_path, &paths.secret_backup)?;
    }

    transaction.phase = Phase::ReplacingSecrets;
    persist(&transaction, &paths).map_err(|error| {
        rollback_error(
            config_path,
            secret_path,
            "记录 secrets.json 提交阶段失败",
            error,
        )
    })?;
    replace_file(&paths.secret_tmp, secret_path).map_err(|error| {
        rollback_error(config_path, secret_path, "提交 secrets.json 失败", error)
    })?;

    transaction.phase = Phase::ReplacingConfig;
    persist(&transaction, &paths)
        .map_err(|error| rollback_error(config_path, secret_path, "记录配置提交阶段失败", error))?;
    replace_file(&paths.config_tmp, config_path)
        .map_err(|error| rollback_error(config_path, secret_path, "提交配置失败", error))?;

    transaction.phase = Phase::Committed;
    persist(&transaction, &paths)
        .map_err(|error| rollback_error(config_path, secret_path, "记录事务完成阶段失败", error))?;
    if let Err(error) = cleanup(&paths) {
        eprintln!("清理已提交的编辑器事务失败: {}", error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_file_overwrites_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("destination.json");
        let temp = directory.path().join("replacement.tmp");
        fs::write(&destination, b"old").unwrap();
        fs::write(&temp, b"new").unwrap();
        replace_file(&temp, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert!(!temp.exists());
    }

    fn assert_recovery(
        phase: Phase,
        replace_secrets: bool,
        replace_config: bool,
        expect_new_files: bool,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let secret_path = directory.path().join("secrets.json");
        fs::write(&config_path, b"old-config").unwrap();
        fs::write(&secret_path, b"old-secrets").unwrap();
        let transaction_id = "0123456789abcdef0123456789abcdef".to_string();
        let paths = transaction_paths(&config_path, &secret_path, &transaction_id);
        let transaction = Transaction {
            version: 1,
            id: transaction_id,
            phase,
            secret_existed: true,
        };
        persist(&transaction, &paths).unwrap();
        write_synced(&paths.config_tmp, b"new-config").unwrap();
        write_synced(&paths.secret_tmp, b"new-secrets").unwrap();
        copy_backup(&config_path, &paths.config_backup).unwrap();
        copy_backup(&secret_path, &paths.secret_backup).unwrap();
        if replace_secrets {
            replace_file(&paths.secret_tmp, &secret_path).unwrap();
        }
        if replace_config {
            replace_file(&paths.config_tmp, &config_path).unwrap();
        }

        recover_locked(&config_path, &secret_path).unwrap();
        let expected_config = if expect_new_files {
            b"new-config".as_slice()
        } else {
            b"old-config".as_slice()
        };
        let expected_secrets = if expect_new_files {
            b"new-secrets".as_slice()
        } else {
            b"old-secrets".as_slice()
        };
        assert_eq!(fs::read(&config_path).unwrap(), expected_config);
        assert_eq!(fs::read(&secret_path).unwrap(), expected_secrets);
        assert!(!paths.manifest.exists());
    }

    #[test]
    fn recovery_uses_explicit_phase() {
        assert_recovery(Phase::Prepared, false, false, false);
        assert_recovery(Phase::ReplacingSecrets, true, false, false);
        assert_recovery(Phase::ReplacingConfig, true, true, false);
        assert_recovery(Phase::Committed, true, true, true);
    }
}
