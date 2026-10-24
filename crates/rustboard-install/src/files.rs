//! 读取 token / 密码等私有文件。
//!
//! 安装器只接受 0600 的普通文件，拒绝符号链接，并在读取前限制大小，避免
//! `--hub-token-file /dev/zero` 或超大文件拖垮安装过程。

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// 读取私有文件，最多 `max_bytes` 字节。
///
/// 约束：
/// - 必须是普通文件，符号链接直接拒绝；
/// - Unix 下权限必须正好是 0600（group/other 不可读，owner 可读写）；
/// - 文件大小超过 `max_bytes` 报错，不返回截断内容。
pub fn read_private_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    if path.as_os_str().is_empty() {
        bail!("私有文件路径不能为空");
    }
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("读取私有文件 {} 失败", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("{} 是符号链接，拒绝读取私有文件", path.display());
    }
    if !meta.is_file() {
        bail!("{} 不是普通文件，拒绝读取私有文件", path.display());
    }
    check_private_mode(path, &meta)?;
    if meta.len() > max_bytes as u64 {
        bail!(
            "{} 大小 {} 字节，超过上限 {} 字节",
            path.display(),
            meta.len(),
            max_bytes
        );
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("打开私有文件 {} 失败", path.display()))?;
    // open 后重新校验，缩小 symlink_metadata 与 open 之间的替换窗口。
    let opened_meta = file
        .metadata()
        .with_context(|| format!("读取私有文件 {} 元数据失败", path.display()))?;
    if !opened_meta.is_file() {
        bail!("{} 不是普通文件，拒绝读取私有文件", path.display());
    }
    check_private_mode(path, &opened_meta)?;

    let limit = (max_bytes as u64).saturating_add(1);
    let mut data = Vec::new();
    file.take(limit)
        .read_to_end(&mut data)
        .with_context(|| format!("读取私有文件 {} 失败", path.display()))?;
    if data.len() > max_bytes {
        bail!(
            "{} 内容超过上限 {} 字节（读取时文件仍在增长）",
            path.display(),
            max_bytes
        );
    }
    Ok(data)
}

fn check_private_mode(path: &Path, meta: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "{} 权限为 {mode:04o}，私有文件要求正好 0600",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta);
    }
    Ok(())
}
