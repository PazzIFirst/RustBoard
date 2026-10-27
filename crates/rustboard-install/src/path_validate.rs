//! 安装器路径的公共校验。
//!
//! 安装器会以 root 写 `/etc`、`/var/lib`、`/usr/local` 等位置，路径校验必须在
//! 任何文件系统操作之前完成：拒绝空路径、相对路径、Windows 前缀与 `..` 组件，
//! 避免调用方把 `--prefix ../../` 之类的值拼进生产路径。

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

/// 校验并归一化一个绝对路径。
///
/// 归一化只处理重复分隔符、结尾 `/` 等 `Path::components` 自带的规则，**不会**
/// 解析或容忍 `..`；含 `..` 一律报错。`what` 用于错误信息（如“安装前缀”）。
pub(crate) fn normalize_absolute(path: &Path, what: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("{what}不能为空");
    }

    let mut normalized = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                bail!("{what}必须是 Unix 绝对路径: {}", path.display());
            }
            Component::RootDir => {
                rooted = true;
                normalized.push("/");
            }
            Component::CurDir => {
                bail!("{what}不能包含 `.` 组件: {}", path.display());
            }
            Component::ParentDir => {
                bail!("{what}不能包含 `..` 组件: {}", path.display());
            }
            Component::Normal(part) => {
                if !rooted {
                    bail!("{what}必须是绝对路径: {}", path.display());
                }
                normalized.push(part);
            }
        }
    }
    if !rooted {
        bail!("{what}必须是绝对路径: {}", path.display());
    }
    Ok(normalized)
}

/// 校验路径字符串不含换行 / 回车 / NUL。
///
/// 这些字符写进 TOML、systemd unit 或命令行后可能变成注入；安装器允许带空格的
/// prefix，但明确拒绝控制字符换行。`label` 用于错误信息。
pub(crate) fn reject_line_injection(path: &Path, label: &str) -> Result<()> {
    let text = path.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "{label}不是有效 UTF-8，无法写入配置文件 / unit: {}",
            path.display()
        )
    })?;
    if text.is_empty() {
        bail!("{label}不能为空");
    }
    if text
        .chars()
        .any(|ch| ch == '\n' || ch == '\r' || ch == '\0')
    {
        bail!("{label}不能包含换行、回车或 NUL: {:?}", text);
    }
    Ok(())
}

/// 从根开始逐组件检查路径：已存在的组件中只要有符号链接就拒绝。
///
/// 目标本身可以不存在；遇到第一个不存在的组件即停止（后续组件尚未创建）。
/// 安装器在写配置 / unit / 状态以及递归删除前调用，避免父目录被替换成链接后
/// 把 root 写入或删除作用到链接目标。路径必须先归一化，含 `..` / `.` 时直接报错。
pub fn reject_symlink_components(path: &Path) -> Result<()> {
    let normalized = normalize_absolute(path, "路径")?;
    let mut current = PathBuf::new();
    for component in normalized.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(part) => {
                current.push(part);
                match std::fs::symlink_metadata(&current) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        bail!(
                            "{} 的路径组件 {} 是符号链接，拒绝操作",
                            normalized.display(),
                            current.display()
                        );
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == ErrorKind::NotFound => break,
                    Err(err) => {
                        return Err(err)
                            .with_context(|| format!("检查路径组件 {} 失败", current.display()));
                    }
                }
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                bail!("{} 不是归一化的绝对路径", normalized.display());
            }
        }
    }
    Ok(())
}

/// 校验要写入 systemd unit 的路径字符集。
///
/// 除控制字符（换行 / 回车 / NUL 等）外，`$` / `%` 会被 systemd 当作变量或
/// specifier 展开，`"` / `'` / `\` 会与 unit 的命令行引用规则冲突。这些字符
/// 无论怎么转义都容易产生歧义，一律在渲染前拒绝；空格仍由 `systemd_quote`
/// 处理。`label` 用于错误信息。
pub(crate) fn reject_unit_unsafe_chars(path: &Path, label: &str) -> Result<()> {
    reject_line_injection(path, label)?;
    let text = path.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "{label}不是有效 UTF-8，无法写入 systemd unit: {}",
            path.display()
        )
    })?;
    if let Some(ch) = text.chars().find(|ch| ch.is_control()) {
        bail!("{label}不能包含控制字符（含换行）{ch:?}: {text:?}");
    }
    if let Some(ch) = text
        .chars()
        .find(|ch| matches!(ch, '$' | '%' | '"' | '\'' | '\\'))
    {
        bail!("{label}不能包含 `{ch}` 等 systemd 特殊字符（$、%、引号、反斜杠）: {text:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_absolute_paths() {
        assert_eq!(
            normalize_absolute(Path::new("/tmp//rustboard/./x/"), "路径").unwrap(),
            PathBuf::from("/tmp/rustboard/x")
        );
        assert_eq!(
            normalize_absolute(Path::new("/"), "路径").unwrap(),
            PathBuf::from("/")
        );
    }

    #[test]
    fn rejects_bad_paths() {
        for path in ["", "relative", "../etc", "/tmp/../etc", "/tmp/a/../b"] {
            assert!(
                normalize_absolute(Path::new(path), "路径").is_err(),
                "{path:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn rejects_line_injection() {
        assert!(reject_line_injection(Path::new("/tmp/a\nb"), "配置").is_err());
        assert!(reject_line_injection(Path::new("/tmp/a\rb"), "配置").is_err());
        assert!(reject_line_injection(Path::new("/tmp/a b"), "配置").is_ok());
    }
}
