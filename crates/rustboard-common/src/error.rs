use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),

    #[error("config parse error: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("config write error: {0}")]
    ConfigWrite(#[from] toml::ser::Error),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// 从 TOML 文件读取配置。
///
/// M3：读取前先收紧既有文件的权限。老版本可能把配置留成 0644，
/// 而 agent.toml 里通常带着 enrollment token。
///
/// 解析失败只给固定诊断（路径 + “TOML 解析失败”）：`toml::de::Error` 会回显
/// 源码行，配置里的 token / 密码不能进入 stderr 或日志。
pub fn load_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::fsutil::harden(path, 0o600)?;
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).map_err(|_| {
        Error::InvalidConfig(format!(
            "TOML 解析失败: {}（已隐藏原始配置内容与解析位置，避免泄露 token/密码）",
            path.display()
        ))
    })
}

/// 写入 TOML 配置：父目录 0700，文件原子写入且权限 0600。
///
/// AgentConfig 里可能带一次性 enrollment token，不能用 umask 决定的默认权限落盘。
pub fn save_toml<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let text = toml::to_string_pretty(value)?;
    if let Some(parent) = path.parent() {
        crate::fsutil::ensure_dir(parent, 0o700)?;
    }
    crate::fsutil::atomic_write(path, text.as_bytes(), 0o600)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct TestConfig {
        token: String,
    }

    #[test]
    fn issue_6_save_toml_writes_private_config_in_private_dir() {
        let dir = std::env::temp_dir().join(format!("rb-save-toml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("agent.toml");

        save_toml(
            &path,
            &TestConfig {
                token: "secret".into(),
            },
        )
        .unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("secret"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M3：读取一次 0644 的配置文件后，权限必须被收紧到 0600。
    #[test]
    fn m3_load_toml_tightens_existing_0644_config() {
        let dir = std::env::temp_dir().join(format!("rb-load-toml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.toml");
        std::fs::write(&path, "token = \"secret\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let cfg: TestConfig = load_toml(&path).unwrap();
        assert_eq!(cfg.token, "secret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P1 复审：TOML 解析错误不得回显含 token 的原始配置行。
    #[test]
    fn load_toml_parse_error_does_not_echo_config_source() {
        let dir =
            std::env::temp_dir().join(format!("rb-load-toml-parse-leak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.toml");
        let secret = "load-toml-canary-token-7c1a";
        std::fs::write(&path, format!("token = \"{secret}\"\nbroken = [\n")).unwrap();

        let err = load_toml::<TestConfig>(&path).expect_err("非法 TOML 必须失败");
        let message = format!("{err:#}");
        assert!(message.contains("TOML 解析失败"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(!message.contains(secret), "解析错误泄露配置原文: {message}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
