use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// agent 端配置。对应 `/etc/rustboard/agent.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// hub 的 WebSocket 入口，例如 `ws://10.0.0.1:8443/agent/ws`。
    pub hub_url: String,
    /// 纳管时由 `rustboard-hub agent add` 生成的一次性 token。
    pub token: String,
    /// hub 服务端证书的 SHA-256 指纹（hex）。自签模式下必须与安装命令一致。
    pub server_fingerprint: String,
    /// 展示名，留空则用 hostname。
    pub name: String,
    pub data_dir: PathBuf,
    /// 采样间隔，hub 可以在运行时下发覆盖值。
    pub sample_interval_ms: u64,
    /// 是否采集每核 CPU（会增加点数）。
    pub per_core: bool,
    /// 需要忽略的网卡名前缀。
    pub excluded_interfaces: Vec<String>,
    /// 本地环形缓冲的最大字节数。
    pub buffer_max_bytes: u64,
    /// 单批最多多少条采样点。
    pub max_batch_samples: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            hub_url: format!("ws://127.0.0.1:{}/agent/ws", crate::DEFAULT_AGENT_PORT),
            token: String::new(),
            server_fingerprint: String::new(),
            name: String::new(),
            data_dir: PathBuf::from("/var/lib/rustboard/agent"),
            sample_interval_ms: 5_000,
            per_core: false,
            excluded_interfaces: default_excluded_interfaces(),
            buffer_max_bytes: 500 * 1024 * 1024,
            max_batch_samples: 512,
        }
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.hub_url.trim().is_empty() {
            return Err(Error::InvalidConfig("hub_url 不能为空".into()));
        }
        if !self.hub_url.starts_with("ws://") && !self.hub_url.starts_with("wss://") {
            return Err(Error::InvalidConfig("hub_url 必须以 ws:// 或 wss:// 开头".into()));
        }
        if self.sample_interval_ms < 1_000 {
            return Err(Error::InvalidConfig("采样间隔不能小于 1000ms".into()));
        }
        if self.hub_url.starts_with("wss://") && self.server_fingerprint.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "wss:// 连接必须配置 server_fingerprint（安装命令里会给出）".into(),
            ));
        }
        Ok(())
    }
}

/// hub 端配置。对应 `/etc/rustboard/hub.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HubConfig {
    /// agent 接入监听地址。
    pub agent_listen: String,
    /// 面板/管理 API 监听地址。默认只绑回环，公网暴露需显式修改。
    pub admin_listen: String,
    pub data_dir: PathBuf,
    /// SQLite 用路径，PostgreSQL 用 `postgres://...`。
    pub database: String,
    /// 是否把 hub 所在主机也当作一台 agent 采集。
    pub self_monitor: bool,
    /// hub 自身的展示名。
    pub name: String,
    /// 服务端证书的 SAN 列表（localhost、内网 IP、公网 IP 等）。
    pub server_names: Vec<String>,
    /// 下发给 agent 的默认采样间隔。
    pub sample_interval_ms: u64,
    pub per_core: bool,
    pub excluded_interfaces: Vec<String>,
    pub retention_raw_days: u32,
    pub retention_1m_days: u32,
    pub retention_1h_days: u32,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            agent_listen: format!("0.0.0.0:{}", crate::DEFAULT_AGENT_PORT),
            admin_listen: format!("127.0.0.1:{}", crate::DEFAULT_ADMIN_PORT),
            data_dir: PathBuf::from("/var/lib/rustboard/hub"),
            database: "sqlite:///var/lib/rustboard/hub/rustboard.db".to_string(),
            self_monitor: true,
            name: String::new(),
            server_names: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            sample_interval_ms: 5_000,
            per_core: false,
            excluded_interfaces: default_excluded_interfaces(),
            retention_raw_days: 7,
            retention_1m_days: 90,
            retention_1h_days: 730,
        }
    }
}

impl HubConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }

    pub fn sqlite_path(&self) -> Result<PathBuf> {
        self.database
            .strip_prefix("sqlite://")
            .map(PathBuf::from)
            .ok_or_else(|| Error::InvalidConfig("v1 暂只支持 sqlite:// 形式的数据库地址".into()))
    }
}

/// 面板配置。对应 `/etc/rustboard/panel.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PanelConfig {
    pub listen: String,
    /// hub 的管理 API 地址，例如 `http://127.0.0.1:8444`。
    pub hub_url: String,
    /// 面板访问 hub 用的 scoped token。
    pub token: String,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            listen: format!("0.0.0.0:{}", crate::DEFAULT_PANEL_PORT),
            hub_url: format!("http://127.0.0.1:{}", crate::DEFAULT_ADMIN_PORT),
            token: String::new(),
        }
    }
}

impl PanelConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }
}

pub fn default_excluded_interfaces() -> Vec<String> {
    ["lo", "docker", "veth", "br-", "virbr", "cni", "flannel"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
