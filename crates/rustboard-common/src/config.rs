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
    /// 本地缓冲的最长保留小时数（与字节上限取先到者）。
    #[serde(default = "default_buffer_max_age_hours")]
    pub buffer_max_age_hours: u64,
    /// 客户端证书剩余寿命不超过该天数时自动轮换。
    #[serde(default = "default_cert_renew_before_days")]
    pub cert_renew_before_days: u32,
    /// 主动重连周期（小时），让轮换后的证书与 hub 配置有机会生效；0 表示不主动重连。
    #[serde(default = "default_session_max_hours")]
    pub session_max_hours: u64,
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
            buffer_max_age_hours: 24,
            cert_renew_before_days: default_cert_renew_before_days(),
            session_max_hours: default_session_max_hours(),
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
            return Err(Error::InvalidConfig(
                "hub_url 必须以 ws:// 或 wss:// 开头".into(),
            ));
        }
        if self.sample_interval_ms < 1_000 {
            return Err(Error::InvalidConfig("采样间隔不能小于 1000ms".into()));
        }
        if self.hub_url.starts_with("wss://") && self.server_fingerprint.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "wss:// 连接必须配置 server_fingerprint（安装命令里会给出）".into(),
            ));
        }
        // 续签阈值至少 1 天：0 会让「剩余寿命 ≤ 阈值」在刚签发后就成立。
        if self.cert_renew_before_days < 1 {
            return Err(Error::InvalidConfig(
                "cert_renew_before_days 至少为 1 天".into(),
            ));
        }
        // 主动重连周期上限 1 年：更大的值等价于不主动重连，且容易是单位写错。
        if self.session_max_hours > MAX_SESSION_MAX_HOURS {
            return Err(Error::InvalidConfig(format!(
                "session_max_hours 不能超过 {MAX_SESSION_MAX_HOURS}（0 表示不主动重连）"
            )));
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
    /// agent 安装命令里使用的 hub 地址。留空则自动从 server_names 里挑一个非回环 IP。
    pub advertise_host: Option<String>,
    /// 下发给 agent 的默认采样间隔。
    pub sample_interval_ms: u64,
    /// agent 接入层允许同时处理的 TLS 连接数；超出后直接关闭 TCP。
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    pub per_core: bool,
    pub excluded_interfaces: Vec<String>,
    pub retention_raw_days: u32,
    pub retention_1m_days: u32,
    pub retention_1h_days: u32,
    /// 管理 API 的 Bearer token；由 `hub init` / `hub admin-token` 生成，为空时拒绝启动。
    #[serde(default)]
    pub admin_token: String,
    /// 新建 CA 的有效期（天）。已存在的 CA 不受影响。
    #[serde(default = "default_ca_validity_days")]
    pub ca_validity_days: u32,
    /// 服务端证书有效期（天）。
    #[serde(default = "default_server_cert_validity_days")]
    pub server_cert_validity_days: u32,
    /// agent 客户端证书有效期（天）。
    #[serde(default = "default_client_cert_validity_days")]
    pub client_cert_validity_days: u32,
    /// 剩余寿命不超过该天数时触发续签。
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    /// 服务端证书续签检查周期（秒），最小 1。
    #[serde(default = "default_cert_check_interval_secs")]
    pub cert_check_interval_secs: u64,
}

/// agent 接入层默认的最大并发连接数。
fn default_max_connections() -> usize {
    1024
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
            advertise_host: None,
            sample_interval_ms: 5_000,
            max_connections: default_max_connections(),
            per_core: false,
            excluded_interfaces: default_excluded_interfaces(),
            retention_raw_days: 7,
            retention_1m_days: 90,
            retention_1h_days: 730,
            admin_token: String::new(),
            ca_validity_days: default_ca_validity_days(),
            server_cert_validity_days: default_server_cert_validity_days(),
            client_cert_validity_days: default_client_cert_validity_days(),
            renew_before_days: default_renew_before_days(),
            cert_check_interval_secs: default_cert_check_interval_secs(),
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

    /// 业务校验：`run` / `init` 入口都会调用。
    ///
    /// 只校验配置值本身是否自洽，不读写证书文件。`admin_token` 属于 M2 的鉴权范围，
    /// 本阶段不校验（为空仍允许启动，保持 v0.1 行为）。
    pub fn validate(&self) -> Result<()> {
        for (name, days) in [
            ("ca_validity_days", self.ca_validity_days),
            ("server_cert_validity_days", self.server_cert_validity_days),
            ("client_cert_validity_days", self.client_cert_validity_days),
        ] {
            if !(MIN_VALIDITY_DAYS..=MAX_VALIDITY_DAYS).contains(&days) {
                return Err(Error::InvalidConfig(format!(
                    "{name} 必须在 {MIN_VALIDITY_DAYS}–{MAX_VALIDITY_DAYS} 天之间，实际 {days}"
                )));
            }
        }
        if self.renew_before_days < 1 {
            return Err(Error::InvalidConfig("renew_before_days 至少为 1 天".into()));
        }
        if self.renew_before_days >= self.server_cert_validity_days {
            return Err(Error::InvalidConfig(format!(
                "renew_before_days（{}）必须小于 server_cert_validity_days（{}），\
                 否则续签出来的证书仍然立刻到期",
                self.renew_before_days, self.server_cert_validity_days
            )));
        }
        // 检查周期过短只会造成无意义的磁盘写入与重复签名。
        if self.cert_check_interval_secs < MIN_CERT_CHECK_INTERVAL_SECS {
            return Err(Error::InvalidConfig(format!(
                "cert_check_interval_secs 至少为 {MIN_CERT_CHECK_INTERVAL_SECS} 秒，实际 {}",
                self.cert_check_interval_secs
            )));
        }
        // server_names 是服务端证书的 SAN 唯一来源：为空或含非法条目时，
        // 启动/init 必须尽早失败（签发层还会再校验一次，这里给出配置级错误）。
        crate::tls::parse_server_sans(&self.server_names)
            .map_err(|err| Error::InvalidConfig(format!("server_names 非法: {err}")))?;
        Ok(())
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
    /// 单管理员的 Argon2id PHC 密码哈希；`panel init` 生成。
    #[serde(default)]
    pub admin_password_hash: String,
    /// 会话有效期（小时）。
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: u64,
    /// 静态资源目录；留空则依次尝试 `web/dist` 与 `/usr/share/rustboard/web`。
    #[serde(default)]
    pub static_dir: String,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            listen: default_panel_listen(),
            hub_url: format!("http://127.0.0.1:{}", crate::DEFAULT_ADMIN_PORT),
            token: String::new(),
            admin_password_hash: String::new(),
            session_ttl_hours: default_session_ttl_hours(),
            static_dir: String::new(),
        }
    }
}

/// 默认只监听回环地址，端口固定为 `DEFAULT_PANEL_PORT`。
///
/// `Default` 是纯函数、不做端口探测 I/O：缺 `listen` 的配置每次 `ports`/`run`
/// 必须得到同一个地址。随机端口只在 `rustboard-panel init` 未传 `--listen` 时选取并落盘。
/// 面板在 M2 只有明文 HTTP，绝不能默认监听 `0.0.0.0`。
fn default_panel_listen() -> String {
    format!("127.0.0.1:{}", crate::DEFAULT_PANEL_PORT)
}

impl PanelConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }
}

fn default_buffer_max_age_hours() -> u64 {
    24
}

/// 证书有效期允许范围（天），与 `tls` 层的签发校验保持一致。
const MIN_VALIDITY_DAYS: u32 = 1;
const MAX_VALIDITY_DAYS: u32 = 36_500;

/// 服务端证书续签检查周期下限（秒）。
const MIN_CERT_CHECK_INTERVAL_SECS: u64 = 60;

/// agent 主动重连周期上限（1 年）；0 表示不主动重连。
const MAX_SESSION_MAX_HOURS: u64 = 24 * 365;

fn default_cert_renew_before_days() -> u32 {
    30
}

fn default_session_max_hours() -> u64 {
    12
}

fn default_session_ttl_hours() -> u64 {
    12
}

fn default_ca_validity_days() -> u32 {
    3650
}

fn default_server_cert_validity_days() -> u32 {
    365
}

fn default_client_cert_validity_days() -> u32 {
    90
}

fn default_renew_before_days() -> u32 {
    30
}

fn default_cert_check_interval_secs() -> u64 {
    6 * 3600
}

pub fn default_excluded_interfaces() -> Vec<String> {
    ["lo", "docker", "veth", "br-", "virbr", "cni", "flannel"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H2：`max_connections` 缺省为 1024，老配置文件不需要显式写这一项。
    #[test]
    fn h2_hub_config_max_connections_is_backward_compatible() {
        let cfg: HubConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.max_connections, 1024);

        let cfg: HubConfig = toml::from_str("max_connections = 32\n").unwrap();
        assert_eq!(cfg.max_connections, 32);
    }

    /// v0.1 的配置文件没有新增字段，必须全部走默认值而不是解析失败。
    #[test]
    fn v02_config_defaults_are_backward_compatible() {
        let agent: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(agent.cert_renew_before_days, 30);
        assert_eq!(agent.session_max_hours, 12);

        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.ca_validity_days, 3650);
        assert_eq!(hub.server_cert_validity_days, 365);
        assert_eq!(hub.client_cert_validity_days, 90);
        assert_eq!(hub.renew_before_days, 30);
        assert_eq!(hub.cert_check_interval_secs, 21_600);
        assert!(hub.admin_token.is_empty());

        let panel: PanelConfig = toml::from_str("").unwrap();
        assert_eq!(panel.session_ttl_hours, 12);
        assert!(panel.admin_password_hash.is_empty());
        assert!(panel.static_dir.is_empty());
        // 面板只有明文 HTTP：默认只绑回环，且固定 8080，不能依赖随机 I/O。
        assert_eq!(
            panel.listen,
            format!("127.0.0.1:{}", crate::DEFAULT_PANEL_PORT)
        );
    }

    /// `Default` 必须幂等：缺 `listen` 的配置反复加载得到同一地址；
    /// 随机端口只属于 `panel init` 的职责。
    #[test]
    fn panel_listen_default_is_stable_and_can_be_overridden() {
        let first = PanelConfig::default();
        let second = PanelConfig::default();
        assert_eq!(first.listen, "127.0.0.1:8080");
        assert_eq!(first.listen, second.listen, "Default 不能在内部选随机端口");

        let loaded: PanelConfig = toml::from_str("").unwrap();
        assert_eq!(loaded.listen, first.listen);

        let panel: PanelConfig = toml::from_str("listen = \"0.0.0.0:18080\"\n").unwrap();
        assert_eq!(panel.listen, "0.0.0.0:18080");
    }

    /// 默认配置必须通过校验（老版本配置文件缺字段时也走默认值）。
    #[test]
    fn v02_default_configs_pass_validation() {
        let hub: HubConfig = toml::from_str("").unwrap();
        hub.validate().expect("默认 hub 配置必须合法");

        let agent: AgentConfig = toml::from_str("").unwrap();
        agent.validate().expect("默认 agent 配置必须合法");
    }

    /// 有效期 / 续签阈值 / 检查周期的非法组合必须被拒绝，且错误信息点名具体字段。
    #[test]
    fn v02_hub_config_validation_rejects_bad_values() {
        let cases: [(HubConfig, &str); 8] = [
            (
                HubConfig {
                    ca_validity_days: 0,
                    ..HubConfig::default()
                },
                "ca_validity_days",
            ),
            (
                HubConfig {
                    server_cert_validity_days: MAX_VALIDITY_DAYS + 1,
                    ..HubConfig::default()
                },
                "server_cert_validity_days",
            ),
            (
                HubConfig {
                    client_cert_validity_days: 0,
                    ..HubConfig::default()
                },
                "client_cert_validity_days",
            ),
            (
                HubConfig {
                    renew_before_days: 0,
                    ..HubConfig::default()
                },
                "renew_before_days",
            ),
            (
                HubConfig {
                    renew_before_days: 365,
                    ..HubConfig::default()
                },
                "必须小于",
            ),
            (
                HubConfig {
                    cert_check_interval_secs: MIN_CERT_CHECK_INTERVAL_SECS - 1,
                    ..HubConfig::default()
                },
                "cert_check_interval_secs",
            ),
            (
                HubConfig {
                    server_names: Vec::new(),
                    ..HubConfig::default()
                },
                "server_names",
            ),
            (
                HubConfig {
                    server_names: vec!["bad name".to_string()],
                    ..HubConfig::default()
                },
                "server_names",
            ),
        ];
        for (cfg, needle) in cases {
            let err = cfg.validate().expect_err("非法配置必须被拒绝").to_string();
            assert!(err.contains(needle), "错误信息应包含 {needle}: {err}");
        }

        // 边界值合法：恰好 1 天有效期 + 2 天阈值 + 60 秒周期。
        let edge = HubConfig {
            ca_validity_days: MIN_VALIDITY_DAYS,
            server_cert_validity_days: 2,
            client_cert_validity_days: MIN_VALIDITY_DAYS,
            renew_before_days: 1,
            cert_check_interval_secs: MIN_CERT_CHECK_INTERVAL_SECS,
            ..HubConfig::default()
        };
        edge.validate().expect("边界值必须合法");
    }

    /// agent 侧：续签阈值至少 1 天，主动重连周期不得超过上限，0 表示不主动重连。
    #[test]
    fn v02_agent_config_validation_checks_renew_and_session_limits() {
        let cfg: AgentConfig = toml::from_str("").unwrap();
        assert!(cfg.validate().is_ok());

        let zero_renew = AgentConfig {
            cert_renew_before_days: 0,
            ..AgentConfig::default()
        };
        assert!(zero_renew.validate().is_err());

        let too_long = AgentConfig {
            session_max_hours: MAX_SESSION_MAX_HOURS + 1,
            ..AgentConfig::default()
        };
        let err = too_long.validate().unwrap_err().to_string();
        assert!(err.contains("session_max_hours"), "错误信息: {err}");

        // 0 表示不主动重连，必须合法。
        let disabled = AgentConfig {
            session_max_hours: 0,
            ..AgentConfig::default()
        };
        assert!(disabled.validate().is_ok());
    }
}
