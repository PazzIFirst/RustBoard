use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
    /// 会话空闲时的客户端证书检查周期（小时）。
    ///
    /// 即使 `session_max_hours = 0`（永不主动重连），也要周期检查证书剩余寿命，
    /// 否则超长会话会错过续签窗口。范围 1–168。
    #[serde(default = "default_cert_check_interval_hours")]
    pub cert_check_interval_hours: u64,
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
            cert_check_interval_hours: default_cert_check_interval_hours(),
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
        // 会话内周期检查必须有下界：0 会让定时器变成忙循环，超长周期则等于没检查。
        if !(MIN_CERT_CHECK_INTERVAL_HOURS..=MAX_CERT_CHECK_INTERVAL_HOURS)
            .contains(&self.cert_check_interval_hours)
        {
            return Err(Error::InvalidConfig(format!(
                "cert_check_interval_hours 必须在 {MIN_CERT_CHECK_INTERVAL_HOURS}–\
                 {MAX_CERT_CHECK_INTERVAL_HOURS} 小时之间，实际 {}",
                self.cert_check_interval_hours
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
    /// 单个来源 IP 的并发连接上限（1–256）。防止单机洪水挤占全部连接槽位。
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// SQLite 只读连接池大小（1–16）。写连接始终只有 1 条。
    #[serde(default = "default_read_pool_size")]
    pub read_pool_size: usize,
    /// 管理 API 每 IP 每分钟请求上限（固定窗口）；0 表示关闭。
    #[serde(default = "default_admin_rate_limit_per_min")]
    pub admin_rate_limit_per_min: u32,
    /// 管理 API 写操作（PUT/POST/PATCH/DELETE）每 IP 每分钟上限；0 表示关闭。
    #[serde(default = "default_admin_write_rate_limit_per_min")]
    pub admin_write_rate_limit_per_min: u32,
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

/// 单来源 IP 默认并发连接上限。
fn default_max_connections_per_ip() -> usize {
    16
}

/// SQLite 只读连接池默认大小。
fn default_read_pool_size() -> usize {
    4
}

/// 管理 API 默认每 IP 每分钟请求上限。
fn default_admin_rate_limit_per_min() -> u32 {
    60
}

/// 管理 API 写操作默认每 IP 每分钟上限。
fn default_admin_write_rate_limit_per_min() -> u32 {
    10
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
            max_connections_per_ip: default_max_connections_per_ip(),
            read_pool_size: default_read_pool_size(),
            admin_rate_limit_per_min: default_admin_rate_limit_per_min(),
            admin_write_rate_limit_per_min: default_admin_write_rate_limit_per_min(),
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
        // 单 IP 上限必须为正且远小于总上限：否则等于没有来源维度的隔离。
        if !(MIN_CONNECTIONS_PER_IP..=MAX_CONNECTIONS_PER_IP).contains(&self.max_connections_per_ip)
        {
            return Err(Error::InvalidConfig(format!(
                "max_connections_per_ip 必须在 {MIN_CONNECTIONS_PER_IP}–\
                 {MAX_CONNECTIONS_PER_IP} 之间，实际 {}",
                self.max_connections_per_ip
            )));
        }
        // 读连接池大小有硬上限：连接数是文件句柄，配置写错不能把 fd 吃光。
        if !(MIN_READ_POOL_SIZE..=MAX_READ_POOL_SIZE).contains(&self.read_pool_size) {
            return Err(Error::InvalidConfig(format!(
                "read_pool_size 必须在 {MIN_READ_POOL_SIZE}–{MAX_READ_POOL_SIZE} 之间，实际 {}",
                self.read_pool_size
            )));
        }
        // 0 表示关闭限速；其余按每分钟请求数校验。
        if self.admin_rate_limit_per_min > MAX_ADMIN_RATE_LIMIT_PER_MIN {
            return Err(Error::InvalidConfig(format!(
                "admin_rate_limit_per_min 不能超过 {MAX_ADMIN_RATE_LIMIT_PER_MIN}（0 表示关闭），\
                 实际 {}",
                self.admin_rate_limit_per_min
            )));
        }
        if self.admin_write_rate_limit_per_min > MAX_ADMIN_RATE_LIMIT_PER_MIN {
            return Err(Error::InvalidConfig(format!(
                "admin_write_rate_limit_per_min 不能超过 {MAX_ADMIN_RATE_LIMIT_PER_MIN}\
                 （0 表示关闭），实际 {}",
                self.admin_write_rate_limit_per_min
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
    /// 可信反代地址（精确 IP 或 CIDR）。只有直连对端命中时，才采信 `X-Forwarded-*`。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// 会话 Cookie 的 `Secure` 属性策略。
    #[serde(default)]
    pub cookie_secure: CookieSecure,
    /// 面板的对外访问源（例如 `https://panel.example.com`），用于 Origin 校验。
    #[serde(default)]
    pub public_origin: String,
}

/// 面板会话 Cookie 的 `Secure` 策略。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CookieSecure {
    /// 仅当直连对端是可信反代且声明 `X-Forwarded-Proto: https` 时加 Secure。
    #[default]
    Auto,
    /// 无条件加 Secure（面板本身走 HTTPS 或整个链路强制 HTTPS）。
    Always,
    /// 不加 Secure（仅限本地明文调试）。
    Never,
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
            trusted_proxies: Vec::new(),
            cookie_secure: CookieSecure::Auto,
            public_origin: String::new(),
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

    /// 面板配置自洽性校验：可信反代地址与 `public_origin` 的语法。
    ///
    /// 非法 CIDR / Origin 必须在启动时失败并点名字段，不能被静默忽略——
    /// 否则运维会以为反代已被信任，实际仍按直连 IP 限速与判定 Cookie。
    pub fn validate(&self) -> Result<()> {
        for proxy in &self.trusted_proxies {
            if !is_valid_trusted_proxy(proxy) {
                return Err(Error::InvalidConfig(format!(
                    "trusted_proxies 含非法条目 {proxy:?}：只接受精确 IP 或 CIDR（例如 10.0.0.0/8）"
                )));
            }
        }
        let origin = self.public_origin.trim();
        if !origin.is_empty() {
            validate_public_origin(origin)?;
        }
        Ok(())
    }
}

/// 可信反代条目：精确 IP 或 `IP/前缀长度`。
fn is_valid_trusted_proxy(entry: &str) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }
    match entry.split_once('/') {
        None => entry.parse::<IpAddr>().is_ok(),
        Some((ip, prefix)) => {
            let Ok(ip) = ip.parse::<IpAddr>() else {
                return false;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            match ip {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            }
        }
    }
}

/// `public_origin` 只允许 `scheme://host[:port]`，不接受路径 / 查询串。
fn validate_public_origin(origin: &str) -> Result<()> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "public_origin 必须以 http:// 或 https:// 开头，实际 {origin:?}"
            ))
        })?;
    if rest.is_empty() {
        return Err(Error::InvalidConfig(
            "public_origin 缺少主机名（例如 https://panel.example.com）".into(),
        ));
    }
    if rest
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '?' || c == '#' || c == '@')
    {
        return Err(Error::InvalidConfig(format!(
            "public_origin 只能是 scheme://host[:port]，不能带路径 / 查询串或空白，实际 {origin:?}"
        )));
    }
    Ok(())
}

fn default_buffer_max_age_hours() -> u64 {
    24
}

/// 证书有效期允许范围（天），与 `tls` 层的签发校验保持一致。
const MIN_VALIDITY_DAYS: u32 = 1;
const MAX_VALIDITY_DAYS: u32 = 36_500;

/// 服务端证书续签检查周期下限（秒）。
const MIN_CERT_CHECK_INTERVAL_SECS: u64 = 60;

/// 单来源 IP 并发连接上限的允许范围。
const MIN_CONNECTIONS_PER_IP: usize = 1;
const MAX_CONNECTIONS_PER_IP: usize = 256;

/// SQLite 只读连接池允许范围。
const MIN_READ_POOL_SIZE: usize = 1;
const MAX_READ_POOL_SIZE: usize = 16;

/// 管理 API 每分钟请求上限的硬上限（0 表示关闭限速）。
const MAX_ADMIN_RATE_LIMIT_PER_MIN: u32 = 6_000;

/// agent 会话内证书检查周期的允许范围（小时）。
const MIN_CERT_CHECK_INTERVAL_HOURS: u64 = 1;
const MAX_CERT_CHECK_INTERVAL_HOURS: u64 = 168;

/// agent 主动重连周期上限（1 年）；0 表示不主动重连。
const MAX_SESSION_MAX_HOURS: u64 = 24 * 365;

fn default_cert_renew_before_days() -> u32 {
    30
}

fn default_session_max_hours() -> u64 {
    12
}

fn default_cert_check_interval_hours() -> u64 {
    6
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

    /// v0.2.1 新增字段：缺省值必须与方案一致，旧配置不写也能启动。
    #[test]
    fn v021_hardening_defaults_are_backward_compatible() {
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.max_connections_per_ip, 16);
        assert_eq!(hub.read_pool_size, 4);
        assert_eq!(hub.admin_rate_limit_per_min, 60);
        assert_eq!(hub.admin_write_rate_limit_per_min, 10);

        let agent: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(agent.cert_check_interval_hours, 6);

        let panel: PanelConfig = toml::from_str("").unwrap();
        assert!(panel.trusted_proxies.is_empty());
        assert_eq!(panel.cookie_secure, CookieSecure::Auto);
        assert!(panel.public_origin.is_empty());

        // 显式配置必须被读取。
        let hub: HubConfig = toml::from_str(
            "max_connections_per_ip = 8\nread_pool_size = 2\n\
             admin_rate_limit_per_min = 0\nadmin_write_rate_limit_per_min = 5\n",
        )
        .unwrap();
        assert_eq!(hub.max_connections_per_ip, 8);
        assert_eq!(hub.read_pool_size, 2);
        assert_eq!(hub.admin_rate_limit_per_min, 0);
        assert_eq!(hub.admin_write_rate_limit_per_min, 5);

        let panel: PanelConfig = toml::from_str(
            "trusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\", \"::1/128\"]\n\
             cookie_secure = \"always\"\npublic_origin = \"https://panel.example.com:8443\"\n",
        )
        .unwrap();
        assert_eq!(panel.trusted_proxies.len(), 3);
        assert_eq!(panel.cookie_secure, CookieSecure::Always);
        assert_eq!(panel.public_origin, "https://panel.example.com:8443");
        panel.validate().expect("合法面板配置必须通过校验");
    }

    /// 非法 `cookie_secure` 值必须在反序列化阶段失败，不能静默回退 auto。
    #[test]
    fn v021_cookie_secure_rejects_unknown_values() {
        let err = toml::from_str::<PanelConfig>("cookie_secure = \"sometimes\"\n")
            .expect_err("未知 CookieSecure 值必须解析失败");
        assert!(err.to_string().contains("cookie_secure"), "错误信息: {err}");

        for (text, expected) in [
            ("auto", CookieSecure::Auto),
            ("always", CookieSecure::Always),
            ("never", CookieSecure::Never),
        ] {
            let cfg: PanelConfig =
                toml::from_str(&format!("cookie_secure = \"{text}\"\n")).unwrap();
            assert_eq!(cfg.cookie_secure, expected);
        }
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

    /// v0.2.1 新增配置项的非法值必须在启动前被拒绝，且错误信息点名字段。
    #[test]
    fn v021_config_validation_rejects_out_of_range_values() {
        let hub_cases: [(HubConfig, &str); 6] = [
            (
                HubConfig {
                    max_connections_per_ip: 0,
                    ..HubConfig::default()
                },
                "max_connections_per_ip",
            ),
            (
                HubConfig {
                    max_connections_per_ip: 257,
                    ..HubConfig::default()
                },
                "max_connections_per_ip",
            ),
            (
                HubConfig {
                    read_pool_size: 0,
                    ..HubConfig::default()
                },
                "read_pool_size",
            ),
            (
                HubConfig {
                    read_pool_size: 17,
                    ..HubConfig::default()
                },
                "read_pool_size",
            ),
            (
                HubConfig {
                    admin_rate_limit_per_min: 6_001,
                    ..HubConfig::default()
                },
                "admin_rate_limit_per_min",
            ),
            (
                HubConfig {
                    admin_write_rate_limit_per_min: 6_001,
                    ..HubConfig::default()
                },
                "admin_write_rate_limit_per_min",
            ),
        ];
        for (cfg, needle) in hub_cases {
            let err = cfg.validate().expect_err("非法配置必须被拒绝").to_string();
            assert!(err.contains(needle), "错误信息应包含 {needle}: {err}");
        }

        // 边界值：1 / 256 / 16 与 0（关闭限速）/ 6000 全部合法。
        let edge = HubConfig {
            max_connections_per_ip: 256,
            read_pool_size: 16,
            admin_rate_limit_per_min: 6_000,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        };
        edge.validate().expect("边界值必须合法");
        let edge = HubConfig {
            max_connections_per_ip: 1,
            read_pool_size: 1,
            admin_rate_limit_per_min: 0,
            ..HubConfig::default()
        };
        edge.validate().expect("最小值必须合法");

        // agent 会话内证书检查周期：1–168 小时，0 与 169 都非法。
        for hours in [0, 169] {
            let cfg = AgentConfig {
                cert_check_interval_hours: hours,
                ..AgentConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err("非法检查周期必须被拒绝")
                .to_string();
            assert!(err.contains("cert_check_interval_hours"), "错误信息: {err}");
        }
        for hours in [1, 168] {
            let cfg = AgentConfig {
                cert_check_interval_hours: hours,
                ..AgentConfig::default()
            };
            cfg.validate().expect("边界检查周期必须合法");
        }
    }

    /// 面板可信反代 / public_origin 的语法校验。
    #[test]
    fn v021_panel_config_validation_rejects_bad_proxies_and_origin() {
        let valid = PanelConfig {
            trusted_proxies: vec![
                "127.0.0.1".to_string(),
                "10.0.0.0/8".to_string(),
                "2001:db8::/32".to_string(),
                "::1/128".to_string(),
            ],
            cookie_secure: CookieSecure::Never,
            public_origin: "http://panel.example.com".to_string(),
            ..PanelConfig::default()
        };
        valid.validate().expect("合法配置必须通过");

        for bad in [
            "10.0.0.0/33",
            "2001:db8::/129",
            "not-an-ip",
            "10.0.0.0/",
            "",
            "10.0.0.1/8/9",
        ] {
            let cfg = PanelConfig {
                trusted_proxies: vec![bad.to_string()],
                ..PanelConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err(&format!("非法 trusted_proxies 条目必须被拒绝: {bad}"))
                .to_string();
            assert!(err.contains("trusted_proxies"), "错误信息: {err}");
        }

        for bad in [
            "panel.example.com",
            "ftp://panel.example.com",
            "https://",
            "https://panel.example.com/path",
            "https://panel.example.com?x=1",
            "https://panel.example.com #frag",
        ] {
            let cfg = PanelConfig {
                public_origin: bad.to_string(),
                ..PanelConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err(&format!("非法 public_origin 必须被拒绝: {bad}"))
                .to_string();
            assert!(err.contains("public_origin"), "错误信息: {err}");
        }

        // 空字符串表示未配置，必须合法。
        PanelConfig::default().validate().expect("空配置必须合法");
    }
}
