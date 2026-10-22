//! RustBoard 公共库：协议帧、数据模型、配置与工具函数。

pub mod config;
pub mod error;
pub mod model;
pub mod tls;
pub mod util;
pub mod wire;

pub use error::{Error, Result};

/// 产品版本，取自 crate 元数据。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 线协议版本。hub 兼容低一个版本的 agent。
pub const PROTOCOL_VERSION: u16 = 1;

pub const DEFAULT_AGENT_CONFIG: &str = "/etc/rustboard/agent.toml";
pub const DEFAULT_HUB_CONFIG: &str = "/etc/rustboard/hub.toml";
pub const DEFAULT_PANEL_CONFIG: &str = "/etc/rustboard/panel.toml";

pub const DEFAULT_AGENT_PORT: u16 = 8443;
pub const DEFAULT_ADMIN_PORT: u16 = 8444;
pub const DEFAULT_PANEL_PORT: u16 = 8080;
