//! RustBoard 公共库：协议帧、数据模型、配置与工具函数。

pub mod config;
pub mod error;
pub mod fsutil;
pub mod model;
pub mod tls;
pub mod util;
pub mod wire;

pub use error::{Error, Result};

/// 产品版本，取自 crate 元数据。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 线协议版本。
///
/// hub 与 agent 必须完全一致：协议不兼容时 agent 会直接退出，
/// 避免带着错误的数据格式进入无限重连。
pub const PROTOCOL_VERSION: u16 = 2;

pub const DEFAULT_AGENT_CONFIG: &str = "/etc/rustboard/agent.toml";
pub const DEFAULT_HUB_CONFIG: &str = "/etc/rustboard/hub.toml";
pub const DEFAULT_PANEL_CONFIG: &str = "/etc/rustboard/panel.toml";

pub const DEFAULT_AGENT_PORT: u16 = 8443;
pub const DEFAULT_ADMIN_PORT: u16 = 8444;
pub const DEFAULT_PANEL_PORT: u16 = 8080;
