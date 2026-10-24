//! 安装角色。

use std::fmt;

use serde::{Deserialize, Serialize};

/// RustBoard 的三个安装角色。
///
/// TOML 中统一使用小写字符串（`hub` / `agent` / `panel`），既用于 state 的
/// `[roles.<role>]`，也用于默认文件名。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Hub,
    Agent,
    Panel,
}

impl Role {
    /// 所有角色，按 hub / agent / panel 的固定顺序。
    pub const ALL: [Role; 3] = [Role::Hub, Role::Agent, Role::Panel];

    /// 小写角色名，用于文件名与 state 键。
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Hub => "hub",
            Role::Agent => "agent",
            Role::Panel => "panel",
        }
    }

    /// 二进制文件名，例如 `rustboard-hub`。
    pub const fn binary_name(self) -> &'static str {
        match self {
            Role::Hub => "rustboard-hub",
            Role::Agent => "rustboard-agent",
            Role::Panel => "rustboard-panel",
        }
    }

    /// systemd unit 文件名，例如 `rustboard-hub.service`。
    pub const fn unit_name(self) -> &'static str {
        match self {
            Role::Hub => "rustboard-hub.service",
            Role::Agent => "rustboard-agent.service",
            Role::Panel => "rustboard-panel.service",
        }
    }

    /// 默认配置文件名，例如 `hub.toml`。
    pub const fn config_name(self) -> &'static str {
        match self {
            Role::Hub => "hub.toml",
            Role::Agent => "agent.toml",
            Role::Panel => "panel.toml",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_stable() {
        assert_eq!(Role::Hub.as_str(), "hub");
        assert_eq!(Role::Agent.binary_name(), "rustboard-agent");
        assert_eq!(Role::Panel.unit_name(), "rustboard-panel.service");
        assert_eq!(Role::Hub.config_name(), "hub.toml");
        assert_eq!(Role::ALL.len(), 3);
    }

    #[test]
    fn role_serde_is_lowercase() {
        let state = std::collections::BTreeMap::from([(Role::Hub, 1u8)]);
        let text = toml::to_string(&state).unwrap();
        assert_eq!(text.trim(), "hub = 1");
        let back: std::collections::BTreeMap<Role, u8> = toml::from_str(&text).unwrap();
        assert_eq!(back.get(&Role::Hub), Some(&1));
    }
}
