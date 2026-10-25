//! M5 Phase C C3/C4：ACME 证书管理。
//!
//! 模块边界：
//! - [`store`]：账户 / 状态 / 服务端证书材料的原子落盘与权限控制；
//! - [`challenge`]：HTTP-01 / TLS-ALPN-01 临时挑战服务；
//! - [`client`]：instant-acme 账户、订单、CSR 与证书获取；
//! - [`renewal`]：到期判断、周期续期、退避与热加载。
//!
//! 安全约束：账户私钥（`account.json`）与证书私钥（`server.key`）只落盘为
//! 0600；日志只允许出现域名、指纹、到期时间等公开信息，绝不打印 token、
//! key authorization、账户 key 或证书私钥。

use rustboard_common::config::{ServerTlsMode, TlsConfig};

pub mod challenge;
pub mod client;
pub mod renewal;
pub mod store;

/// 本次订单实际使用的 ACME profile：显式配置优先；`acme-ip` 留空时用
/// `shortlived`（6 天短期证书，D8 的 48h 续期阈值依赖它），域名模式留空不设置。
pub fn effective_profile(tls: &TlsConfig) -> Option<&str> {
    let configured = tls.acme_profile.trim();
    if !configured.is_empty() {
        return Some(configured);
    }
    match tls.mode {
        ServerTlsMode::AcmeIp => Some("shortlived"),
        ServerTlsMode::AcmeDomain | ServerTlsMode::SelfSigned => None,
    }
}
