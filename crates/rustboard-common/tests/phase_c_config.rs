//! M5 Phase C C2：配置兼容、三种 hub TLS 模式、agent 三模式与面板 cert/key 校验。
//!
//! 这些用例只依赖 `rustboard_common::config` 的公开接口；不读磁盘、不访问网络。

use std::path::PathBuf;

use rustboard_common::config::{
    AcmeChallenge, AgentConfig, AgentTlsMode, HubConfig, PanelConfig, ServerTlsMode, TlsConfig,
    DEFAULT_ACME_DIRECTORY,
};

fn hub_from_toml(text: &str) -> HubConfig {
    toml::from_str(text).expect("测试 TOML 必须能反序列化")
}

fn valid_fingerprint() -> String {
    "ab".repeat(32)
}

fn acme_domain_tls() -> TlsConfig {
    TlsConfig {
        mode: ServerTlsMode::AcmeDomain,
        acme_email: "admin@example.com".to_string(),
        domains: vec!["board.example.com".to_string()],
        ..TlsConfig::default()
    }
}

fn acme_ip_tls() -> TlsConfig {
    TlsConfig {
        mode: ServerTlsMode::AcmeIp,
        acme_email: "admin@example.com".to_string(),
        domains: vec!["203.0.113.10".to_string()],
        ..TlsConfig::default()
    }
}

fn agent_with(
    mode: AgentTlsMode,
    hub_url: &str,
    fingerprint: &str,
    server_ca: &str,
) -> AgentConfig {
    AgentConfig {
        hub_url: hub_url.to_string(),
        tls_mode: mode,
        server_fingerprint: fingerprint.to_string(),
        server_ca: server_ca.to_string(),
        data_dir: PathBuf::from("/var/lib/rustboard/agent"),
        ..AgentConfig::default()
    }
}

/// C-G1：旧 hub.toml / agent.toml / panel.toml 不写任何新字段时行为不变。
#[test]
fn c2_legacy_configs_default_to_v04_behavior() {
    // --- hub：缺 [tls] → self-signed，ACME 字段全部默认，不要求填写 ---
    let hub: HubConfig = hub_from_toml("");
    assert_eq!(hub.tls.mode, ServerTlsMode::SelfSigned);
    assert_eq!(hub.tls.mode.as_str(), "self-signed");
    assert!(hub.tls.acme_email.is_empty());
    assert_eq!(hub.tls.acme_directory, DEFAULT_ACME_DIRECTORY);
    assert_eq!(hub.tls.challenge, AcmeChallenge::Http01);
    assert_eq!(hub.tls.challenge.as_str(), "http-01");
    assert!(hub.tls.domains.is_empty());
    assert!(hub.tls.acme_profile.is_empty());
    assert!(hub.tls.acme_ca_file.is_empty());
    assert!(hub.tls.staging_check, "默认安装前跑 staging 检查");
    assert!(hub.tls.fallback_to_self_signed, "默认失败回退 self-signed");
    assert_eq!(
        hub.effective_server_names(),
        hub.server_names,
        "self-signed 的 SAN 仍只取 server_names"
    );
    hub.validate().expect("旧 hub 配置必须能通过校验");

    // 旧配置显式 server_names 仍生效；空 server_names 在 self-signed 下仍必须报错。
    let explicit = hub_from_toml("server_names = [\"hub.example.com\"]\n");
    explicit.validate().expect("显式 server_names 必须合法");
    assert_eq!(
        explicit.effective_server_names(),
        vec!["hub.example.com".to_string()]
    );
    let empty_names = HubConfig {
        server_names: Vec::new(),
        ..HubConfig::default()
    };
    let err = empty_names
        .validate()
        .expect_err("self-signed 且 server_names 为空必须拒绝")
        .to_string();
    assert!(
        err.contains("server_names"),
        "错误必须点名 server_names: {err}"
    );

    // self-signed 不要求也不校验 ACME 字段（旧行为：不因无关字段启动失败）。
    let self_signed_with_junk_acme = HubConfig {
        tls: TlsConfig {
            acme_email: "not-an-email".to_string(),
            acme_directory: "http://acme.invalid/dir".to_string(),
            domains: vec!["*.example.com".to_string()],
            acme_ca_file: "relative/ca.pem".to_string(),
            ..TlsConfig::default()
        },
        ..HubConfig::default()
    };
    self_signed_with_junk_acme
        .validate()
        .expect("self-signed 模式不得因未使用的 ACME 字段拒绝启动");

    // --- agent：缺 tls_mode/server_ca → fingerprint，旧校验不变 ---
    let legacy_agent: AgentConfig = toml::from_str(&format!(
        "hub_url = \"wss://hub.example.com:8443/agent/ws\"\nserver_fingerprint = \"{}\"\n",
        valid_fingerprint()
    ))
    .unwrap();
    assert_eq!(legacy_agent.tls_mode, AgentTlsMode::Fingerprint);
    assert_eq!(legacy_agent.tls_mode.as_str(), "fingerprint");
    assert!(legacy_agent.server_ca.is_empty());
    legacy_agent.validate().expect("旧 agent 配置必须能启动");

    let missing_fingerprint: AgentConfig =
        toml::from_str("hub_url = \"wss://hub.example.com:8443/agent/ws\"\n").unwrap();
    let err = missing_fingerprint
        .validate()
        .expect_err("旧规则：wss 必须配置指纹")
        .to_string();
    assert!(err.contains("server_fingerprint"), "错误信息: {err}");

    // --- panel：缺 tls_cert/tls_key → 空，仍然 HTTP ---
    let panel: PanelConfig = toml::from_str("").unwrap();
    assert!(panel.tls_cert.is_empty());
    assert!(panel.tls_key.is_empty());
    panel.validate().expect("旧 panel 配置必须合法");
}

/// hub `acme-domain`：合法正例 + email/directory/domains/profile/ca 文件负例。
#[test]
fn c2_hub_acme_domain_validation() {
    let valid = HubConfig {
        server_names: Vec::new(),
        tls: acme_domain_tls(),
        ..HubConfig::default()
    };
    valid.validate().expect("合法 acme-domain 配置必须通过");
    assert_eq!(
        valid.effective_server_names(),
        vec!["board.example.com".to_string()],
        "ACME 模式的 SAN 来自 tls.domains"
    );

    // 多个域名、自定义 directory（带 path/query）、profile、私有 CA 与
    // tls-alpn-01 都是合法组合。
    let mut full = acme_domain_tls();
    full.domains = vec![
        "board.example.com".to_string(),
        "www.example.com".to_string(),
    ];
    full.acme_directory = "https://acme.internal.example.com/dir?env=test".to_string();
    full.challenge = AcmeChallenge::TlsAlpn01;
    full.acme_profile = "shortlived".to_string();
    full.acme_ca_file = "/etc/rustboard/acme-ca.pem".to_string();
    full.staging_check = false;
    full.fallback_to_self_signed = false;
    HubConfig {
        server_names: Vec::new(),
        tls: full,
        ..HubConfig::default()
    }
    .validate()
    .expect("完整合法 acme-domain 组合必须通过");

    // TOML 层枚举名称（显式 rename，不能是 tls-alpn01/http01）。
    let cfg: HubConfig = toml::from_str(
        "server_names = []\n[tls]\nmode = \"acme-domain\"\n\
         acme_email = \"admin@example.com\"\n\
         domains = [\"board.example.com\"]\n\
         challenge = \"tls-alpn-01\"\nstaging_check = false\n\
         fallback_to_self_signed = false\n",
    )
    .unwrap();
    assert_eq!(cfg.tls.challenge, AcmeChallenge::TlsAlpn01);
    assert!(!cfg.tls.staging_check);
    assert!(!cfg.tls.fallback_to_self_signed);
    cfg.validate().expect("显式 tls-alpn-01 配置必须合法");

    let base = acme_domain_tls();
    let cases: Vec<(&str, TlsConfig, &str)> = vec![
        (
            "空 email",
            TlsConfig {
                acme_email: String::new(),
                ..base.clone()
            },
            "acme_email",
        ),
        (
            "两个 @",
            TlsConfig {
                acme_email: "a@@example.com".to_string(),
                ..base.clone()
            },
            "acme_email",
        ),
        (
            "缺少域名部分",
            TlsConfig {
                acme_email: "admin@".to_string(),
                ..base.clone()
            },
            "acme_email",
        ),
        (
            "含空白",
            TlsConfig {
                acme_email: "admin @example.com".to_string(),
                ..base.clone()
            },
            "acme_email",
        ),
        (
            "domains 为空",
            TlsConfig {
                domains: Vec::new(),
                ..base.clone()
            },
            "tls.domains",
        ),
        (
            "domains 超过 20",
            TlsConfig {
                domains: (0..21)
                    .map(|index| format!("h{index}.example.com"))
                    .collect(),
                ..base.clone()
            },
            "1–20",
        ),
        (
            "通配符",
            TlsConfig {
                domains: vec!["*.example.com".to_string()],
                ..base.clone()
            },
            "通配符",
        ),
        (
            "acme-domain 填 IP",
            TlsConfig {
                domains: vec!["203.0.113.10".to_string()],
                ..base.clone()
            },
            "acme-domain",
        ),
        (
            "下划线标签",
            TlsConfig {
                domains: vec!["bad_name.example.com".to_string()],
                ..base.clone()
            },
            "标签",
        ),
        (
            "标签以 - 开头",
            TlsConfig {
                domains: vec!["-bad.example.com".to_string()],
                ..base.clone()
            },
            "标签",
        ),
        (
            "连续点",
            TlsConfig {
                domains: vec!["a..example.com".to_string()],
                ..base.clone()
            },
            "标签",
        ),
        (
            "http directory",
            TlsConfig {
                acme_directory: "http://acme.example.com/dir".to_string(),
                ..base.clone()
            },
            "acme_directory",
        ),
        (
            "directory 带 userinfo",
            TlsConfig {
                acme_directory: "https://user:pass@acme.example.com/dir".to_string(),
                ..base.clone()
            },
            "userinfo",
        ),
        (
            "directory 带 fragment",
            TlsConfig {
                acme_directory: "https://acme.example.com/dir#frag".to_string(),
                ..base.clone()
            },
            "fragment",
        ),
        (
            "acme_ca_file 相对路径",
            TlsConfig {
                acme_ca_file: "certs/acme-ca.pem".to_string(),
                ..base.clone()
            },
            "acme_ca_file",
        ),
        (
            "acme_ca_file 含 NUL",
            TlsConfig {
                acme_ca_file: "/etc/rustboard/acme\0.pem".to_string(),
                ..base.clone()
            },
            "acme_ca_file",
        ),
        (
            "profile 含空格",
            TlsConfig {
                acme_profile: "short lived".to_string(),
                ..base.clone()
            },
            "acme_profile",
        ),
    ];
    for (name, tls, needle) in cases {
        let cfg = HubConfig {
            server_names: Vec::new(),
            tls,
            ..HubConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err(&format!("{name} 应被拒绝"))
            .to_string();
        assert!(
            err.contains(needle),
            "{name} 的错误必须包含 {needle}: {err}"
        );
    }

    // 枚举值拼错必须在反序列化阶段失败，不能静默回退默认值。
    for toml in [
        "[tls]\nmode = \"acme-dns\"\n",
        "[tls]\nmode = \"acme-domain\"\nchallenge = \"http01\"\n",
    ] {
        let err = toml::from_str::<HubConfig>(toml).expect_err("非法枚举必须解析失败");
        let text = err.to_string();
        assert!(
            text.contains("mode") || text.contains("challenge"),
            "错误应点名字段: {text}"
        );
    }
}

/// hub `acme-ip`：恰好一个 IPv4；拒绝 IPv6/多值/空/域名。
#[test]
fn c2_hub_acme_ip_validation() {
    let valid = HubConfig {
        server_names: Vec::new(),
        tls: acme_ip_tls(),
        ..HubConfig::default()
    };
    valid.validate().expect("合法 acme-ip 配置必须通过");
    assert_eq!(
        valid.effective_server_names(),
        vec!["203.0.113.10".to_string()],
        "acme-ip 的 SAN 是 domains 里的 IP 字符串"
    );

    let mut with_profile = acme_ip_tls();
    with_profile.acme_profile = "shortlived".to_string();
    HubConfig {
        server_names: Vec::new(),
        tls: with_profile,
        ..HubConfig::default()
    }
    .validate()
    .expect("显式 shortlived profile 必须合法");

    let base = acme_ip_tls();
    let cases: Vec<(&str, TlsConfig, &str)> = vec![
        (
            "IPv6",
            TlsConfig {
                domains: vec!["2001:db8::1".to_string()],
                ..base.clone()
            },
            "IPv6",
        ),
        (
            "两个 IP",
            TlsConfig {
                domains: vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()],
                ..base.clone()
            },
            "恰好",
        ),
        (
            "空 domains",
            TlsConfig {
                domains: Vec::new(),
                ..base.clone()
            },
            "恰好",
        ),
        (
            "域名",
            TlsConfig {
                domains: vec!["board.example.com".to_string()],
                ..base.clone()
            },
            "IPv4",
        ),
        (
            "带端口",
            TlsConfig {
                domains: vec!["203.0.113.10:443".to_string()],
                ..base.clone()
            },
            "IPv4",
        ),
        (
            "IPv4 带空格",
            TlsConfig {
                domains: vec![" 203.0.113.10".to_string()],
                ..base.clone()
            },
            "空白",
        ),
        (
            "空 email",
            TlsConfig {
                acme_email: String::new(),
                ..base.clone()
            },
            "acme_email",
        ),
    ];
    for (name, tls, needle) in cases {
        let cfg = HubConfig {
            server_names: Vec::new(),
            tls,
            ..HubConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err(&format!("{name} 应被拒绝"))
            .to_string();
        assert!(
            err.contains(needle),
            "{name} 的错误必须包含 {needle}: {err}"
        );
    }

    // 只设置 acme-ip 模式、不写 domains：必须失败，不能拿 server_names 顶替。
    let cfg: HubConfig =
        toml::from_str("[tls]\nmode = \"acme-ip\"\nacme_email = \"admin@example.com\"\n").unwrap();
    let err = cfg
        .validate()
        .expect_err("缺少 domains 必须拒绝")
        .to_string();
    assert!(err.contains("tls.domains"), "错误信息: {err}");
}

/// agent 三模式：wss 的信任源要求、绝对路径与旧配置默认值。
#[test]
fn c2_agent_tls_modes_validation() {
    let wss = "wss://hub.example.com:8443/agent/ws";
    let ws = "ws://127.0.0.1:8443/agent/ws";

    // fingerprint：保持旧行为（wss 必须有指纹）。
    let err = agent_with(AgentTlsMode::Fingerprint, wss, "", "")
        .validate()
        .expect_err("fingerprint + 空指纹必须拒绝")
        .to_string();
    assert!(err.contains("server_fingerprint"), "错误信息: {err}");
    agent_with(AgentTlsMode::Fingerprint, wss, &valid_fingerprint(), "")
        .validate()
        .expect("fingerprint + 合法指纹必须通过");

    // system-roots：不要求 fingerprint/server_ca。
    agent_with(AgentTlsMode::SystemRoots, wss, "", "")
        .validate()
        .expect("system-roots 不要求指纹/CA");
    agent_with(AgentTlsMode::SystemRoots, wss, &valid_fingerprint(), "")
        .validate()
        .expect("system-roots 携带旧指纹也应允许（字段不参与校验）");

    // custom-ca：必须绝对路径 server_ca；指纹可选。
    let err = agent_with(AgentTlsMode::CustomCa, wss, "", "")
        .validate()
        .expect_err("custom-ca + 空 server_ca 必须拒绝")
        .to_string();
    assert!(err.contains("server_ca"), "错误信息: {err}");
    let err = agent_with(
        AgentTlsMode::CustomCa,
        wss,
        "",
        "/etc/rustboard/server-ca.pem",
    )
    .validate();
    assert!(err.is_ok(), "合法 custom-ca 必须通过: {err:?}");
    agent_with(
        AgentTlsMode::CustomCa,
        wss,
        &valid_fingerprint(),
        "/etc/rustboard/server-ca.pem",
    )
    .validate()
    .expect("custom-ca 可选指纹");

    let err = agent_with(AgentTlsMode::CustomCa, wss, "", "relative/ca.pem")
        .validate()
        .expect_err("server_ca 相对路径必须拒绝")
        .to_string();
    assert!(err.contains("绝对路径"), "错误信息: {err}");

    // 非空 server_ca 只在 custom-ca 模式允许；其他模式必须显式拒绝，
    // 不能等到运行期才被静默忽略。
    for mode in [AgentTlsMode::Fingerprint, AgentTlsMode::SystemRoots] {
        let fingerprint = if mode == AgentTlsMode::Fingerprint {
            valid_fingerprint()
        } else {
            String::new()
        };
        let err = agent_with(mode, wss, &fingerprint, "/etc/rustboard/server-ca.pem")
            .validate()
            .expect_err("非 custom-ca 模式携带 server_ca 必须拒绝")
            .to_string();
        assert!(err.contains("server_ca"), "错误信息: {err}");
    }
    let err = agent_with(
        AgentTlsMode::Fingerprint,
        wss,
        &valid_fingerprint(),
        "ca.pem",
    )
    .validate()
    .expect_err("fingerprint 模式下非空 server_ca 也要拒绝")
    .to_string();
    assert!(err.contains("server_ca"), "错误信息: {err}");

    // ws:// 明文：只允许 fingerprint（旧行为）；system-roots / custom-ca
    // 的 CA 与主机名校验会被忽略，必须拒绝。
    agent_with(AgentTlsMode::Fingerprint, ws, "", "")
        .validate()
        .expect("ws:// + fingerprint 允许空指纹");
    for mode in [AgentTlsMode::SystemRoots, AgentTlsMode::CustomCa] {
        let err = agent_with(mode, ws, "", "")
            .validate()
            .expect_err("ws:// + 非 fingerprint 必须拒绝")
            .to_string();
        assert!(
            err.contains("ws://") && err.contains("fingerprint"),
            "错误信息必须点明 ws:// 只允许 fingerprint: {err}"
        );
        assert!(
            err.contains(mode.as_str()),
            "错误信息必须点明实际模式 {}: {err}",
            mode.as_str()
        );
    }

    // serde：kebab-case 名称可解析；未知值必须失败。
    let cfg: AgentConfig = toml::from_str(
        "hub_url = \"wss://hub.example.com:8443/agent/ws\"\n\
         tls_mode = \"system-roots\"\nserver_ca = \"/etc/rustboard/server-ca.pem\"\n",
    )
    .unwrap();
    assert_eq!(cfg.tls_mode, AgentTlsMode::SystemRoots);
    assert_eq!(cfg.server_ca, "/etc/rustboard/server-ca.pem");
    let err = cfg
        .validate()
        .expect_err("system-roots 携带 server_ca 必须在校验时拒绝")
        .to_string();
    assert!(err.contains("server_ca"), "错误信息: {err}");
    let err = toml::from_str::<AgentConfig>("tls_mode = \"ca\"\n").expect_err("未知模式必须失败");
    assert!(err.to_string().contains("tls_mode"), "错误信息: {err}");
}

/// panel：`tls_cert` / `tls_key` 必须成对且为绝对路径；默认仍 HTTP。
#[test]
fn c2_panel_tls_cert_key_pair_validation() {
    PanelConfig::default()
        .validate()
        .expect("空配置（HTTP）合法");

    let https = PanelConfig {
        tls_cert: "/etc/rustboard/panel-tls/cert.pem".to_string(),
        tls_key: "/etc/rustboard/panel-tls/key.pem".to_string(),
        ..PanelConfig::default()
    };
    https.validate().expect("成对的绝对路径必须合法");

    for (cert, key, needle) in [
        ("/etc/rustboard/cert.pem", "", "成对"),
        ("", "/etc/rustboard/key.pem", "成对"),
        ("certs/panel.pem", "/etc/rustboard/key.pem", "绝对路径"),
        ("/etc/rustboard/cert.pem", "keys/panel.key", "绝对路径"),
        (
            "/etc/rustboard/cert\0.pem",
            "/etc/rustboard/key.pem",
            "控制字符",
        ),
    ] {
        let cfg = PanelConfig {
            tls_cert: cert.to_string(),
            tls_key: key.to_string(),
            ..PanelConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("非法 cert/key 组合必须拒绝")
            .to_string();
        assert!(err.contains(needle), "错误必须包含 {needle}: {err}");
    }

    // TOML 字段名与 serde 往返。
    let cfg: PanelConfig = toml::from_str(
        "tls_cert = \"/etc/rustboard/cert.pem\"\n\
         tls_key = \"/etc/rustboard/key.pem\"\n",
    )
    .unwrap();
    assert_eq!(cfg.tls_cert, "/etc/rustboard/cert.pem");
    let text = toml::to_string(&cfg).unwrap();
    let roundtrip: PanelConfig = toml::from_str(&text).unwrap();
    assert_eq!(roundtrip.tls_cert, cfg.tls_cert);
    assert_eq!(roundtrip.tls_key, cfg.tls_key);
}
