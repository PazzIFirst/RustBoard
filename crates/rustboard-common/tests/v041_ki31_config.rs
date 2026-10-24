//! v0.4.1 KI-31：`archive.max_object_bytes` 上限收敛到 64 MiB 的独立回归。
//!
//! 依据 `docs/plans/2026-10-24-known-issues-fix.md` §3.2：
//! - 64 MiB（67 108 864）必须通过校验；
//! - 64 MiB + 1 必须在启动 / 配置校验阶段被拒绝；
//! - 下界 1 MiB 与默认 32 MiB 不变。
//!
//! 只使用 `rustboard_common::config::ArchiveConfig::validate` 公开接口，
//! 不依赖 hub 内部下载实现。v0.4.0 基线上 64 MiB + 1 会被接受，故本用例失败。

use rustboard_common::config::ArchiveConfig;

const MIB: u64 = 1024 * 1024;
/// 64 MiB：修复后允许的最大单对象字节数。
const MAX_BYTES: u64 = 64 * MIB;

/// 构造只覆盖 `max_object_bytes` 的归档配置，其余字段用默认值。
fn archive_config(max_object_bytes: u64) -> ArchiveConfig {
    ArchiveConfig {
        max_object_bytes,
        ..ArchiveConfig::default()
    }
}

#[test]
fn v041_ki31_archive_max_object_bytes_rejects_above_64_mib() {
    let cfg = archive_config(MAX_BYTES);
    cfg.validate()
        .expect("archive.max_object_bytes = 64 MiB 必须通过校验（上界包含）");

    let cfg = archive_config(MAX_BYTES + 1);
    let err = cfg
        .validate()
        .expect_err("archive.max_object_bytes = 64 MiB + 1 必须在启动/校验时被拒绝");
    let message = err.to_string();
    assert!(
        message.contains("max_object_bytes"),
        "拒绝错误应点名字段 archive.max_object_bytes，实际: {message}"
    );

    // 旧上界 1 GiB 及更大的值同样必须拒绝，避免只对 64 MiB+1 做特判。
    let cfg = archive_config(128 * MIB);
    assert!(
        cfg.validate().is_err(),
        "128 MiB 超过下载内存上限，必须被拒绝"
    );
}

#[test]
fn v041_ki31_archive_max_object_bytes_lower_bound_and_default_unchanged() {
    let cfg = ArchiveConfig::default();
    assert_eq!(
        cfg.max_object_bytes,
        32 * MIB,
        "默认值必须保持 32 MiB（方案：默认不变）"
    );
    cfg.validate().expect("默认 32 MiB 必须通过校验");

    let cfg = archive_config(MIB);
    cfg.validate().expect("下界 1 MiB 必须通过校验");

    let cfg = archive_config(MIB - 1);
    assert!(cfg.validate().is_err(), "1 MiB - 1 必须维持拒绝");
}
