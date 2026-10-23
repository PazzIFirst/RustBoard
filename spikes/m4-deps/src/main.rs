//! M4 冷归档依赖 spike（方案 §12）。
//!
//! 本工程只验证依赖可编译与 API 形状，不进入根 workspace、不参与 M4 实现。
//! 默认只跑本地可离线验证的部分（flate2 / HMAC / async-trait）；真实 S3/SFTP
//! 连通性通过环境变量显式开启，避免 CI 或本地误连外部服务。

mod coldstore;
mod sftp;

use anyhow::{bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

use coldstore::{ColdStore, MemoryColdStore, S3ColdStore, S3Config};

#[tokio::main]
async fn main() -> Result<()> {
    println!("declared rust-version = {}", env!("CARGO_PKG_RUST_VERSION"));

    // 1. flate2 rust_backend：gzip 压缩/解压往返。
    let raw = b"agent_id,metric,labels,ts,value\nhub-1,disk_used,{\"mount\":\"/\"},1,42\n";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(raw).context("flate2 压缩写入失败")?;
    let gz = encoder.finish().context("flate2 finish 失败")?;

    let mut decoder = flate2::read::GzDecoder::new(gz.as_slice());
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .context("flate2 解压失败")?;
    if decoded != raw {
        bail!("flate2 往返内容不一致");
    }
    println!(
        "flate2(rust_backend) ok: {} -> {} 字节",
        raw.len(),
        gz.len()
    );

    // 2. HMAC-SHA256（与仓库已有 sha2 0.10 配对）。
    let mut mac = Hmac::<Sha256>::new_from_slice(b"spike-key").context("HMAC key 非法")?;
    mac.update(raw);
    let tag = mac.finalize().into_bytes();
    let tag_hex: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("hmac-sha256 ok: {tag_hex}");

    // 3. async-trait 定义的 ColdStore：用内存实现跑通 put/get/delete/test。
    let store: Box<dyn ColdStore> = Box::new(MemoryColdStore::default());
    let key = "objects/2026/10/24/0001.csv.gz";
    store.put(key, &gz).await?;
    if store.get(key).await? != gz {
        bail!("ColdStore 内存实现回读不一致");
    }
    store.test().await?;
    store.delete(key).await?;
    println!("async-trait ColdStore ok");

    // 4. S3：仅当显式设置 M4_SPIKE_S3=1 时真连网。
    if std::env::var("M4_SPIKE_S3").as_deref() == Ok("1") {
        s3_smoke().await?;
    }

    // 5. SFTP：仅当显式设置 M4_SPIKE_SFTP=1 时真连网。
    if std::env::var("M4_SPIKE_SFTP").as_deref() == Ok("1") {
        let cfg = sftp::SftpConfig::from_env()?;
        sftp::smoke(&cfg).await?;
    }

    println!("m4-deps spike: 本地检查全部通过");
    Ok(())
}

/// 真实 S3/MinIO 冒烟：put → get → head（put 内部）→ delete。
async fn s3_smoke() -> Result<()> {
    let bucket = std::env::var("M4_SPIKE_S3_BUCKET").context("缺少 M4_SPIKE_S3_BUCKET")?;
    let endpoint = std::env::var("M4_SPIKE_S3_ENDPOINT").unwrap_or_default();
    let region = std::env::var("M4_SPIKE_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
    let access_key_id =
        std::env::var("M4_SPIKE_S3_ACCESS_KEY").context("缺少 M4_SPIKE_S3_ACCESS_KEY")?;
    let secret_access_key =
        std::env::var("M4_SPIKE_S3_SECRET_KEY").context("缺少 M4_SPIKE_S3_SECRET_KEY")?;
    let path_style = std::env::var("M4_SPIKE_S3_PATH_STYLE").as_deref() != Ok("0");

    let store = S3ColdStore::new(&S3Config {
        bucket: &bucket,
        region: &region,
        endpoint: &endpoint,
        access_key_id: &access_key_id,
        secret_access_key: &secret_access_key,
        path_style,
        allow_http: endpoint.starts_with("http://"),
    })?;

    let key = "objects/2026/10/24/spike.csv.gz";
    store.put(key, b"s3 spike payload").await?;
    let data = store.get(key).await?;
    if data != b"s3 spike payload" {
        bail!("S3 回读内容不一致");
    }
    store.test().await?;
    store.delete(key).await?;
    println!("s3 ok: bucket={bucket} key={key}");
    Ok(())
}
