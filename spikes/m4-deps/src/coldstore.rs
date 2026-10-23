//! `ColdStore` 抽象与 S3 实现（方案 §7.3）。
//!
//! 这里只做依赖 spike：验证 `object_store`（仅 AWS feature）能提供
//! 自定义 endpoint、path_style、静态凭证，以及 put/get/head/delete 的编译期 API。
//! 运行时是否真连网由 `main` 的环境变量开关决定。

use anyhow::{bail, Result};
use async_trait::async_trait;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::ObjectStore;
use std::sync::Arc;

/// M4 冷归档后端抽象，与方案 §7.3 保持一致。
#[async_trait]
pub trait ColdStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn test(&self) -> Result<()>;
}

/// 内存实现：让 `ColdStore` trait 在无网络时也能被实例化和调用。
#[derive(Default)]
pub struct MemoryColdStore {
    objects: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl ColdStore for MemoryColdStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        self.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("内存 store 锁中毒"))?
            .insert(key.to_owned(), data.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        match self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("内存 store 锁中毒"))?
            .get(key)
        {
            Some(data) => Ok(data.clone()),
            None => bail!("object not found: {key}"),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("内存 store 锁中毒"))?
            .remove(key);
        Ok(())
    }

    async fn test(&self) -> Result<()> {
        Ok(())
    }
}

/// S3/MinIO 配置（对应 hub.toml 的 `[archive.s3]`）。
pub struct S3Config<'a> {
    pub bucket: &'a str,
    pub region: &'a str,
    /// 空 = AWS 官方端点；MinIO 等兼容服务填写 `http(s)://host:port`。
    pub endpoint: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    /// true = path-style（`endpoint/bucket/key`），MinIO 通常需要。
    pub path_style: bool,
    /// 仅当 endpoint 是 http 时显式允许明文，生产应使用 https。
    pub allow_http: bool,
}

/// `object_store` 的 S3 后端封装。
pub struct S3ColdStore {
    store: Arc<dyn ObjectStore>,
}

impl S3ColdStore {
    pub fn new(cfg: &S3Config<'_>) -> Result<Self> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(cfg.bucket)
            .with_region(cfg.region)
            .with_access_key_id(cfg.access_key_id)
            .with_secret_access_key(cfg.secret_access_key)
            .with_allow_http(cfg.allow_http)
            // object_store 0.11 的“虚拟主机风格”开关：false 即 path-style
            // （`https://endpoint/bucket/objects/...`），兼容 MinIO。
            .with_virtual_hosted_style_request(!cfg.path_style);

        if !cfg.endpoint.is_empty() {
            builder = builder.with_endpoint(cfg.endpoint);
        }
        if cfg.bucket.is_empty() {
            bail!("archive.s3.bucket 不能为空");
        }

        Ok(Self {
            store: Arc::new(builder.build()?),
        })
    }

    fn path(key: &str) -> ObjectPath {
        ObjectPath::from(key)
    }
}

#[async_trait]
impl ColdStore for S3ColdStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        self.store
            .put(&Self::path(key), data.to_vec().into())
            .await?;
        // 方案 §7.2：写入后 head 校验对象存在。
        let meta = self.store.head(&Self::path(key)).await?;
        if meta.size != data.len() {
            bail!(
                "head 校验失败：key={key} 期望 {} 字节，实际 {} 字节",
                data.len(),
                meta.size
            );
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        Ok(self
            .store
            .get(&Self::path(key))
            .await?
            .bytes()
            .await?
            .to_vec())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.store.delete(&Self::path(key)).await?;
        Ok(())
    }

    async fn test(&self) -> Result<()> {
        // 只读列举即可验证 endpoint/凭证/网络连通性，且不写入任何数据。
        self.store.list_with_delimiter(None).await?;
        Ok(())
    }
}
