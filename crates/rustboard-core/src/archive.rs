//! M4-C1：冷归档核心模型。
//!
//! 本模块只提供**与后端无关**的能力，WebDAV 上传实现属于 C1b：
//!
//! - [`ArchiveObject`] / [`ArchiveStatus`] / [`ArchiveManifest`]：数据库与对象
//!   元数据模型，状态字符串稳定为 `pending` / `uploaded` / `local_deleted` /
//!   `failed`；
//! - [`ColdStore`]：冷存储异步 trait（`put/get/delete/head/test`），错误全部是
//!   **固定中文枚举**，不携带后端 URL、凭据或响应正文，避免日志泄露；
//! - [`CsvArchiveWriter`]：把 raw 采样写成 `csv.gz`（纯 Rust `flate2`
//!   rust_backend），返回压缩后字节数、行数与 SHA-256；
//! - [`ArchiveManifest`]：与对象同目录、同名的 `.manifest.json`，字段顺序固定，
//!   JSON 稳定换行；
//! - [`build_object_keys`]：只由 prefix + UTC 日期 + 分片生成对象 key，拒绝
//!   路径穿越与绝对路径，不接受任何外部输入拼路径。
//!
//! 安全约定：
//! - 归档对象 key 的每一个可变部分都被校验，不会产生 `..` / 绝对路径；
//! - `sha256` 基于**压缩后**的字节计算，manifest 与 `archive_objects` 一致；
//! - CSV 字段按 RFC 4180 规则转义（逗号、引号、CR/LF），labels 原样保存 JSON。

use std::fmt;
use std::io::Write;
use std::str::FromStr;

use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// CSV 表头；所有归档对象的第一行固定为它。
pub const CSV_HEADER: &str = "agent_id,metric,labels,ts,value";

/// manifest 格式版本；结构发生不兼容变更时递增。
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// 归档 prefix 允许的最大字节数（与配置校验一致）。
pub const MAX_ARCHIVE_PREFIX_BYTES: usize = 64;

/// 分片最大编号（`part-00001` ..= `part-99999`）。
pub const MAX_ARCHIVE_SHARD: u32 = 99_999;

/// v7 旧归档对象的 ledger 版本：没有 claim 行集，只能作为历史对象保留。
pub const LEDGER_VERSION_V7: i64 = 0;

/// v8 claim 对象的 ledger 版本：`archive_objects` 必须能通过
/// `samples.archive_object_id` 找到同一行集。
pub const LEDGER_VERSION_V8: i64 = 1;

/// `archive_state` 中的 v8 ledger 重建待办标记：为 `1` 时 raw 保留期必须跳过。
pub const STATE_ARCHIVE_LEDGER_PENDING: &str = "archive_ledger_pending";

// ---------------------------------------------------------------------------
// 领域错误
// ---------------------------------------------------------------------------

/// 归档核心错误。
///
/// 所有 `Display` 都是固定中文，**不拼接后端 URL / 凭据 / 响应正文**；
/// C1b 的后端实现只能把底层错误映射到这些分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveError {
    /// 对象 key / 日期 / 分片非法（含路径穿越与绝对路径）。
    InvalidKey,
    /// manifest JSON 无法解析或字段不合法。
    InvalidManifest,
    /// 数据库 / 外部写入的状态字符串非法。
    InvalidStatus,
    /// CSV / gzip 编码失败（本地内存写入，通常意味着实现缺陷）。
    Encode,
    /// 冷存储后端未配置、不可达或认证失败。
    BackendUnavailable,
    /// 后端对象不存在。
    NotFound,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidKey => "归档对象 key 非法",
            Self::InvalidManifest => "归档 manifest 非法",
            Self::InvalidStatus => "归档对象状态非法",
            Self::Encode => "归档数据编码失败",
            Self::BackendUnavailable => "冷存储后端不可用",
            Self::NotFound => "归档对象不存在",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ArchiveError {}

/// 归档模块的统一 `Result`。
pub type ArchiveResult<T> = std::result::Result<T, ArchiveError>;

/// `archive_objects` 的领域错误。
///
/// 存储层只返回这四类错误；HTTP 状态码映射由 C1b / C4 的 API 层负责。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveStoreError {
    /// `object_key` 已存在（UNIQUE 冲突），不得重复上传同一 key。
    ObjectExists,
    /// 指定 id / key 的归档对象不存在。
    NotFound,
    /// 状态迁移非法，例如 `local_deleted -> uploaded` 回退。
    InvalidTransition,
    /// claim 行集与扫描结果不一致（并发 claim / 行已被删除）。
    ///
    /// 可重试：调用方必须整事务回滚，重新扫描未认领行后生成新对象。
    ClaimConflict,
}

impl fmt::Display for ArchiveStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ObjectExists => "归档对象已存在",
            Self::NotFound => "归档对象不存在",
            Self::InvalidTransition => "归档对象状态迁移非法",
            Self::ClaimConflict => "归档行集已被其他任务认领或删除，请重试",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ArchiveStoreError {}

// ---------------------------------------------------------------------------
// 状态与对象
// ---------------------------------------------------------------------------

/// 归档对象状态。
///
/// 数据库与 API 里的字符串稳定为：
/// `pending` / `uploaded` / `local_deleted` / `failed`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveStatus {
    /// 已生成对象、等待上传（或正在上传）。
    #[default]
    Pending,
    /// 后端已确认写入。
    Uploaded,
    /// 上传成功且本地 raw 已删除。
    LocalDeleted,
    /// 上传 / 校验失败；保留 raw 等待重试。
    Failed,
}

impl ArchiveStatus {
    /// 稳定字符串表示。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Uploaded => "uploaded",
            Self::LocalDeleted => "local_deleted",
            Self::Failed => "failed",
        }
    }

    /// 解析数据库 / API 字符串；未知值返回 `None`，不静默降级。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "uploaded" => Some(Self::Uploaded),
            "local_deleted" => Some(Self::LocalDeleted),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// 是否允许迁移到 `next`。
    ///
    /// 正常路径 `pending -> uploaded -> local_deleted`；失败可以从 `pending` /
    /// `uploaded` 进入 `failed`，并允许 `failed -> pending|uploaded` 重试。
    /// `local_deleted` 是终态，只能原值更新（幂等），不能回退到任何其它状态。
    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        matches!(
            (self, next),
            (Self::Pending, Self::Uploaded | Self::Failed)
                | (Self::Uploaded, Self::LocalDeleted | Self::Failed)
                | (Self::Failed, Self::Pending | Self::Uploaded)
        )
    }
}

impl FromStr for ArchiveStatus {
    type Err = ArchiveError;

    fn from_str(value: &str) -> ArchiveResult<Self> {
        Self::parse(value).ok_or(ArchiveError::InvalidStatus)
    }
}

/// 一条归档对象记录，与 `archive_objects` 表一一对应。
///
/// `id` 在插入时由数据库生成（插入 API 会忽略传入值并返回新 id）。
/// `ledger_version` 区分 v7 旧对象（[`LEDGER_VERSION_V7`]）与 v8 claim
/// 对象（[`LEDGER_VERSION_V8`]）；旧构造代码可用 `..Default::default()`
/// 得到默认的 v7 语义。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArchiveObject {
    pub id: i64,
    /// 后端标识：`webdav` / `s3` / `sftp`。
    pub backend: String,
    /// 压缩对象 key，例如 `rustboard/2026/10/24/part-00001.csv.gz`。
    pub object_key: String,
    /// 同名 manifest key，以 `.manifest.json` 结尾。
    pub manifest_key: String,
    /// 对象覆盖的 raw 时间范围 `[from_ts, to_ts]`（Unix 毫秒）。
    pub from_ts: i64,
    pub to_ts: i64,
    /// 归档行数。
    pub rows: u64,
    /// 压缩后字节数。
    pub bytes: u64,
    /// 压缩后字节的 SHA-256（小写 hex）。
    pub sha256: String,
    pub status: ArchiveStatus,
    /// 最近一次失败原因；成功时为空。
    pub error: String,
    /// 记录创建时间（Unix 毫秒）。
    pub created_at: i64,
    /// 上传完成时间；未上传为 `None`。
    pub uploaded_at: Option<i64>,
    /// 本地 raw 删除完成时间；未删除为 `None`。
    pub deleted_at: Option<i64>,
    /// ledger 版本：0 = v7 旧对象，1 = v8 claim 对象。
    pub ledger_version: i64,
    /// failed 重试次数（仅 v8 claim 对象使用；旧对象默认 0）。
    pub attempts: i64,
}

/// 归档对象的 manifest；与 `.csv.gz` 同目录、同 basename。
///
/// 字段顺序固定（serde 按声明顺序序列化），JSON 输出带一个末尾换行，
/// 保证同一对象重复生成的 manifest 字节级一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub format_version: u32,
    pub object_key: String,
    pub from_ts: i64,
    pub to_ts: i64,
    pub rows: u64,
    pub bytes: u64,
    pub sha256: String,
    pub created_at: i64,
}

impl ArchiveManifest {
    /// 按当前格式版本构造 manifest。
    pub fn new(
        object_key: impl Into<String>,
        from_ts: i64,
        to_ts: i64,
        rows: u64,
        bytes: u64,
        sha256: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            format_version: MANIFEST_FORMAT_VERSION,
            object_key: object_key.into(),
            from_ts,
            to_ts,
            rows,
            bytes,
            sha256: sha256.into(),
            created_at,
        }
    }

    /// 序列化为稳定的 pretty JSON（字段顺序固定，末尾带换行）。
    pub fn to_json(&self) -> ArchiveResult<String> {
        let mut text =
            serde_json::to_string_pretty(self).map_err(|_| ArchiveError::InvalidManifest)?;
        text.push('\n');
        Ok(text)
    }

    /// 解析 manifest JSON；非法内容返回 [`ArchiveError::InvalidManifest`]。
    pub fn from_json(text: &str) -> ArchiveResult<Self> {
        serde_json::from_str(text).map_err(|_| ArchiveError::InvalidManifest)
    }
}

/// 把 manifest 序列化为稳定 JSON（字段顺序固定、末尾换行）。
pub fn manifest_json(manifest: &ArchiveManifest) -> ArchiveResult<String> {
    manifest.to_json()
}

// ---------------------------------------------------------------------------
// 冷存储 trait
// ---------------------------------------------------------------------------

/// 后端对象的 HEAD 元数据。
///
/// 只暴露校验所需的大小，不暴露 ETag / URL / 响应头，避免把后端细节带进日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdObjectMeta {
    /// 对象字节数。
    pub size: u64,
}

/// 冷存储后端抽象；WebDAV 实现在 C1b，S3 / SFTP 在 C2 / C3。
///
/// 实现约定：
/// - 错误必须是 [`ArchiveError`] 的固定分类，**不得**把后端 URL、用户名、
///   密码、token 或响应正文拼进错误 / 日志；
/// - [`ColdStore::head`] 对不存在返回 `Ok(None)`，只有后端故障才返回错误；
/// - 所有 key 都来自 [`build_object_keys`]，实现不得接受外部构造的路径。
#[async_trait]
pub trait ColdStore: Send + Sync {
    /// 写入对象（覆盖写由后端语义决定；调用方先查再传）。
    async fn put(&self, key: &str, data: &[u8]) -> ArchiveResult<()>;

    /// 读取完整对象；不存在返回 [`ArchiveError::NotFound`]。
    async fn get(&self, key: &str) -> ArchiveResult<Vec<u8>>;

    /// 删除对象；不存在按成功处理（幂等），其它失败返回错误。
    async fn delete(&self, key: &str) -> ArchiveResult<()>;

    /// 查询对象是否存在；存在时返回大小。
    async fn head(&self, key: &str) -> ArchiveResult<Option<ColdObjectMeta>>;

    /// 后端连通性 / 认证测试；不做任何写入。
    async fn test(&self) -> ArchiveResult<()>;
}

// ---------------------------------------------------------------------------
// 对象 key
// ---------------------------------------------------------------------------

/// 一个 UTC 日期（归档按 UTC 天分目录）。
///
/// 只能在 `1970-01-01 ..= 9999-12-31` 范围内构造；字段私有，保证实例合法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchiveDay {
    year: u32,
    month: u32,
    day: u32,
}

impl ArchiveDay {
    /// 构造并校验 UTC 日期（含闰年规则）。
    pub fn new(year: u32, month: u32, day: u32) -> ArchiveResult<Self> {
        if !(1970..=9999).contains(&year) {
            return Err(ArchiveError::InvalidKey);
        }
        if !(1..=12).contains(&month) {
            return Err(ArchiveError::InvalidKey);
        }
        if day == 0 || day > days_in_month(year, month) {
            return Err(ArchiveError::InvalidKey);
        }
        Ok(Self { year, month, day })
    }

    pub fn year(self) -> u32 {
        self.year
    }

    pub fn month(self) -> u32 {
        self.month
    }

    pub fn day(self) -> u32 {
        self.day
    }
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        // 月份已在上方校验；这里返回 0 让日期校验必然失败。
        _ => 0,
    }
}

/// 一个归档对象的两个 key：压缩对象与 manifest。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveObjectKeys {
    pub object_key: String,
    pub manifest_key: String,
}

/// 生成归档对象 key：
/// `<prefix>/<yyyy>/<mm>/<dd>/<shard>.csv.gz` 与同名 `.manifest.json`。
///
/// 只接受已校验的 UTC 日期与 `part-00001` 形式的分片名；prefix 只允许
/// `[A-Za-z0-9._-]`、非空、≤64 字节、不含 `..`。任何非法输入都返回
/// [`ArchiveError::InvalidKey`]，不会拼出绝对路径或 `..`。
pub fn build_object_keys(
    prefix: &str,
    day: ArchiveDay,
    shard: &str,
) -> ArchiveResult<ArchiveObjectKeys> {
    validate_prefix(prefix)?;
    let shard_number = validate_shard(shard)?;
    let base = format!(
        "{prefix}/{:04}/{:02}/{:02}/part-{shard_number:05}",
        day.year, day.month, day.day
    );
    Ok(ArchiveObjectKeys {
        object_key: format!("{base}.csv.gz"),
        manifest_key: format!("{base}.manifest.json"),
    })
}

/// prefix 规则与配置校验一致；这里再校验一次，防止调用方绕过配置。
fn validate_prefix(prefix: &str) -> ArchiveResult<()> {
    if prefix.is_empty()
        || prefix.len() > MAX_ARCHIVE_PREFIX_BYTES
        || prefix.contains("..")
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(ArchiveError::InvalidKey);
    }
    Ok(())
}

/// 分片名固定 `part-` + 5 位数字，编号 1..=99999。
fn validate_shard(shard: &str) -> ArchiveResult<u32> {
    let digits = shard
        .strip_prefix("part-")
        .ok_or(ArchiveError::InvalidKey)?;
    if digits.len() != 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ArchiveError::InvalidKey);
    }
    let number = digits
        .parse::<u32>()
        .map_err(|_| ArchiveError::InvalidKey)?;
    if !(1..=MAX_ARCHIVE_SHARD).contains(&number) {
        return Err(ArchiveError::InvalidKey);
    }
    Ok(number)
}

// ---------------------------------------------------------------------------
// CSV.GZ
// ---------------------------------------------------------------------------

/// 一个 CSV.GZ 归档对象的生成结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvArchiveOutput {
    /// 压缩后的完整字节（上传内容）。
    pub data: Vec<u8>,
    /// 数据行数（不含表头）。
    pub rows: u64,
    /// 压缩后字节数，等于 `data.len()`。
    pub bytes: u64,
    /// 压缩后字节的 SHA-256（小写 hex）。
    pub sha256: String,
}

/// 流式 CSV.GZ 写入器。
///
/// 使用 `flate2::write::GzEncoder` + `Compression::default`（纯 Rust
/// rust_backend），不会把未压缩数据整体驻留内存之外的额外结构；表头在首个
/// 数据行或 [`Self::finish`] 时写入，保证空对象也有表头。
#[derive(Debug)]
pub struct CsvArchiveWriter {
    encoder: GzEncoder<Vec<u8>>,
    rows: u64,
    header_written: bool,
}

impl Default for CsvArchiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl CsvArchiveWriter {
    /// 创建写入器。
    pub fn new() -> Self {
        Self {
            encoder: GzEncoder::new(Vec::new(), Compression::default()),
            rows: 0,
            header_written: false,
        }
    }

    /// 当前已写入的数据行数（不含表头）。
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// 写入一行原始采样。
    ///
    /// - `labels` 是原始 JSON 文本，按 CSV 规则转义（含逗号 / 引号 / 换行）；
    /// - `agent_id` / `metric` 同样转义，避免恶意或异常字段破坏列结构；
    /// - `value` 使用 `f64` 的最短可往返十进制表示，与 locale / 平台无关。
    pub fn write_row(
        &mut self,
        agent_id: &str,
        metric: &str,
        labels: &str,
        ts: i64,
        value: f64,
    ) -> ArchiveResult<()> {
        self.write_header()?;

        let mut line = String::new();
        push_csv_field(&mut line, agent_id);
        line.push(',');
        push_csv_field(&mut line, metric);
        line.push(',');
        push_csv_field(&mut line, labels);
        line.push(',');
        line.push_str(&ts.to_string());
        line.push(',');
        line.push_str(&format_csv_value(value));
        line.push('\n');

        self.encoder
            .write_all(line.as_bytes())
            .map_err(|_| ArchiveError::Encode)?;
        self.rows += 1;
        Ok(())
    }

    /// 结束写入，返回压缩字节、行数、字节数与 SHA-256。
    pub fn finish(mut self) -> ArchiveResult<CsvArchiveOutput> {
        self.write_header()?;
        let data = self.encoder.finish().map_err(|_| ArchiveError::Encode)?;
        let bytes = data.len() as u64;
        let sha256 = sha256_hex(&data);
        Ok(CsvArchiveOutput {
            data,
            rows: self.rows,
            bytes,
            sha256,
        })
    }

    fn write_header(&mut self) -> ArchiveResult<()> {
        if self.header_written {
            return Ok(());
        }
        self.encoder
            .write_all(format!("{CSV_HEADER}\n").as_bytes())
            .map_err(|_| ArchiveError::Encode)?;
        self.header_written = true;
        Ok(())
    }
}

/// f64 的稳定十进制表示；`Display` 输出最短可往返表示，不受 locale 影响。
pub fn format_csv_value(value: f64) -> String {
    value.to_string()
}

/// 按 RFC 4180 规则追加一个 CSV 字段：包含逗号 / 双引号 / CR / LF 时加引号，
/// 内部双引号写成两个双引号。
fn push_csv_field(out: &mut String, field: &str) {
    let needs_quotes = field
        .bytes()
        .any(|b| matches!(b, b',' | b'"' | b'\n' | b'\r'));
    if !needs_quotes {
        out.push_str(field);
        return;
    }
    out.push('"');
    for ch in field.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
}

/// 计算字节的 SHA-256，返回小写 hex。
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
