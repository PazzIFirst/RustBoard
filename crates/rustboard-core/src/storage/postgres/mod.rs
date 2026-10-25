//! PostgreSQL 后端（M5 Phase D）。
//!
//! D2 只落地 schema/migration： [`schema::apply_schema`] 建 21 张表与 19 个
//! 命名索引、维护 PG 独立的 `schema_migrations`，并用事务级 advisory lock
//! 串行化多实例启动。`PostgresStorage` 的 29 个 [`Storage`] 方法、r2d2 连接池
//! 与 rustls TLS 都在 D3 实现，本模块**不**依赖 [`Storage`](crate::storage::Storage)。
//!
//! [`Storage`]: crate::storage::Storage

pub mod schema;

pub use schema::{
    apply_schema, connect_for_schema, POSTGRES_SCHEMA_VERSION, SCHEMA_ADVISORY_LOCK_KEY,
};
