//! RustBoard 安装器内核。
//!
//! 本 crate 只承载安装/升级/卸载需要的通用能力：路径规划、系统探测、交互提示、
//! 安装状态、带回滚的事务、systemd 与 HTTP 健康检查。它**不依赖** hub / agent /
//! panel 二进制，避免循环依赖；三个二进制的 `install` 子命令在 Phase A 后续接入。
//!
//! 安全约定：
//! - 配置、状态、token 一律 0600，目录中的私有数据 0700（复用
//!   [`rustboard_common::fsutil`] 的原子写入与私有目录校验）；
//! - 调用 systemctl 只用 `Command::args([...])`，不拼 shell；stop / restart /
//!   enable 前用 [`ServiceManager::ensure_fragment_is`] 核对 systemd 实际解析的
//!   unit 文件，拒绝同名外来 / 更高优先级 unit 与 transient unit；
//! - `--dry-run` 不创建目录、不备份、不写文件、不调用 systemctl；
//! - 安装失败由 [`InstallTxn`] 逆序恢复，绝不删除安装前已存在的数据目录；
//!   回滚本身失败时保留备份目录并报出路径，供人工恢复；
//! - 安装前缀与卸载路径分别经 [`validate_install_prefix`] /
//!   [`validate_managed_path`] allowlist；跨角色共享状态由
//!   [`InstallLock::acquire_global`] 串行（角色锁 [`InstallLock::acquire`] 仅保留
//!   兼容，不能保护不同角色共用的 `install-state.toml`）。

mod files;
mod lock;
mod network;
mod path_validate;
mod paths;
mod policy;
mod prompt;
mod role;
mod service;
mod state;
mod system;
mod txn;
mod util;

pub use files::read_private_file;
pub use lock::{InstallLock, GLOBAL_LOCK_PATH, LOCK_HELD_ENV};
pub use network::wait_https_ok_with_server_name;
pub use path_validate::reject_symlink_components;
pub use paths::{PathOverrides, Paths};
pub use policy::{validate_install_prefix, validate_managed_path, ManagedPathKind};
pub use prompt::Prompt;
pub use role::Role;
pub use service::{
    ensure_service_stopped, is_systemd_unit_dir, remove_enable_symlink, render_unit, shell_arg,
    stop_service_checked, unit_is_ours, wait_http_ok, ServiceControl, ServiceManager, ServiceState,
    UNIT_MARKER,
};
pub use state::{InstallState, RoleState, INSTALL_STATE_SCHEMA};
pub use system::{detect_system, pick_free_port, require_root, require_systemd, SystemInfo};
pub use txn::InstallTxn;
