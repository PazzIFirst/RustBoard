//! 安装事务与回滚。
//!
//! 任何会落盘的安装步骤都经过 [`InstallTxn`]：
//! - 目标已存在时先复制到本次事务的备份目录（保留权限），再用原子 rename 替换；
//! - 目标不存在时登记为 created，回滚只删除本次事务创建的文件；
//! - `rollback` 逆序恢复/删除；`dry_run` 不创建目录、不备份、不写文件；
//! - `Drop` 时未 `commit` 会尽力回滚并打印警告。
//!
//! 安全边界：`remove()` 只接受普通文件，拒绝目录与符号链接，避免“清空安装”
//! 误删已有数据目录；数据目录的删除只能由调用方在显式 `--purge` 流程里处理。
//! 所有写 / 复制 / 建目录 / 删除操作都会在落盘前拒绝符号链接路径组件，防止
//! 攻击者把 config / unit 的父目录换成链接后让 root 写入逃逸到别处。
//!
//! 失败备份保留：`rollback` 只有在**全部**操作恢复成功时才删除备份目录；任一
//! 操作失败都会保留备份并在错误信息中给出 `backup_dir`，供人工恢复。`Drop`
//! 触发的回滚失败也会打印备份路径——自动删除失败现场会直接导致数据不可恢复。

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustboard_common::fsutil;

use crate::path_validate::{normalize_absolute, reject_symlink_components};
use crate::util::{random_u64, utc_stamp};

const TMP_CREATE_ATTEMPTS: usize = 16;

/// 事务开始时目标的原始状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Original {
    Missing,
    Existing,
}

/// 逆序回滚所需的操作记录。
#[derive(Debug)]
enum Op {
    CreatedFile(PathBuf),
    CreatedDir(PathBuf),
    /// 本事务独占的数据目录：回滚时连同其中运行期产生的证书 / 数据库一起删除。
    OwnedDir(PathBuf),
    Restore {
        path: PathBuf,
        backup: PathBuf,
        mode: u32,
    },
}

/// 安装事务。
pub struct InstallTxn {
    backup_dir: PathBuf,
    dry_run: bool,
    finished: bool,
    originals: HashMap<PathBuf, Original>,
    ops: Vec<Op>,
    /// 事务创建的备份目录祖先，按“由浅到深”排列；回滚时反过来尝试删除空目录。
    backup_created_dirs: Vec<PathBuf>,
    backup_ready: bool,
}

impl InstallTxn {
    /// 开始事务。备份目录名由配置文件名 + UTC 时间 + 随机后缀组成。
    ///
    /// 非 `dry_run` 时立即创建 0700 的备份目录并校验可写（失败在改动系统前暴露）；
    /// `dry_run` 只计算路径，不创建目录、备份或文件。
    pub fn begin(paths: &crate::Paths, dry_run: bool) -> Result<Self> {
        let backup_root = normalize_absolute(&paths.backup_root, "备份根目录")?;
        if backup_root == Path::new("/") {
            bail!("备份根目录不能是 /");
        }
        reject_symlink_components(&backup_root)
            .with_context(|| format!("检查备份根目录 {} 失败", backup_root.display()))?;
        let tag = backup_tag(&paths.config);
        let backup_dir =
            backup_root.join(format!("{tag}-{}-{:08x}", utc_stamp(), random_u64() as u32));
        let mut txn = Self {
            backup_dir,
            dry_run,
            finished: false,
            originals: HashMap::new(),
            ops: Vec::new(),
            backup_created_dirs: Vec::new(),
            backup_ready: false,
        };
        if !dry_run {
            txn.ensure_backup_dir()?;
        }
        Ok(txn)
    }

    /// 本次事务的备份目录。
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// 原子写入文件并设置权限；已有文件先备份。
    pub fn write(&mut self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        let path = normalize_absolute(path, "写入路径")?;
        reject_symlink_components(&path)
            .with_context(|| format!("检查写入路径 {} 失败", path.display()))?;
        if self.dry_run {
            return Ok(());
        }
        self.ensure_parent_dirs(&path)?;
        self.register_original(&path)?;
        fsutil::atomic_write(&path, bytes, mode)
            .with_context(|| format!("原子写入 {} 失败", path.display()))
    }

    /// 从 `src` 流式复制到 `dest` 并设置权限；已有目标先备份。
    ///
    /// 用同目录临时文件 + rename 保证原子性，**不会**把源文件整个读进内存，
    /// 适合复制几十 MB 的二进制。`dry_run` 只校验源文件存在，不打开源文件内容，
    /// 也不创建备份或目标。
    pub fn copy_file(&mut self, src: &Path, dest: &Path, mode: u32) -> Result<()> {
        let dest = normalize_absolute(dest, "复制目标路径")?;
        reject_symlink_components(&dest)
            .with_context(|| format!("检查复制目标 {} 失败", dest.display()))?;
        if src.as_os_str().is_empty() {
            bail!("复制源路径不能为空");
        }
        let meta = fs::symlink_metadata(src)
            .with_context(|| format!("读取复制源 {} 失败", src.display()))?;
        if meta.file_type().is_symlink() {
            bail!("复制源 {} 是符号链接，拒绝复制", src.display());
        }
        if !meta.is_file() {
            bail!("复制源 {} 不是普通文件", src.display());
        }
        if src == dest {
            bail!("复制源与目标相同: {}", src.display());
        }
        if self.dry_run {
            return Ok(());
        }
        self.ensure_parent_dirs(&dest)?;
        self.register_original(&dest)?;
        atomic_copy(src, &dest, mode)
            .with_context(|| format!("复制 {} 到 {} 失败", src.display(), dest.display()))
    }

    /// 创建目录（含父目录），`mode` 不含 group/other 位时按私有目录校验/收紧。
    pub fn create_dir(&mut self, path: &Path, mode: u32) -> Result<()> {
        let path = normalize_absolute(path, "目录路径")?;
        reject_symlink_components(&path)
            .with_context(|| format!("检查目录路径 {} 失败", path.display()))?;
        if self.dry_run {
            return Ok(());
        }
        let missing = missing_dirs(&path)?;
        // 先登记再创建：即使 ensure 在部分目录已创建后失败，Drop 回滚也能清掉。
        for dir in &missing {
            self.ops.push(Op::CreatedDir(dir.clone()));
        }
        ensure_directory(&path, mode)
    }

    /// 创建“本事务独占”的数据目录：**仅当调用前不存在**时登记为 owned。
    ///
    /// 与 [`InstallTxn::create_dir`] 的区别只在回滚：owned 目录在安装失败时用
    /// 递归删除清掉运行期产生的证书 / 数据库等内容；调用前已存在的目录保持
    /// 「只创建 / 收紧、不登记删除」的旧语义，回滚绝不动。
    ///
    /// 递归删除前会拒绝符号链接与符号链接祖先，避免把删除作用到链接目标。
    pub fn create_owned_dir(&mut self, path: &Path, mode: u32) -> Result<()> {
        let path = normalize_absolute(path, "独占数据目录")?;
        reject_symlink_components(&path)
            .with_context(|| format!("检查独占数据目录 {} 失败", path.display()))?;
        if self.dry_run {
            return Ok(());
        }

        match fs::symlink_metadata(&path) {
            Ok(_) => {
                // 已存在（目录、符号链接或其他类型）：走通用 create_dir 的
                // 创建/收紧/报错语义，且不登记为 owned。
                return self.create_dir(&path, mode);
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("检查目录 {} 失败", path.display()));
            }
        }

        let missing = missing_dirs(&path)?;
        if missing.last().map(PathBuf::as_path) != Some(path.as_path()) {
            // 两次检查之间目录被并发创建：按“已存在”处理，避免回滚误删。
            return self.create_dir(&path, mode);
        }
        // 祖先目录是普通 created（只删空目录），最终目录是 owned（递归删除）。
        for dir in &missing {
            if dir == &path {
                self.ops.push(Op::OwnedDir(path.clone()));
            } else {
                self.ops.push(Op::CreatedDir(dir.clone()));
            }
        }
        ensure_directory(&path, mode)
    }

    /// 删除一个普通文件；已有文件先备份，回滚可恢复。
    ///
    /// 目录与符号链接一律拒绝：防止 `uninstall --purge` 误删数据目录或链接目标。
    pub fn remove(&mut self, path: &Path) -> Result<()> {
        let path = normalize_absolute(path, "删除路径")?;
        reject_symlink_components(&path)
            .with_context(|| format!("检查删除路径 {} 失败", path.display()))?;
        if self.dry_run {
            return Ok(());
        }
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| format!("读取待删除文件 {} 失败", path.display()));
            }
        };
        if meta.file_type().is_symlink() {
            bail!("{} 是符号链接，事务拒绝删除", path.display());
        }
        if meta.is_dir() {
            bail!(
                "{} 是目录，事务拒绝删除目录（数据目录只能走显式 --purge 流程）",
                path.display()
            );
        }
        if !meta.is_file() {
            bail!("{} 不是普通文件，事务拒绝删除", path.display());
        }

        self.register_original(&path)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("删除文件 {} 失败", path.display())),
        }
    }

    /// 提交事务并清理本次备份。
    ///
    /// 注意：清理备份后无法再回滚。升级场景若需长期保留旧版本，调用方应在
    /// `commit` 前把 [`InstallTxn::backup_dir`] 复制到自己的保留目录。
    pub fn commit(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.dry_run {
            return Ok(());
        }
        if let Err(err) = self.cleanup_backup() {
            // 安装本身已经成功；备份清理失败只告警，不能让调用方误以为要回滚。
            eprintln!("警告：清理安装备份目录失败: {err:#}");
        }
        Ok(())
    }

    /// 逆序回滚本次事务：恢复备份、删除本次创建的文件与空目录。
    ///
    /// 只有全部操作都恢复成功（`first_error.is_none()`）才删除备份目录。任一
    /// 操作失败时保留完整备份，并在返回错误的最外层带上 `backup_dir`，供人工
    /// 按备份恢复；绝不能因为“回滚函数返回错误”就把最后的恢复现场删掉。
    pub fn rollback(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.dry_run {
            self.ops.clear();
            return Ok(());
        }

        let mut first_error: Option<anyhow::Error> = None;
        while let Some(op) = self.ops.pop() {
            let result = match op {
                Op::CreatedFile(path) => remove_created_file(&path),
                Op::CreatedDir(path) => remove_created_dir(&path),
                Op::OwnedDir(path) => remove_owned_dir(&path),
                Op::Restore { path, backup, mode } => atomic_copy(&backup, &path, mode)
                    .with_context(|| {
                        format!("回滚 {} 失败（备份 {}）", path.display(), backup.display())
                    }),
            };
            if let Err(err) = result {
                keep_first_error(&mut first_error, err);
            }
        }

        // 任一 Op 恢复失败：保留备份目录，错误里带路径，交人工处理。
        if let Some(err) = first_error {
            return Err(err.context(format!(
                "安装事务回滚未完成；备份目录 {} 已保留，请人工恢复",
                self.backup_dir.display()
            )));
        }

        // 全部恢复成功才删除备份；清理失败（例如父目录不可写）作为错误返回，
        // 此时备份目录可能仍在，错误信息由 cleanup_backup 自己带路径。
        self.cleanup_backup()
    }

    /// 写入前确保父目录存在；父目录按通用目录 0755 创建并登记。
    fn ensure_parent_dirs(&mut self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} 缺少父目录", path.display()))?;
        self.create_dir(parent, 0o755)
    }

    /// 第一次触碰某路径时记录原始状态；已有文件立即备份。
    fn register_original(&mut self, path: &Path) -> Result<()> {
        if self.originals.contains_key(path) {
            return Ok(());
        }
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("{} 是符号链接，事务拒绝覆盖", path.display());
            }
            Ok(meta) if !meta.is_file() => {
                bail!("{} 已存在且不是普通文件，事务拒绝覆盖", path.display());
            }
            Ok(meta) => {
                let mode = file_mode(&meta);
                let backup = self.backup_existing(path, mode)?;
                self.ops.push(Op::Restore {
                    path: path.to_path_buf(),
                    backup,
                    mode,
                });
                self.originals
                    .insert(path.to_path_buf(), Original::Existing);
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.ops.push(Op::CreatedFile(path.to_path_buf()));
                self.originals.insert(path.to_path_buf(), Original::Missing);
            }
            Err(err) => {
                return Err(err).with_context(|| format!("检查目标 {} 失败", path.display()));
            }
        }
        Ok(())
    }

    /// 把已有文件复制到备份目录并保留权限。
    fn backup_existing(&mut self, path: &Path, mode: u32) -> Result<PathBuf> {
        self.ensure_backup_dir()?;
        let name = path
            .file_name()
            .map(|name| sanitize_component(&name.to_string_lossy()))
            .unwrap_or_else(|| "file".to_string());
        let backup = self
            .backup_dir
            .join(format!("{:04}-{name}", self.ops.len()));
        fs::copy(path, &backup)
            .with_context(|| format!("备份 {} 到 {} 失败", path.display(), backup.display()))?;
        set_mode(&backup, mode)?;
        Ok(backup)
    }

    /// 懒创建备份目录，并记录本次创建的祖先目录。
    fn ensure_backup_dir(&mut self) -> Result<()> {
        if self.backup_ready {
            return Ok(());
        }
        // 备份目录必须是本事务新建的：已存在说明随机名撞车或有人预占，
        // 继续使用会在 commit 时删掉非本事务的目录。
        if fs::symlink_metadata(&self.backup_dir).is_ok() {
            bail!("备份目录 {} 已存在，拒绝复用", self.backup_dir.display());
        }
        let missing = missing_dirs(&self.backup_dir)?;
        fsutil::ensure_private_dir(&self.backup_dir, 0o700)
            .with_context(|| format!("创建备份目录 {} 失败", self.backup_dir.display()))?;
        self.backup_created_dirs = missing;
        self.backup_ready = true;
        Ok(())
    }

    /// 删除本次事务的备份目录，并尝试删除因此变空的祖先目录。
    fn cleanup_backup(&mut self) -> Result<()> {
        let mut first_error = None;
        if self.backup_ready {
            match fs::remove_dir_all(&self.backup_dir) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    keep_first_error(
                        &mut first_error,
                        anyhow::Error::new(err)
                            .context(format!("删除备份目录 {} 失败", self.backup_dir.display())),
                    );
                }
            }
        }
        for dir in self.backup_created_dirs.iter().rev() {
            match fs::remove_dir(dir) {
                Ok(()) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(err) => {
                    keep_first_error(
                        &mut first_error,
                        anyhow::Error::new(err)
                            .context(format!("删除空目录 {} 失败", dir.display())),
                    );
                }
            }
        }
        self.backup_created_dirs.clear();
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl Drop for InstallTxn {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        eprintln!("警告：安装事务未 commit，正在回滚本次改动");
        if let Err(err) = self.rollback() {
            eprintln!(
                "警告：安装事务回滚失败，备份目录 {} 已保留: {err:#}",
                self.backup_dir.display()
            );
        }
    }
}

/// 删除本次创建的文件；目标已变成目录时拒绝删除。
fn remove_created_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            bail!(
                "{} 在事务期间变成目录，拒绝回滚删除（可能是已有数据）",
                path.display()
            );
        }
        Ok(_) => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("删除 {} 失败", path.display())),
        },
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("检查待删除文件 {} 失败", path.display())),
    }
}

/// 删除本次创建的空目录；非空目录保留（里面可能有用户数据）。
fn remove_created_dir(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty | ErrorKind::NotADirectory
            ) =>
        {
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("删除空目录 {} 失败", path.display())),
    }
}

/// 删除本事务独占的数据目录（含运行期生成的文件）。
///
/// 先拒绝符号链接目标与任何符号链接祖先，再调用 `remove_dir_all`。标准库的
/// `remove_dir_all` 不会跟随目录树内部的链接；这里的祖先检查用于避免删除
/// 作用到被替换成链接的父路径上。路径在检查后被并发替换的窗口无法完全消除，
/// 但安装器操作的是 root 拥有的系统目录，风险窗口远小于直接按路径删除。
fn remove_owned_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!(
                "{} 在事务期间变成符号链接，拒绝递归删除（避免删除链接目标）",
                path.display()
            );
        }
        Ok(meta) if !meta.is_dir() => {
            bail!(
                "{} 在事务期间不再是目录，拒绝递归删除（可能是已有数据）",
                path.display()
            );
        }
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("检查独占目录 {} 失败", path.display()));
        }
    }

    reject_symlink_components(path)?;
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("递归删除独占目录 {} 失败", path.display())),
    }
}

/// 按权限选择通用目录或私有目录的创建 / 收紧实现。
fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    let result = if mode & 0o077 == 0 {
        fsutil::ensure_private_dir(path, mode)
    } else {
        fsutil::ensure_dir(path, mode)
    };
    result.with_context(|| format!("创建目录 {} 失败（目标权限 {mode:04o}）", path.display()))
}

/// 找出 `path` 上尚未存在的目录链，按“由浅到深”返回。
fn missing_dirs(path: &Path) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut current = Some(path.to_path_buf());
    while let Some(dir) = current {
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() || meta.file_type().is_symlink() => break,
            Ok(_) => {
                bail!("{} 已存在且不是目录", dir.display());
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                missing.push(dir.clone());
                current = dir.parent().map(Path::to_path_buf);
            }
            Err(err) => {
                return Err(err).with_context(|| format!("检查目录 {} 失败", dir.display()));
            }
        }
    }
    missing.reverse();
    Ok(missing)
}

/// 流式原子复制：同目录随机临时文件 → 写入 → fsync → rename → fsync 父目录。
fn atomic_copy(src: &Path, dest: &Path, mode: u32) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 缺少父目录", dest.display()))?;
    let name = dest
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} 缺少文件名", dest.display()))?
        .to_string_lossy()
        .to_string();
    let mut source =
        File::open(src).with_context(|| format!("打开复制源 {} 失败", src.display()))?;

    for _ in 0..TMP_CREATE_ATTEMPTS {
        let tmp = parent.join(format!(
            ".{name}.copy.{}.{:016x}",
            std::process::id(),
            random_u64()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }
        let mut file = match options.open(&tmp) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("创建临时文件 {} 失败", tmp.display()));
            }
        };

        let copy_result = (|| -> Result<()> {
            io::copy(&mut source, &mut file)?;
            // 先把权限收紧到目标值并 fsync 元数据，再 rename 到目标路径。
            set_file_mode(&file, mode)?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);
        if let Err(err) = copy_result {
            let _ = fs::remove_file(&tmp);
            return Err(err).context(format!("写入临时文件 {} 失败", tmp.display()));
        }
        if let Err(err) = fs::rename(&tmp, dest) {
            let _ = fs::remove_file(&tmp);
            return Err(err).context(format!(
                "rename {} 到 {} 失败",
                tmp.display(),
                dest.display()
            ));
        }
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        return Ok(());
    }
    bail!(
        "{} 的临时文件在 {TMP_CREATE_ATTEMPTS} 次尝试后仍无法创建",
        dest.display()
    )
}

/// 读取文件的权限位；非 Unix 返回 0600（写入时只用于还原）。
fn file_mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o600
    }
}

/// 设置已打开文件的权限；非 Unix 为 no-op。
fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("设置临时文件权限 {mode:04o} 失败"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
    }
    Ok(())
}

/// 设置文件权限；非 Unix 为 no-op。
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("设置 {} 权限 {mode:04o} 失败", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// 备份目录标签取自配置文件名（如 `hub.toml` → `hub`）。
fn backup_tag(config: &Path) -> String {
    let raw = config
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| "install".to_string());
    let tag = sanitize_component(&raw);
    if tag.is_empty() {
        "install".to_string()
    } else {
        tag
    }
}

/// 把任意字符串收窄成可安全放进文件名的 ASCII 组件。
fn sanitize_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    sanitized.trim_matches('_').to_string()
}

fn keep_first_error(slot: &mut Option<anyhow::Error>, err: anyhow::Error) {
    if slot.is_none() {
        *slot = Some(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_backup_names() {
        assert_eq!(sanitize_component("hub.toml"), "hub_toml");
        assert_eq!(sanitize_component("../x"), "x");
        assert_eq!(sanitize_component(""), "");
    }

    #[test]
    fn backup_tag_comes_from_config_stem() {
        assert_eq!(backup_tag(Path::new("/etc/rustboard/hub.toml")), "hub");
        assert_eq!(backup_tag(Path::new("/tmp/custom")), "custom");
    }
}
