//! M5 Phase D D0：L-01 / L-03 黑盒回归。
//!
//! 约束：
//! - 只通过编译出的 `rustboard-hub` 二进制与文件系统观察行为，不引用 hub 内部模块；
//!   这样在 L-01 / L-03 实现尚未落地时测试仍可编译，失败会精确落在验收点上。
//! - 每个用例独立临时目录；`hub run` 一律由 RAII 守卫 `kill` + `wait`，并有硬超时，
//!   不会因为断言失败把子进程留在后台。
//! - 仅 Linux：依赖 Unix mode；权限收紧失败的用例还用 `chattr +i` 制造 EACCES
//!   （不可变属性在文件系统不支持时显式跳过，不伪造通过）。
//!
//! 验收来源：`docs/plans/2026-10-26-m5-phase-d-postgres-backup-l01-l03.md`
//! §1.1（account/state 0644→0600、缺失可启动、symlink 拒绝、status 只读告警）、
//! §1.2（L-03 三条修复路径）与 §6.1。

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// ACME account 的最小合法 JSON；只要求启动时能被当作账户文件，不参与真实签发。
const ACCOUNT_JSON: &str = concat!(
    r#"{"status":"valid","contact":[],"termsOfServiceAgreed":true,"#,
    r#""orders":"https://acme.example/account/1/orders"}"#
);

/// ACME state 的示意内容；字段名按文档描述，测试只依赖它是合法 TOML。
const STATE_TOML: &str = concat!(
    "directory = \"https://acme-v02.api.letsencrypt.org/directory\"\n",
    "domains = [\"board.example.com\"]\n",
    "profile = \"\"\n",
    "last_issue_unix = 0\n",
    "next_attempt_unix = 0\n",
    "last_error = \"\"\n"
);

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rustboard-hub")
}

/// 独立临时目录，Drop 时递归删除。
struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(tag: &str) -> Self {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let path = base.join(format!(
            "phase-d-l01-l03-{}-{tag}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("创建测试临时目录");
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Install {
    dir: TestDir,
    config: PathBuf,
    data_dir: PathBuf,
}

/// 用与生产同一条 `hub init` 路径构造 base 安装（self-signed、admin_tls=off）。
/// `admin_port == 0` 表示让内核分配端口，避免并行测试固定端口冲突。
fn init_install(tag: &str, admin_port: u16) -> Install {
    let dir = TestDir::new(tag);
    let config = dir.path.join("hub.toml");
    let data_dir = dir.path.join("data");
    let admin_listen = format!("127.0.0.1:{admin_port}");
    let output = Command::new(bin())
        .arg("init")
        .arg("--config")
        .arg(&config)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--admin-listen")
        .arg(&admin_listen)
        .arg("--agent-listen")
        .arg("127.0.0.1:0")
        .output()
        .expect("执行 rustboard-hub init");
    assert!(
        output.status.success(),
        "hub init 失败（status={:?}）\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Install {
        dir,
        config,
        data_dir,
    }
}

fn hub(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("执行 rustboard-hub")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn file_mode(path: &Path) -> Option<u32> {
    fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode() & 0o777)
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|err| panic!("设置 {} 权限为 {mode:o} 失败: {err}", path.display()));
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("申请空闲端口");
    listener.local_addr().expect("读取临时端口").port()
}

/// 在 `<data_dir>/certs/acme/` 预置 0644 的 account.json 与 state.toml。
fn seed_acme_files(data_dir: &Path) -> (PathBuf, PathBuf) {
    let acme_dir = data_dir.join("certs/acme");
    fs::create_dir_all(&acme_dir).expect("创建 certs/acme");
    set_mode(&acme_dir, 0o700);
    let account = acme_dir.join("account.json");
    let state = acme_dir.join("state.toml");
    fs::write(&account, ACCOUNT_JSON).expect("写 account.json");
    fs::write(&state, STATE_TOML).expect("写 state.toml");
    set_mode(&account, 0o644);
    set_mode(&state, 0o644);
    (account, state)
}

/// `certs/acme/` 的文件名集合 + 内容快照（含符号链接指向），用于证明只读命令
/// 没有备份、改写或新增任何文件（例如 `.corrupt-*`）。
fn snapshot_dir(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut snapshot = BTreeMap::new();
    for entry in
        fs::read_dir(dir).unwrap_or_else(|err| panic!("读取 {} 失败: {err}", dir.display()))
    {
        let entry = entry.expect("读取目录项");
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).expect("stat 目录项");
        let content = if meta.file_type().is_symlink() {
            format!(
                "symlink:{}",
                fs::read_link(&path).expect("读取符号链接").display()
            )
            .into_bytes()
        } else if meta.is_file() {
            fs::read(&path).expect("读取文件内容")
        } else {
            b"<non-file>".to_vec()
        };
        snapshot.insert(name, content);
    }
    snapshot
}

/// 读取配置文本并替换指定段落中的一个键（支持跨行数组）。
fn set_config_value(text: &str, section: Option<&str>, key: &str, value: &str) -> String {
    let mut out = String::new();
    let mut current_section: Option<String> = None;
    let mut replaced = false;
    let mut skipping_array = false;
    for line in text.lines() {
        if skipping_array {
            if line.trim() == "]" {
                skipping_array = false;
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = Some(
                trimmed
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string(),
            );
        }
        let in_section = match section {
            Some(name) => current_section.as_deref() == Some(name),
            None => current_section.is_none(),
        };
        let prefix = format!("{key} =");
        if in_section && !replaced && trimmed.starts_with(&prefix) {
            out.push_str(&format!("{key} = {value}\n"));
            replaced = true;
            // 只对真正的跨行数组（此行以 `[` 结尾）跳过后续元素与 `]`；
            // 标量行不能触发跳过，否则会吞掉同段后续配置。
            if trimmed.ends_with('[') {
                skipping_array = true;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    assert!(
        replaced,
        "配置中未找到 section={section:?} key={key}，原始配置:\n{text}"
    );
    out
}

fn rewrite_config(path: &Path, text: &str) {
    // 配置由 init 写成 0600；fs::write 截断写不会改变已有 mode。
    fs::write(path, text).expect("写回 hub.toml");
}

/// 启动 `hub run`，stdout/stderr 走管道；Drop 兜底 kill + wait。
struct HubRun {
    child: Child,
}

impl HubRun {
    fn spawn(config: &Path) -> Self {
        let child = Command::new(bin())
            .arg("run")
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("启动 rustboard-hub run");
        Self { child }
    }

    fn wait_until(
        &mut self,
        label: &str,
        timeout: Duration,
        mut condition: impl FnMut() -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if condition() {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().expect("查询 hub 子进程状态") {
                return Err(format!("{label}: hub run 提前退出（{status}）"));
            }
            if Instant::now() >= deadline {
                return Err(format!("{label}: 超过 {timeout:?} 仍未满足"));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("查询 hub 子进程状态") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("查询 hub 子进程状态")
            .is_none()
    }

    /// 终止（若仍在运行）并回收管道内容；幂等，重复调用只返回缓存退出状态。
    fn stop(&mut self) -> (ExitStatus, String, String) {
        if self
            .child
            .try_wait()
            .expect("查询 hub 子进程状态")
            .is_none()
        {
            let _ = self.child.kill();
        }
        let status = self.child.wait().expect("回收 hub 子进程");
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        (status, stdout, stderr)
    }
}

impl Drop for HubRun {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 条件超时/子进程提前退出时，先终止子进程再 panic，避免把进程挂住。
fn require_condition(
    run: &mut HubRun,
    label: &str,
    timeout: Duration,
    condition: impl FnMut() -> bool,
) {
    if let Err(reason) = run.wait_until(label, timeout, condition) {
        let (status, stdout, stderr) = run.stop();
        panic!("{reason}\n最终状态: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }
}

fn health_status(port: u16) -> Option<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(300)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(1_000)))
        .ok()?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response.windows(2).any(|window| window == b"\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
        if response.len() > 4_096 {
            break;
        }
    }
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// L-01 验收点：启动时把旧 0644 的 account/state 收紧到 0600。
#[test]
fn run_hardens_preexisting_0644_acme_account_and_state() {
    let install = init_install("harden", 0);
    let (account, state) = seed_acme_files(&install.data_dir);
    let account_before = fs::read(&account).expect("读取预置 account.json");
    let state_before = fs::read(&state).expect("读取预置 state.toml");
    assert_eq!(file_mode(&account), Some(0o644), "前置条件：account 0644");
    assert_eq!(file_mode(&state), Some(0o644), "前置条件：state 0644");

    let mut run = HubRun::spawn(&install.config);
    require_condition(
        &mut run,
        "account.json 与 state.toml 启动后收紧为 0600",
        Duration::from_secs(20),
        || file_mode(&account) == Some(0o600) && file_mode(&state) == Some(0o600),
    );
    assert!(
        run.running(),
        "权限已收紧但 hub run 已退出，按启动失败处理；{}",
        run.stop().2
    );

    let (status, stdout, stderr) = run.stop();
    assert!(
        status.signal().is_some(),
        "测试主动终止 hub 应得到信号退出；status={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        file_mode(&account),
        Some(0o600),
        "hub 被终止后 account.json 仍必须是 0600"
    );
    assert_eq!(
        file_mode(&state),
        Some(0o600),
        "hub 被终止后 state.toml 仍必须是 0600"
    );
    assert_eq!(
        fs::read(&account).expect("终止后读取 account.json"),
        account_before,
        "收紧权限不得改写 account.json 内容"
    );
    assert_eq!(
        fs::read(&state).expect("终止后读取 state.toml"),
        state_before,
        "收紧权限不得改写 state.toml 内容"
    );
}

/// L-01 验收点：文件不存在时 `hub run` 正常启动，不因缺失而报错/退出。
#[test]
fn run_starts_when_acme_account_and_state_are_absent() {
    let admin_port = free_port();
    let install = init_install("missing", admin_port);
    let acme_dir = install.data_dir.join("certs/acme");
    let account = acme_dir.join("account.json");
    let state = acme_dir.join("state.toml");
    assert!(!account.exists(), "前置条件：account.json 不存在");
    assert!(!state.exists(), "前置条件：state.toml 不存在");

    let mut run = HubRun::spawn(&install.config);
    require_condition(
        &mut run,
        "hub run 启动后 /healthz 返回 200",
        Duration::from_secs(30),
        || health_status(admin_port) == Some(200),
    );

    // 要求“短暂等待后仍存活”，避免把刚绑定端口就退出的进程误判为正常启动。
    thread::sleep(Duration::from_millis(500));
    assert!(run.running(), "健康检查已通过，但 500ms 后 hub 进程已退出");

    let (status, stdout, stderr) = run.stop();
    assert!(
        status.signal().is_some(),
        "测试主动终止 hub 应得到信号退出；status={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // 缺失即跳过是 L-01 的要求：不得为了“收紧”而创建占位账户/状态文件。
    assert!(
        !account.exists(),
        "启动时 account.json 不存在，不应被创建: {}",
        account.display()
    );
    assert!(
        !state.exists(),
        "启动时 state.toml 不存在，不应被创建: {}",
        state.display()
    );
}

/// 启动时 ACME 私有文件是符号链接必须拒绝；不跟随 chmod、不改目标内容/权限。
fn assert_symlinked_acme_file_rejected(tag: &str, file_name: &str, content: &str) {
    let install = init_install(tag, 0);
    let acme_dir = install.data_dir.join("certs/acme");
    fs::create_dir_all(&acme_dir).expect("创建 certs/acme");
    set_mode(&acme_dir, 0o700);
    let target = install.dir.path.join(format!("outside-{file_name}"));
    fs::write(&target, content).expect("写符号链接目标");
    set_mode(&target, 0o644);
    let target_before = fs::read(&target).expect("读取符号链接目标");
    let link = acme_dir.join(file_name);
    std::os::unix::fs::symlink(&target, &link)
        .unwrap_or_else(|err| panic!("创建 {file_name} 符号链接失败: {err}"));
    assert!(
        fs::symlink_metadata(&link)
            .expect("stat 符号链接")
            .file_type()
            .is_symlink(),
        "前置条件：{file_name} 必须是符号链接"
    );

    let mut run = HubRun::spawn(&install.config);
    let exit = run.wait_exit(Duration::from_secs(20));
    if exit.is_none() {
        let (status, stdout, stderr) = run.stop();
        panic!(
            "{file_name} 是符号链接时 hub run 必须在 20s 内失败退出，但仍存活；\
             终止状态={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    let (status, stdout, stderr) = run.stop();
    assert!(
        !status.success(),
        "{file_name} 是符号链接时 hub run 必须非零退出；status={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains(file_name),
        "失败信息必须点名 {file_name}，便于定位；stderr:\n{stderr}"
    );
    assert!(
        fs::symlink_metadata(&link)
            .expect("终止后 stat 符号链接")
            .file_type()
            .is_symlink(),
        "启动失败不得把符号链接替换成普通文件: {}",
        link.display()
    );
    assert_eq!(
        fs::read_link(&link).expect("读取符号链接目标"),
        target,
        "启动失败不得改写符号链接指向"
    );
    assert_eq!(
        file_mode(&target),
        Some(0o644),
        "不得跟随符号链接把目标 chmod 成 0600: {}",
        target.display()
    );
    assert_eq!(
        fs::read(&target).expect("终止后读取符号链接目标"),
        target_before,
        "不得改写符号链接目标内容"
    );
}

/// L-01 验收点：account.json 是符号链接时启动失败，且不得跟随链接 chmod 目标。
#[test]
fn run_fails_on_symlinked_account_without_chmodding_target() {
    assert_symlinked_acme_file_rejected("symlink-account", "account.json", ACCOUNT_JSON);
}

/// L-01 验收点：state.toml 是符号链接时启动同样必须拒绝，且不跟随、不改目标。
#[test]
fn run_fails_on_symlinked_state_without_chmodding_target() {
    assert_symlinked_acme_file_rejected("symlink-state", "state.toml", STATE_TOML);
}

/// L-01 验收点：`tls status` 只读；检测到 0644 必须分别 WARN 账户与状态文件，
/// 且不得 harden 配置文件、不得在 `certs/acme/` 新增备份（如 `.corrupt-*`）。
#[test]
fn tls_status_warns_on_0644_and_keeps_files_unchanged() {
    let install = init_install("status", 0);
    let (account, state) = seed_acme_files(&install.data_dir);
    let acme_dir = install.data_dir.join("certs/acme");
    let account_before = fs::read(&account).expect("读取 account.json");
    let state_before = fs::read(&state).expect("读取 state.toml");
    // 配置也故意放宽到 0644：status 是只读诊断，不能像启动路径那样 harden 它。
    set_mode(&install.config, 0o644);
    let config_before = fs::read(&install.config).expect("读取 hub.toml");
    let snapshot_before = snapshot_dir(&acme_dir);

    let output = hub(&[
        "tls",
        "status",
        "--config",
        install.config.to_str().expect("config 路径是 UTF-8"),
    ]);
    let text = combined(&output);
    assert!(
        text.contains("WARN"),
        "tls status 检测到 0644 时必须输出 WARN；输出:\n{text}"
    );
    let account_warn = text
        .lines()
        .any(|line| line.contains("WARN") && line.contains("ACME 账户文件"));
    let state_warn = text
        .lines()
        .any(|line| line.contains("WARN") && line.contains("ACME 状态文件"));
    assert!(
        account_warn,
        "必须单独输出含“ACME 账户文件”的 WARN 行；输出:\n{text}"
    );
    assert!(
        state_warn,
        "必须单独输出含“ACME 状态文件”的 WARN 行；输出:\n{text}"
    );
    let has_repair_hint = (text.contains("chmod")
        && (text.contains("600") || text.contains("0600")))
        || text.contains("rustboard-hub run")
        || text.contains("hub run")
        || text.contains("自动收紧");
    assert!(
        has_repair_hint,
        "WARN 必须给出可执行的修复建议（chmod 600 / hub run / 自动收紧）；输出:\n{text}"
    );

    // 只读：status 不得收紧、不得改写内容。
    assert_eq!(
        file_mode(&account),
        Some(0o644),
        "tls status 必须只读，不得把 account.json 改成 0600"
    );
    assert_eq!(
        file_mode(&state),
        Some(0o644),
        "tls status 必须只读，不得把 state.toml 改成 0600"
    );
    assert_eq!(
        fs::read(&account).expect("status 后读取 account.json"),
        account_before,
        "tls status 不得改写 account.json"
    );
    assert_eq!(
        fs::read(&state).expect("status 后读取 state.toml"),
        state_before,
        "tls status 不得改写 state.toml"
    );
    assert_eq!(
        file_mode(&install.config),
        Some(0o644),
        "tls status 不得把 hub.toml harden 成 0600"
    );
    assert_eq!(
        fs::read(&install.config).expect("status 后读取 hub.toml"),
        config_before,
        "tls status 不得改写 hub.toml"
    );
    assert_eq!(
        snapshot_dir(&acme_dir),
        snapshot_before,
        "tls status 不得在 certs/acme/ 新增/改写文件（含 .corrupt-* 备份）"
    );
}

/// L-01 验收点：ACME 模式下 state.toml 损坏时 `tls status` 必须报错退出，
/// 且只读诊断不得在 `certs/acme/` 生成 `.corrupt-*` 备份或任何新文件。
#[test]
fn tls_status_corrupt_state_is_error_and_creates_no_backup() {
    let install = init_install("status-corrupt", 0);
    let config_text = fs::read_to_string(&install.config).expect("读取 hub.toml");
    let config_text = set_config_value(&config_text, Some("tls"), "mode", "\"acme-domain\"");
    let config_text = set_config_value(
        &config_text,
        Some("tls"),
        "acme_email",
        "\"admin@example.com\"",
    );
    let config_text = set_config_value(
        &config_text,
        Some("tls"),
        "acme_directory",
        "\"https://127.0.0.1:1/dir\"",
    );
    let config_text = set_config_value(
        &config_text,
        Some("tls"),
        "domains",
        "[\"board.example.com\"]",
    );
    let config_text = set_config_value(&config_text, Some("tls"), "staging_check", "false");
    rewrite_config(&install.config, &config_text);

    let acme_dir = install.data_dir.join("certs/acme");
    fs::create_dir_all(&acme_dir).expect("创建 certs/acme");
    set_mode(&acme_dir, 0o700);
    let account = acme_dir.join("account.json");
    fs::write(&account, ACCOUNT_JSON).expect("写 account.json");
    set_mode(&account, 0o600);
    let state = acme_dir.join("state.toml");
    let corrupt_state = b"this is not = valid toml [[[\n";
    fs::write(&state, corrupt_state).expect("写损坏的 state.toml");
    set_mode(&state, 0o600);
    let snapshot_before = snapshot_dir(&acme_dir);

    let output = hub(&[
        "tls",
        "status",
        "--config",
        install.config.to_str().expect("config 路径是 UTF-8"),
    ]);
    let output_text = combined(&output);
    assert!(
        !output.status.success(),
        "ACME 模式下损坏的 state.toml 必须让 tls status 非零退出；输出:\n{output_text}"
    );
    assert!(
        output_text.contains("state.toml"),
        "错误必须点名 state.toml；输出:\n{output_text}"
    );
    assert!(
        output_text.contains("损坏")
            || output_text.to_lowercase().contains("parse")
            || output_text.to_lowercase().contains("toml"),
        "错误必须说明 state.toml 解析/格式损坏，而不是笼统失败；输出:\n{output_text}"
    );
    assert_eq!(
        snapshot_dir(&acme_dir),
        snapshot_before,
        "tls status 是只读诊断，不得备份/改写/新增 certs/acme/ 下的文件（含 .corrupt-*）"
    );
    assert_eq!(
        file_mode(&state),
        Some(0o600),
        "tls status 不得改写损坏 state.toml 的权限"
    );
    assert_eq!(
        fs::read(&state).expect("status 后读取 state.toml"),
        corrupt_state,
        "tls status 不得改写损坏 state.toml 的内容"
    );
    assert_eq!(
        file_mode(&account),
        Some(0o600),
        "tls status 不得改写 account.json 的权限"
    );
    assert_eq!(
        fs::read(&account).expect("status 后读取 account.json"),
        ACCOUNT_JSON.as_bytes(),
        "tls status 不得改写 account.json 的内容"
    );
}

/// 检查是否出现了“把回环 IP 加入公共 ACME / tls.domains”的误导性建议。
/// 否定句（“不要/请勿/不含…”)不算误导；逐行检查避免跨行拼接误报。
fn misleading_loopback_acme_advice(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_lowercase();
        let mentions_loopback = lower.contains("127.0.0.1")
            || lower.contains("::1")
            || lower.contains("回环")
            || lower.contains("loopback");
        let public_target = lower.contains("tls.domains")
            || lower.contains("公共 acme")
            || lower.contains("公共证书")
            || lower.contains("acme 域名");
        let suggests_add = lower.contains("加入")
            || lower.contains("添加")
            || lower.contains("写入")
            || lower.contains("add ")
            || lower.contains("include");
        let negated = [
            "不要",
            "不能",
            "不可",
            "禁止",
            "切勿",
            "请勿",
            "勿将",
            "无需",
            "不必",
            "不含",
            "不应",
            "不允许",
            "not ",
            "never",
        ]
        .iter()
        .any(|needle| lower.contains(needle));
        if mentions_loopback && public_target && suggests_add && !negated {
            return Some(line.to_string());
        }
    }
    None
}

fn is_numbered_path_start(line: &str, number: u8) -> bool {
    let trimmed = line.trim_start();
    [")", ".", "、"]
        .iter()
        .any(|separator| trimmed.starts_with(&format!("{number}{separator}")))
}

/// 按错误信息中 `1) / 2) / 3)` 的编号切片，确保每条路径的关键词只在本路径内命中。
fn numbered_path_sections(text: &str) -> [String; 3] {
    let lines: Vec<&str> = text.lines().collect();
    let find = |number: u8| {
        lines
            .iter()
            .position(|line| is_numbered_path_start(line, number))
            .unwrap_or_else(|| panic!("错误信息缺少第 {number} 条路径；完整 stderr:\n{text}"))
    };
    let first = find(1);
    let second = find(2);
    let third = find(3);
    assert!(
        first < second && second < third,
        "三条路径编号顺序异常（{first}/{second}/{third}）；完整 stderr:\n{text}"
    );
    [
        lines[first..second].join("\n"),
        lines[second..third].join("\n"),
        lines[third..].join("\n"),
    ]
}

/// L-03 验收点：ACME 域名证书 + 回环管理口 + admin_tls=required 必须 fail-closed，
/// 且错误信息给出三条可执行路径，不得诱导给公共 ACME 证书加回环 IP。
///
/// 本地单测不连接 Pebble / 公共 CA；这里用本机 CA 重签出与 ACME 域名证书相同的
/// SAN 形状（仅 DNS、无回环 IP），以驱动同一段启动校验。真实 ACME 签发的端到端
/// 覆盖不在本文件伪造。
#[test]
fn acme_domain_with_loopback_admin_tls_reports_three_paths() {
    let admin_port = free_port();
    let install = init_install("l03", admin_port);

    // 1) 把 server_names 收缩为 ACME 域名，重签出「只有 DNS SAN、没有回环 IP SAN」
    //    的服务端证书，模拟 ACME 域名证书的 SAN 形状。
    let text = fs::read_to_string(&install.config).expect("读取 hub.toml");
    let text = set_config_value(&text, None, "server_names", "[\"board.example.com\"]");
    rewrite_config(&install.config, &text);
    let rotate = hub(&[
        "rotate-cert",
        "--force",
        "--config",
        install.config.to_str().expect("config 路径是 UTF-8"),
    ]);
    assert!(
        rotate.status.success(),
        "前置条件：按 DNS-only SAN 重签证书失败\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rotate.stdout),
        String::from_utf8_lossy(&rotate.stderr)
    );
    let status = hub(&[
        "tls",
        "status",
        "--config",
        install.config.to_str().expect("config 路径是 UTF-8"),
    ]);
    let status_text = combined(&status);
    assert!(
        status_text.contains("SAN: DNS:board.example.com"),
        "前置条件：服务端证书应只有 DNS:board.example.com SAN；tls status:\n{status_text}"
    );
    assert!(
        !status_text.contains("IP:127.0.0.1") && !status_text.contains("IP:::1"),
        "前置条件：服务端证书不得含回环 IP SAN；tls status:\n{status_text}"
    );

    // 2) 切到 ACME 域名模式 + admin_tls=required，admin 仍绑回环。
    let text = fs::read_to_string(&install.config).expect("重读 hub.toml");
    let text = set_config_value(&text, Some("tls"), "mode", "\"acme-domain\"");
    let text = set_config_value(&text, Some("tls"), "acme_email", "\"admin@example.com\"");
    let text = set_config_value(
        &text,
        Some("tls"),
        "acme_directory",
        "\"https://127.0.0.1:1/dir\"",
    );
    let text = set_config_value(&text, Some("tls"), "domains", "[\"board.example.com\"]");
    let text = set_config_value(&text, None, "admin_tls", "\"required\"");
    rewrite_config(&install.config, &text);
    assert!(
        text.contains("admin_listen = \"127.0.0.1:")
            && text.contains("admin_tls = \"required\"")
            && text.contains("mode = \"acme-domain\""),
        "前置条件：配置必须是 ACME + admin_tls=required + 回环 admin_listen:\n{text}"
    );

    // 3) 必须失败退出，不能挂起。
    let mut run = HubRun::spawn(&install.config);
    let exit = run.wait_exit(Duration::from_secs(20));
    if exit.is_none() {
        let (status, stdout, stderr) = run.stop();
        panic!(
            "ACME 域名 + 回环 admin_tls=required 必须 fail-closed，但 hub run 仍存活；\
             终止状态={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    let (status, stdout, stderr) = run.stop();
    assert!(
        !status.success(),
        "ACME 域名 + 回环 admin_tls=required 必须非零退出；status={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // 三条路径必须分别自包含：各路径的关键词只在该路径切片内断言，避免用
    // 前面路径出现的 self-signed / 127.0.0.1 / rotate-cert 让第 3 条虚假通过。
    let [path1, path2, path3] = numbered_path_sections(&stderr);
    assert!(
        path1.contains("0.0.0.0:8444")
            && path1.contains("防火墙")
            && path1.contains("安全组"),
        "路径 1 必须同时包含 0.0.0.0:8444、防火墙、安全组；实际路径 1:\n{path1}\n完整 stderr:\n{stderr}"
    );
    assert!(
        (path2.contains("admin_tls = \"off\"") || path2.contains("admin_tls=\"off\""))
            && path2.contains("反向代理"),
        "路径 2 必须同时包含 admin_tls = \"off\" 与反向代理；实际路径 2:\n{path2}\n完整 stderr:\n{stderr}"
    );
    let path3_unique_phrase = path3.contains("仅 self-signed")
        || path3.contains("仅限 self-signed")
        || path3.contains("只有 self-signed");
    assert!(
        path3_unique_phrase,
        "路径 3 必须带“仅 self-signed”（或等价唯一限定短语）；实际路径 3:\n{path3}\n完整 stderr:\n{stderr}"
    );
    assert!(
        path3.contains("加入 server_names"),
        "路径 3 必须明确写“加入 server_names”；实际路径 3:\n{path3}\n完整 stderr:\n{stderr}"
    );
    assert!(
        path3.contains("包含 127.0.0.1 SAN") || path3.contains("包含 ::1 SAN"),
        "路径 3 必须明确写“包含 127.0.0.1 SAN”（或 ::1 SAN）；实际路径 3:\n{path3}\n完整 stderr:\n{stderr}"
    );
    assert!(
        path3.contains("rotate-cert"),
        "路径 3 必须给出 rotate-cert 可执行命令；实际路径 3:\n{path3}\n完整 stderr:\n{stderr}"
    );

    // 不得出现“把回环 IP 加入公共 ACME / tls.domains”的误导。
    assert!(
        !stderr.contains("请先把 127.0.0.1（或管理端 DNS 名）加入 server_names / tls.domains"),
        "仍在建议把回环 IP 加入公共 ACME 域名（旧误导文案）；stderr:\n{stderr}"
    );
    if let Some(line) = misleading_loopback_acme_advice(&stderr) {
        panic!("错误信息包含“给公共 ACME 证书加回环 IP”的误导建议: {line}\n完整 stderr:\n{stderr}");
    }
}

fn current_euid() -> u32 {
    let output = Command::new("id").arg("-u").output().expect("执行 id -u");
    assert!(
        output.status.success(),
        "id -u 失败: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("解析 id -u 输出")
}

/// `chattr(1)` 设置/清除不可变位；用来在 root 下制造 chmod EACCES。
fn set_immutable(path: &Path, immutable: bool) -> Result<(), String> {
    let flag = if immutable { "+i" } else { "-i" };
    let output = Command::new("chattr")
        .arg(flag)
        .arg(path)
        .output()
        .map_err(|err| format!("无法执行 chattr: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "chattr {flag} {} 失败: {}{}",
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

struct ImmutableFile {
    path: PathBuf,
}

impl Drop for ImmutableFile {
    fn drop(&mut self) {
        if let Err(err) = set_immutable(&self.path, false) {
            eprintln!("清理不可变位失败（需人工检查）: {err}");
        }
    }
}

/// L-01 验收点：权限收紧失败（EACCES）时启动失败，不能静默继续。
///
/// 以 root 运行时普通 0555 目录无法阻止 chmod；这里用 `chattr +i` 让 account.json
/// 的 chmod 稳定返回 EPERM/EACCES。该用例需要 root + CAP_LINUX_IMMUTABLE，故显式
/// `#[ignore]`，默认套件不计入 passed。root 门禁必须额外执行：
/// `cargo test ... -- --ignored --exact run_fails_when_account_hardening_is_denied`。
/// 非 root 误跑时直接 panic 说明原因，不再静默 return 造成假跳过。
#[test]
#[ignore = "requires root + chattr +i (CAP_LINUX_IMMUTABLE)"]
fn run_fails_when_account_hardening_is_denied() {
    let euid = current_euid();
    if euid != 0 {
        panic!(
            "run_fails_when_account_hardening_is_denied 带 #[ignore]，只能由 root 门禁执行；\
             当前 euid={euid}，非 root 下 chattr +i 必然 EPERM，无法构造权限收紧失败"
        );
    }
    let install = init_install("harden-denied", 0);
    let acme_dir = install.data_dir.join("certs/acme");
    fs::create_dir_all(&acme_dir).expect("创建 certs/acme");
    set_mode(&acme_dir, 0o700);
    let account = acme_dir.join("account.json");
    fs::write(&account, ACCOUNT_JSON).expect("写 account.json");
    set_mode(&account, 0o644);
    let before = fs::read(&account).expect("读取 account.json");

    if let Err(reason) = set_immutable(&account, true) {
        panic!(
            "无法构造权限收紧失败（{reason}）；该 #[ignore] 用例要求 root + 支持 chattr +i \
             （CAP_LINUX_IMMUTABLE）的文件系统"
        );
    }
    let _immutable = ImmutableFile {
        path: account.clone(),
    };

    let mut run = HubRun::spawn(&install.config);
    let exit = run.wait_exit(Duration::from_secs(20));
    if exit.is_none() {
        let (status, stdout, stderr) = run.stop();
        panic!(
            "chmod account.json 失败（不可变位）时 hub run 必须失败退出，但仍在运行；\
             终止状态={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    let (status, stdout, stderr) = run.stop();
    assert!(
        !status.success(),
        "权限收紧失败时 hub run 必须非零退出，不能静默继续；status={status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let account_path = account.display().to_string();
    assert!(
        (stderr.contains("启动前收紧") || stderr.contains("权限失败"))
            && stderr.contains(&account_path),
        "失败信息必须同时包含“启动前收紧/权限失败”和具体 account.json 路径；\
         stderr:\n{stderr}"
    );
    assert_eq!(
        file_mode(&account),
        Some(0o644),
        "chmod 失败后 account.json 必须保持 0644"
    );
    assert_eq!(
        fs::read(&account).expect("失败后读取 account.json"),
        before,
        "权限收紧失败不得改写 account.json 内容"
    );
}
