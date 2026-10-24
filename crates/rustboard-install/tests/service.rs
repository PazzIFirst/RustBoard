//! systemd unit 渲染、静态 unit 同步、ServiceManager 与 HTTP 健康检查。

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;
use std::time::Duration;

use rustboard_install::{
    is_systemd_unit_dir, render_unit, shell_arg, unit_is_ours, PathOverrides, Paths, Role,
    ServiceManager, UNIT_MARKER,
};

const HUB_STATIC: &str = include_str!("../../../packaging/systemd/rustboard-hub.service");
const AGENT_STATIC: &str = include_str!("../../../packaging/systemd/rustboard-agent.service");
const PANEL_STATIC: &str = include_str!("../../../packaging/systemd/rustboard-panel.service");

#[test]
fn production_default_render_matches_packaging_static_units() {
    for (role, packaged) in [
        (Role::Hub, HUB_STATIC),
        (Role::Agent, AGENT_STATIC),
        (Role::Panel, PANEL_STATIC),
    ] {
        let paths = Paths::for_role(role, Path::new("/"), PathOverrides::default()).unwrap();
        let rendered = render_unit(role, &paths).unwrap();
        assert_eq!(rendered, packaged, "{role} 的静态 unit 与渲染结果不一致");
        assert_eq!(rendered.lines().next(), Some(UNIT_MARKER));
        assert!(rendered.contains("NoNewPrivileges=true"));
        assert!(rendered.contains("ProtectSystem=strict"));
        assert!(rendered.contains("ProtectHome=true"));
        assert!(rendered.contains("ReadWritePaths=/var/lib/rustboard/"));
        assert!(!rendered.contains('@'));
        assert!(unit_is_ours(role, &paths, &rendered));
    }
}

#[test]
fn prefix_render_uses_absolute_prefixed_paths() {
    let temp = common::TempDir::new("render-prefix");
    let paths = Paths::for_role(Role::Hub, temp.path(), PathOverrides::default()).unwrap();
    let rendered = render_unit(Role::Hub, &paths).unwrap();

    let expected_exec = format!(
        "ExecStart={}/usr/local/bin/rustboard-hub run --config {}/etc/rustboard/hub.toml",
        temp.path().display(),
        temp.path().display()
    );
    assert!(rendered.contains(&expected_exec), "{rendered}");
    assert!(rendered.contains(&format!(
        "ReadWritePaths={}/var/lib/rustboard/hub",
        temp.path().display()
    )));
    assert!(!rendered.contains('@'));
}

#[test]
fn placeholder_text_inside_path_is_not_replaced_twice() {
    let temp = common::TempDir::new("render-at");
    let prefix = temp.join("@CONFIG@");
    let paths = Paths::for_role(Role::Hub, &prefix, PathOverrides::default()).unwrap();
    let rendered = render_unit(Role::Hub, &paths).unwrap();
    let expected = format!(
        "ExecStart={}/usr/local/bin/rustboard-hub run --config {}/etc/rustboard/hub.toml",
        prefix.display(),
        prefix.display()
    );
    assert!(rendered.contains(&expected), "{rendered}");
}

#[test]
fn render_rejects_newline_injection() {
    let prefix = Path::new("/tmp/rustboard\nExecStart=/bin/sh -c id");
    let paths = Paths::for_role(Role::Hub, prefix, PathOverrides::default()).unwrap();
    let err = render_unit(Role::Hub, &paths).unwrap_err();
    assert!(format!("{err:#}").contains("换行"), "{err:#}");
}

#[test]
fn shell_arg_matches_posix_quoting_rules() {
    assert_eq!(shell_arg("simple"), "simple");
    assert_eq!(shell_arg("/a-b_c.d:e@f%g+h,i"), "/a-b_c.d:e@f%g+h,i");
    assert_eq!(shell_arg("with space"), "'with space'");
    assert_eq!(shell_arg("a'b"), r"'a'\''b'");
    assert_eq!(shell_arg("$HOME"), "'$HOME'");
    assert_eq!(shell_arg(""), "''");
}

#[test]
fn write_unit_writes_0644_and_dry_run_writes_nothing() {
    let temp = common::TempDir::new("service-write");
    let unit_dir = temp.join("units");
    let manager = ServiceManager::new(unit_dir.clone(), false, false);
    let path = manager
        .write_unit("rustboard-test.service", "[Unit]\nDescription=x\n")
        .unwrap();
    assert_eq!(path, unit_dir.join("rustboard-test.service"));
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "[Unit]\nDescription=x\n"
    );
    assert_eq!(common::mode_of(&path), 0o644);

    let dry_dir = temp.join("dry-units");
    let dry = ServiceManager::new(dry_dir.clone(), false, true);
    let dry_path = dry
        .write_unit("rustboard-dry.service", "[Unit]\nDescription=x\n")
        .unwrap();
    assert_eq!(dry_path, dry_dir.join("rustboard-dry.service"));
    assert!(!dry_dir.exists());

    assert!(manager.write_unit("../escape.service", "x").is_err());
    assert!(manager.write_unit("a/b.service", "x").is_err());
    assert!(manager.write_unit("-x.service", "x").is_err());
    assert!(manager.write_unit("x.service", "bad\0unit").is_err());
}

#[test]
fn manage_false_skips_systemctl_for_all_operations() {
    let manager = ServiceManager::new(
        std::env::temp_dir().join("rustboard-install-no-systemctl"),
        false,
        false,
    );
    manager.daemon_reload().unwrap();
    manager.enable_now("rustboard-hub.service").unwrap();
    manager.restart("rustboard-hub.service").unwrap();
    manager.stop_disable("rustboard-hub.service").unwrap();
    assert!(!manager.is_active("rustboard-hub.service").unwrap());
}

#[test]
fn fragment_checks_skip_systemctl_when_unmanaged_or_dry_run() {
    let unit = "rustboard-hub.service";
    let expected = Path::new("/etc/systemd/system/rustboard-hub.service");

    // manage=false：不查询 systemd，FragmentPath 视为未知（None），检查跳过。
    let unmanaged = ServiceManager::new(
        std::env::temp_dir().join("rustboard-install-fragment-unmanaged"),
        false,
        false,
    );
    assert_eq!(unmanaged.fragment_path(unit).unwrap(), None);
    unmanaged.ensure_fragment_is(unit, expected).unwrap();
    // 跳过 systemctl 不等于跳过参数校验：相对路径 / 非法 unit 名仍然报错。
    assert!(unmanaged
        .ensure_fragment_is(unit, Path::new("etc/unit"))
        .is_err());
    assert!(unmanaged.fragment_path("-x.service").is_err());

    // dry_run=true（即使 manage=true）同样不执行 systemctl。
    let dry = ServiceManager::new(
        std::env::temp_dir().join("rustboard-install-fragment-dry"),
        true,
        true,
    );
    assert_eq!(dry.fragment_path(unit).unwrap(), None);
    dry.ensure_fragment_is(unit, expected).unwrap();
}

/// 单次响应服务器；返回端口和线程句柄。
fn serve_once(response: &'static [u8]) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(response);
        }
    });
    (port, handle)
}

#[test]
fn wait_http_ok_accepts_http_200() {
    let (port, handle) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    rustboard_install::wait_http_ok(
        &format!("http://127.0.0.1:{port}/healthz"),
        Duration::from_secs(3),
    )
    .unwrap();
    handle.join().unwrap();
}

#[test]
fn wait_http_ok_retries_until_200() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for (index, response) in [
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(response);
            if index == 0 {
                // 模拟服务刚启动尚未 ready：第一次非 200，随后成功。
                thread::sleep(Duration::from_millis(50));
            }
        }
    });
    rustboard_install::wait_http_ok(
        &format!("http://127.0.0.1:{port}/healthz"),
        Duration::from_secs(3),
    )
    .unwrap();
    handle.join().unwrap();
}

#[test]
fn wait_http_ok_rejects_https_and_non_200_times_out() {
    assert!(rustboard_install::wait_http_ok(
        "https://127.0.0.1:1/healthz",
        Duration::from_millis(50)
    )
    .is_err());

    let (port, handle) =
        serve_once(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
    let err = rustboard_install::wait_http_ok(
        &format!("http://127.0.0.1:{port}/healthz"),
        Duration::from_millis(150),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("超时"), "{err:#}");
    handle.join().unwrap();
}

#[test]
fn wait_http_ok_connect_failure_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // 不 accept：连接会进入 backlog，客户端读响应超时后重试。
    let err = rustboard_install::wait_http_ok(
        &format!("http://127.0.0.1:{port}/healthz"),
        Duration::from_millis(150),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("超时"), "{err:#}");
    drop(listener);
}

#[test]
fn unit_is_ours_requires_marker_and_exact_exec_start() {
    let paths = Paths::for_role(Role::Hub, Path::new("/"), PathOverrides::default()).unwrap();
    let rendered = render_unit(Role::Hub, &paths).unwrap();
    assert!(unit_is_ours(Role::Hub, &paths, &rendered));

    let without_marker = rendered.replacen(&format!("{UNIT_MARKER}\n"), "", 1);
    assert_ne!(without_marker, rendered);
    assert!(!unit_is_ours(Role::Hub, &paths, &without_marker));

    let expected = "ExecStart=/usr/local/bin/rustboard-hub run --config /etc/rustboard/hub.toml";
    assert!(rendered.lines().any(|line| line == expected));
    let altered = rendered.replace(expected, "ExecStart=/bin/true");
    assert_ne!(altered, rendered);
    assert!(!unit_is_ours(Role::Hub, &paths, &altered));

    // 只做宽松 contains 会漏掉“多一个空格 / 前缀”这类伪行；这里必须整体不匹配。
    let prefixed = rendered.replace(expected, &format!(" {expected}"));
    assert!(!unit_is_ours(Role::Hub, &paths, &prefixed));

    let other_paths =
        Paths::for_role(Role::Hub, Path::new("/opt/rb"), PathOverrides::default()).unwrap();
    assert!(!unit_is_ours(Role::Hub, &other_paths, &rendered));
}

#[test]
fn render_rejects_unit_special_characters() {
    for prefix in [
        "/opt/rb$",
        "/opt/rb%",
        "/opt/rb\"",
        "/opt/rb'",
        "/opt/rb\\",
        "/opt/rb\u{7}",
    ] {
        let paths =
            Paths::for_role(Role::Hub, Path::new(prefix), PathOverrides::default()).unwrap();
        let err = render_unit(Role::Hub, &paths).unwrap_err();
        assert!(
            format!("{err:#}").contains("特殊字符") || format!("{err:#}").contains("控制字符"),
            "{prefix:?}: {err:#}"
        );
    }
}

#[test]
fn systemd_unit_dirs_are_recognized() {
    for dir in [
        "/run/systemd/system",
        "/etc/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/usr/local/share/systemd/system",
    ] {
        assert!(is_systemd_unit_dir(Path::new(dir)), "{dir} 应被识别");
        assert!(
            is_systemd_unit_dir(&Path::new(dir).join("")),
            "{dir}/ 应被识别"
        );
    }
    for dir in [
        "",
        "etc/systemd/system",
        "/etc/systemd",
        "/run/systemd",
        "/opt/systemd/system",
        "/tmp/systemd/system",
        "/etc/systemd/system/../other",
    ] {
        assert!(!is_systemd_unit_dir(Path::new(dir)), "{dir:?} 不应被识别");
    }
}
