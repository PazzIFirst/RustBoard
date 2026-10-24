//! 系统探测与端口选择。

use std::net::TcpListener;
use std::path::Path;

use rustboard_install::{detect_system, pick_free_port, require_root, require_systemd, SystemInfo};

#[test]
fn detect_system_matches_process() {
    let info: SystemInfo = detect_system();
    assert!(!info.os_name.is_empty());
    assert_eq!(info.arch, std::env::consts::ARCH);
    assert_eq!(info.systemd, Path::new("/run/systemd/system").is_dir());
}

#[test]
fn picked_port_is_in_five_digit_range() {
    for _ in 0..4 {
        let port = pick_free_port(&[]).unwrap();
        assert!((20_000..=64_999).contains(&port), "{port}");
        TcpListener::bind(("127.0.0.1", port)).unwrap();
    }
}

#[test]
fn excluded_port_list_is_honored() {
    let all: Vec<u16> = (20_000..=64_999).collect();
    assert!(pick_free_port(&all).is_err());
}

#[test]
fn root_and_systemd_requirements_are_consistent() {
    let info = detect_system();
    if info.euid == 0 {
        require_root().unwrap();
    } else {
        assert!(require_root().is_err());
    }
    if info.systemd {
        require_systemd().unwrap();
    } else {
        assert!(require_systemd().is_err());
    }
}
