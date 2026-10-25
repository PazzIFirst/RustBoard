# M5 Phase B 交付证据（2026-10-25）

> 本文件记录 Phase B checkpoint 前的可复现证据。发布版本仍为 `v0.4.2` 工作区包；
> `v1.0.0` 的 tag/Release/GHCR 正式发布留 Phase E。

## 1. 产物与校验

| 产物 | SHA-256 |
|---|---|
| `packaging/install.sh` / 两包内 `install.sh` | `48ba90cb2b330c05b225752857c5defda3cf2b28b3895f2bad28756db7456089` |
| `dist/serverdashboard-v0.4.2-x86_64.tar.gz` | `e95fe644331c15dc2e83e99c6ddf19d368393c1f626b46c723d0b57c6ab9e1ae` |
| `dist/serverdashboard-v0.4.2-aarch64.tar.gz` | `b09ef65deb88a181e7bece9bc84af896e7d42e0878285696bf426f4e27fa6f03` |
| `dist/amd64/bin/rustboard-hub`（LTO thin） | `d61f48c53dada98aa9a197c1a0707b153a75eababf373a3440971f9a9c944376` |
| `dist/arm64/bin/rustboard-hub`（本地重编，含 inherited；发布由原生 arm64 runner 重建） | `f264511008c368d23acf113ddfe4385e26553711982c4ee521310828a4179b6d` |

两个包内/包外 `SHA256SUMS` 均 `sha256sum -c --strict` 通过。

## 2. 静态构建

- 仓库 `docker/Dockerfile.build` x86_64 实测成功：三个二进制 `static-pie`，无 `INTERP`，
  `rustboard-hub --version` 0.4.2，`.comment` 含 Alpine 14.2.0；与包内 x86 二进制逐字节一致。
- arm64 三个二进制 `statically linked`，无 `INTERP`，qemu `--version` 0.4.2；
  本地重编 hub 后重新打包，包内 hub 与源 dist 一致。
- 构建镜像固定：`rust:1.89-alpine@sha256:4b800f2e72e04be908e5f634c504c741bd943b763d1d8ad7b096cc340e1b5b46`。

## 3. 测试证据

| 测试 | 结果 | 日志 |
|---|---|---|
| `tests/e2e/v100-offline.sh`（新 x86 包，含 agent 真实 enrollment、STRICT=1 复测） | **122 PASS / 0 FAIL / 0 SKIP** | `/tmp/v100-offline-strict-review.log` |
| `tests/e2e/v100-arm64.sh`（新 arm64 包） | **40 PASS / 0 FAIL / 2 SKIP**（x86 主机按设计不能直接执行 arm64 `install.sh`；qemu 安装/hub healthz 通过） | `/tmp/v100-arm64-final.log` |
| `tests/e2e/v100-docker.sh`（新包、来源校验、agent enrollment、arm64 QEMU） | **126 PASS / 0 FAIL / 0 SKIP** | `/tmp/v100-docker-final2.log` |
| `tests/e2e/v100-install.sh`（Phase A 回归） | **121 PASS / 0 FAIL** | `/tmp/v100-install-run.log` |
| `cargo test --workspace --locked` | **1080 passed / 0 failed** | `/tmp/rb-test-final.log` |
| `cargo fmt` / `clippy -D warnings` / `cargo audit` | 通过 / 通过 / 0 漏洞（411 deps） | `/tmp/rb-clippy-final.log` / `/tmp/rb-audit2.log` |
| 前端 `tsc` / vitest / build | 通过 / 80 passed / build | 终端输出 |
| `actionlint` / shellcheck / `bash -n` | 通过 | 终端输出 |

## 4. arm64 wrapper + 锁继承

- 在 arm64 Debian 容器中，用新包执行
  `install.sh hub --yes --offline --no-systemd --prefix /opt/rb --panel no`：成功，
  config/web 落盘，`rustboard-hub --version` 0.4.2。
- 外部持有 `/run/rustboard-install.lock` 时：设置
  `RUSTBOARD_INSTALL_LOCK_HELD=1` 的 arm64 hub 安装成功（跳过二次锁）；不设置则
  在写盘前失败。这关闭了 H-01 的 arm64 部分。

## 5. 多架构镜像（本地 registry 演练，非 GHCR）

在本地 `registry:2` 上合并 amd64/arm64 单架构镜像，三个 role 的
`v0.4.2` / `sha-e6f4a7630255` / `latest` 指向同一 digest：

| role | digest |
|---|---|
| hub | `sha256:8ac30bee7e03987a78929f4b6ce9a6d2553dbe953f9ffee115b82350bc43729d` |
| panel | `sha256:da8c8cf8cb1b11d8247a2d98813a2e30cdc989730b9fd814bf97b8dcebed432f` |
| agent | `sha256:ca1b82291158a4617e976bf77b48805578518ecec91d97f5d0899e578afde20e` |

manifest 同时含 `linux/amd64`、`linux/arm64`（以及 buildx 生成的 attestation
`unknown/unknown`）；`docker run --platform linux/arm64 ... hub:latest --version`
返回 0.4.2。

## 6. 未执行 / 已知残余

- 未用真实 `v*` tag 触发 GitHub Actions，未推 GHCR，未生成真实 GitHub Release/
  attestation；workflow 已 actionlint，并以本地 registry/fake gh 验证时序。
- `delivery-e2e` 的 GitHub hosted runner `sudo/unshare/strace` 未实跑；失败会阻塞发布，
  不会绕过。
- S1 信号竞态（child 成功后、`WEB_COMMITTED` 置位前的 SIGTERM；hub 子 panel 的
  descendant）为残余边界，未做代码修复；不涉及远程攻击或数据丢失，记录在评审/渗透报告。
- `--skip-build` 的 musl `.comment` 断言是防误用，不是密码学证明；发布 workflow 不使用
  `--skip-build`。
- 只读根需 `--tmpfs /run`（Phase A 安装锁）；文档已补。
- 正式 `v1.0.0` 的 CHANGELOG 归档、tag、Release、镜像推送在 Phase E 执行。
