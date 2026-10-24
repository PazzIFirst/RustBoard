# v0.4.1 已知问题修复计划

> 状态：已发布（v0.4.1，`8d42d03`）　｜　基线：`v0.4.0`（`818d42d`）
> 输入：[known-issues.md](../known-issues.md)、M4 评审/复审记录、v0.4.0 发布说明
> 目标：在不引入新功能的前提下，修复 v0.4.0 遗留的可修复缺陷，并补齐 SFTP 真实环境验证。
>
> 实现备注：KI-31 下载硬限固定 64 MiB（`max_object_bytes` 只控分片），新增加性
> `downloadable` 字段；KI-29 在每批 prune 事务内降水位并在最大 rowid 行删除时
> 推进 `raw_prune_generation`，downsample 用 rowid+generation CAS 认领，关闭并发
> 回写竞态（不升 schema）；SFTP 真实环境 29/29。

## 1. 目标与非目标

### 目标

1. 修复 **KI-29**（降采样 rowid 复用边界）和 **KI-31**（归档对象上限/下载硬限不一致）；
2. 修复 **KI-28**（单 IP 连接拒绝 WARN 未采样）和 **KI-20**（安装命令 name 未转义）；
3. 完成 **SFTP 真实服务器验证**（密码 + ed25519、目录创建、上传/下载），不要求新增后端；
4. 保持 v0.4.0 的协议 v2、schema v7、证书格式和 API 兼容（KI-29 不升 schema）；
5. 产出一份可复核的 v0.4.1 回归报告，作为 M4 专项渗透的前置。

### 非目标

- 不做归档流式下载（KI-31 先收敛配置上限；流式下载放 v0.5.0）；
- 不实现 PostgreSQL、ACME、安装器/镜像（M5）；
- 不改通知渠道协议、不外发真实 secret；
- 不修复设计取舍类 KI-13~16、KI-23、KI-25；KI-22 排入 v0.5.0。

## 2. 优先级与版本

| ID | 级别 | 目标 | 修复主题 | 预估 | 依赖 |
|---|---|---|---|---|---|
| KI-29 | 低（数据完整性） | v0.4.1 | raw 删除后原子降低 rowid 水位 | 1–2 天 | 无 schema |
| KI-31 | 中（功能一致性） | v0.4.1 | 归档对象上限收敛到 64 MiB | 1 天 | 需配置迁移说明 |
| KI-28 | 低（日志放大） | v0.4.1 | 每 IP 窗口首条 WARN，其余 DEBUG | 1 天 | 无 |
| KI-20 | 低（命令注入面） | v0.4.1 | 安装命令 name 安全引用 | 0.5 天 | 无 |
| SFTP 验证 | 验证缺口 | v0.4.1 | 真实 OpenSSH SFTP 验证 | 1–2 天 | 测试机/容器 |
| KI-22 | 低 | v0.5.0 | 打开后 `fstat` 拒绝硬链接 | 1–2 天 | 需评估 fd 语义 |

v0.4.1 是补丁版本：不新增配置项，不改 API/协议/schema 版本；只允许收紧校验与修复缺陷。

## 3. 逐项方案

### 3.1 KI-29：raw 删除后 rowid 水位复用

**问题**：`samples` 的 rowid 会被 SQLite 复用；若“最大 rowid”行先被 retention 删除，
随后迟到行复用同一 rowid，`downsample_1m_last_raw_rowid` 可能误判为已认领。

**修复设计（不升 schema）**：

- 在 `prune_samples_before` 的**同一个写事务**内，删除完成后读取 `MAX(rowid)`；
- 若 `downsample_1m_last_raw_rowid` 存在且 **大于** 新 `MAX(rowid)`，原子地把它降为
  新 `MAX(rowid)`；表为空时清除该水位；
- 不得在新水位写入前释放写锁，避免新 raw 插入抢在降水位前；
- 只降低、不抬高，避免跳过尚未扫描的行；
- 增加日志（只含旧/新 rowid 数值）和 `maintenance_state` 失败回滚测试。

**验收**：

- 构造“最大 rowid 迟到行 → retention 删除 → 插入复用 rowid 的迟到行”回归，
  `maintenance run --task downsample` 能重算 1m/1h；
- 正常保留期删除不重复扫描、不丢水位；
- 并发插入/删除下无 `database is locked` 新增回归；
- 不改变 `maintenance run --task downsample` 输出字段。

**回滚**：只回代码；已降低的水位是安全方向（最多重扫，不漏算），无需数据修复。

### 3.2 KI-31：归档对象上限与下载硬限

**问题**：`archive.max_object_bytes` 可配 1 GiB，但 hub 下载硬限 64 MiB，导致
上传成功的大对象无法下载。

**修复设计（v0.4.1，推荐）**：

- 配置校验把 `archive.max_object_bytes` 上限从 1 GiB 收紧到 **64 MiB**
  （下界 1 MiB 不变）；错误信息明确“下载内存上限”。
- `archive.max_object_bytes` 仍控制 worker 分片；默认 32 MiB 不变。
- 已有 >64 MiB 对象：不删除、不自动重传；`/api/v1/archive/objects` 与 `/archive`
  页面显示 `downloadable=false` 或状态提示，下载返回 413 + 固定说明；
  文档给出“直接访问冷存储/等待 v0.5 流式下载”的处置。
- 不引入流式 `ColdStore`；流式方案在 v0.5.0 单独立项（需要 trait/DTO 变更）。

**验收**：

- 配置 64 MiB 通过；64 MiB + 1 启动拒绝；错误码/文案稳定；
- 64 MiB 对象可下载且 SHA/长度校验通过；>64 MiB 旧对象下载 413、不读 body；
- 面板不把不可下载对象渲染成可点击按钮；
- 发布说明写明配置收紧属于**有意 breaking change**。

### 3.3 KI-28：连接拒绝 WARN 采样

**修复设计**：

- 复用认证失败限速的窗口采样模式：按来源 IP 每 60s 窗口首条拒绝 WARN，
  其余 DEBUG；不改变拒绝行为、不新增配置；
- 表需要有界（例如最多 4096 个 IP，过期清理），避免攻击者用大量来源 IP
  把采样表变成内存放大；
- 日志字段只保留来源 IP、计数、窗口，不回显端口/证书；
- 单测覆盖窗口边界、表满、不同 IP 不互相抑制；e2e 用 `max_connections_per_ip=2`
  连续建 40 条 TCP，断言 WARN 数量为 1、其余 DEBUG。

**验收**：拒绝行为/状态码不变；日志放大被抑制；采样表容量有界。

### 3.4 KI-20：安装命令 name 转义

**修复设计**：

- 统一 shell 单引号引用函数：`'` → `'\''`；对换行/控制字符先拒绝或转义；
- 所有拼接进安装命令的字段（name、fingerprint、hub URL、token）都走同一函数；
- 增加 name 含空格、`'`、`$()`、反引号、分号的单测；
- 不改变正常 name 的命令可读性。

**验收**：恶意 name 不会在目标 shell 执行；正常 name 安装命令保持不变；
`agent add` 输出仍可直接粘贴执行。

### 3.5 SFTP 真实服务器验证（验证缺口）

**环境**：隔离容器/测试机，OpenSSH `sshd` + `internal-sftp`，临时用户，
只监听 `127.0.0.1` 随机端口；主机密钥 ed25519；用户密钥 ed25519（0600）。

**用例**：

1. `archive test` 密码认证成功；错误密码固定失败；
2. ed25519 私钥认证成功；0644 私钥拒绝；错误指纹拒绝；
3. 远端目录逐级创建（含 `health/` 清理）；
4. 一天数据 2 分片上传 + manifest + HEAD 大小校验；
5. 删除远端对象后 `get/head` 返回 NotFound/None；
6. 主机密钥换成另一把 ed25519 → 握手拒绝；
7. RSA-only 主机密钥 → 明确失败（文档化不支持）；
8. 进程退出/断网时 worker 失败不推进水位、raw 保留。

**不通过处理**：视为 v0.4.1 发布阻塞；只修复 SFTP，不放宽主机密钥校验。

### 3.6 KI-22（v0.5.0）

- 在 `openat2` 打开日志文件后 `fstat`；`nlink != 1` 拒绝；
- 需要确认与日志轮转/`O_PATH`/目录 fd 的交互；
- 单测覆盖硬链接、普通文件、轮转后重开；仍保留现有路径校验。

## 4. 测试与门禁

每个修复都必须：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit
```

v0.4.1 发布前额外：

- `bash tests/e2e/v040.sh`（27 项，防 M4 回归）
- `bash tests/e2e/panel.sh`（159 项）
- `bash tests/e2e/security.sh`（9 项）
- 新增 `tests/e2e/v041.sh`：KI-29 复用 rowid、KI-31 64 MiB 边界、KI-20 name 转义
- SFTP 真实验证记录（命令、脱敏日志、对象 sha256）
- 独立评审 + 对 KI-29/KI-31 的针对性复审；修复严重问题必须换新评审

## 5. 发布与回滚

- 版本：`0.4.1`；CHANGELOG 增加 `[0.4.1]`；
- 兼容性：协议 v2、schema v7、API 路径不变；KI-31 配置收紧为 breaking change；
- 发布顺序：先 hub 再 agent（agent 无行为变更，可同版本）；
- 回滚：代码可回 v0.4.0；KI-29 已降水位的库仍安全（最多重扫）；KI-31 旧配置
  回滚后可继续启动，但大对象仍不可下载；
- 不移动 `v0.4.0` tag；v0.4.1 新 tag。

## 6. 时间表（建议）

| 日期 | 交付 |
|---|---|
| 2026-10-27 | KI-29/KI-31 设计评审 + 失败测试 |
| 2026-10-29 | KI-29/28/20/31 实现 + 单测 |
| 2026-10-30 | SFTP 真实环境验证 + v041 e2e |
| 2026-10-31 | 独立评审/复审、全量门禁、v0.4.1 发布 |

## 7. 完成定义（DoD）

- [x] KI-29/28/20/31 状态改为“已修复”，补回归用例与修复记录；
- [x] KI-31 配置收紧写入 CHANGELOG/README/升级说明；
- [x] SFTP 密码与 ed25519 真实验证通过，报告脱敏归档；
- [x] v040/panel/security + 新 v041 e2e 全绿；
- [x] audit 0、clippy/fmt 0、独立评审无未关闭 [严重]；
- [x] v0.4.1 tag/GitHub Release 发布，main 与 tag 可追溯。

## 8. 关联

- [known-issues.md](../known-issues.md)
- [M4 方案](2026-10-24-m4-alerting-archive.md)
- [M4 渗透测试计划](2026-10-24-m4-pentest.md)
- [status.md](../status.md)
