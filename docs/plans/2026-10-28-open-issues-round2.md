# 2026-10-28 开放 issue 第二轮核实与修复方案

## 0. 状态与基线

- 核实基线：`c5316b4`（产品代码与 `745d2f9` 相同；两者之间只有 docs/plans 和 v041 测试断言变更）。
- 上一轮 #43–#50、#55 已按用户确认关闭；本方案不重新打开、不移动 `v1.0.0-rc.2`，也不移动已推送的 `v1.0.0-rc.3`。
- 本轮新开 issue 中 **#51–#54、#56–#102 共 51 条仍 OPEN**；#55 是已关闭的 v041 测试契约 issue，不重复处理。
- 本轮只做核实与方案，**未修改产品代码**。核实以 6 个独立只读子代理 + 主 Agent 抽查完成；静态证明为主，#51/#59 有仓库外最小复现，#81/#88/#89 有独立数值/Bash 复现。
- 结论：**51 条 OPEN issue 全部 CONFIRMED，没有 REFUTED**。其中若干为测试门禁、文档或 vendored 库问题，不等于 51 条都是产品运行时缺陷；级别/影响按下方分类。
- 当前 release 状态：`v1.0.0-rc.3` tag 已存在；rc.3 的 24h soak 在约 12.5h 时因本轮需要改代码主动中止，证据目录为
  `target/load/20261027T025506Z-200a-aborted/`，**不是有效 24h 证据**。`v1.0.0` 未发布。
- 新修复必须进入新 tag `v1.0.0-rc.4`；在全部门禁通过前不发布 `v1.0.0`。

## 1. 核实总表

| Issue | 级别 | 结论 | 主题 | 集群 | 阶段 | 发布阻塞 |
|---|---|---|---|---|---|---|
| #51 | P1 | CONFIRMED | [升级数据丢失] v7→v8 按聚合 count 认领现存 raw，会误删尚未聚合的迟到数据 | 数据/迁移/备份 | P1 | 是 |
| #52 | P2 | CONFIRMED | [备份] 在线快照未与证书轮换互斥，可能备份不配套的证书和私钥 | 数据/迁移/备份 | P1 | 是 |
| #53 | P2 | CONFIRMED | [安装器] Hub 安装确认回答 n 后仍继续写入系统 | 安装器/Docker/面板 | P4 | 是 |
| #54 | P2 | CONFIRMED | [发布] Release 未检查目标提交的安全 E2E，CI 红灯仍可进入正式发布 | 告警/日志/发布 | P3 | 是 |
| #56 | P2 | CONFIRMED | [Docker] Agent 入口固定 fingerprint 模式，无法完成 ACME Hub 的纳管后连接 | 安装器/Docker/面板 | P4 | 是 |
| #57 | P2 | CONFIRMED | [控制面] 周期续签期间已执行命令的应答滞留，导致 Hub 误报超时 | Agent/控制面 | P2 | 是 |
| #58 | P1 | CONFIRMED | [迁移] 事件清理后迁移会重置自增编号，旧通知游标持续跳过新告警 | 数据/迁移/备份 | P1 | 是 |
| #59 | P2 | CONFIRMED | [迁移] 聚合时间戳用 i64 求和，约 515 万条分钟聚合即可使合法库迁移失败 | 数据/迁移/备份 | P1 | 是 |
| #60 | P2 | CONFIRMED | [安装器] ACME 长输出截断检查固定 UTF-8 边界，中文输出可让安装进程永久循环 | 安装器/Docker/面板 | P4 | 是 |
| #61 | P2 | CONFIRMED | [日志] backup/restore/migrate 的 TOML 解析错误会回显含 token 的配置原文 | 告警/日志/发布 | P3 | 是 |
| #62 | P2 | CONFIRMED | [日志] PostgreSQL 密码参数名百分号编码后绕过 DSN 脱敏 | 告警/日志/发布 | P3 | 是 |
| #63 | P2 | CONFIRMED | [Agent] max_batch_samples 配置从未读取，采集批次不遵守上限 | Agent/控制面 | P2 | 是 |
| #64 | P2 | CONFIRMED | [备份] DSN 同时含两处 password 时，备份选用的密码与 Hub 驱动不同 | 数据/迁移/备份 | P1 | 是 |
| #65 | P2 | CONFIRMED | [控制面] 排队期间已返回 504 的未派发请求，稍后仍会执行 | Agent/控制面 | P2 | 是 |
| #66 | P2 | CONFIRMED | [采样] hub-self 的间隔设置保存成功，但本机采集始终使用启动配置 | Agent/控制面 | P2 | 是 |
| #67 | P1 | CONFIRMED | [备份] pg_dump/pg_restore 未继承 Hub TLS 策略，缺省可退回不校验证书的 prefer 模式 | 数据/迁移/备份 | P1 | 是 |
| #68 | P2 | CONFIRMED | [告警] 证书热加载失败时，到期告警读取磁盘新证书而忽略仍在服务的旧证书 | 告警/日志/发布 | P3 | 是 |
| #69 | P2 | CONFIRMED | [告警] 停用规则并清空状态后，旧评估仍可重建状态并产生通知 | 告警/日志/发布 | P3 | 是 |
| #70 | P2 | CONFIRMED | [告警] 渠道存在性校验与规则写入分离，并发删除可留下悬空 channel_ids | 告警/日志/发布 | P3 | 是 |
| #71 | P2 | CONFIRMED | [安装] Panel --force 复用外部 TLS 证书时改写为固定路径却不复制文件 | 安装器/Docker/面板 | P4 | 是 |
| #72 | P2 | CONFIRMED | [卸载] 三个角色忽略停服失败，仍删除 unit、二进制并可清空运行中的数据 | 安装器/Docker/面板 | P4 | 是 |
| #73 | P3 | CONFIRMED | [安装诊断] 腾讯云固定元数据域名被仅支持字面 IP 的探测器直接拒绝 | 文档/诊断 | P7 | 发布前文档 |
| #74 | P3 | CONFIRMED | [测试] 自动审计清理用例只查询最新 10 条，旧记录未删除也会通过 | 测试门禁 | P6 | 门禁修复 |
| #75 | P2 | CONFIRMED | [采集] Hub 本机采样入库失败后直接丢弃，缺少约定的缓冲与重试 | Agent/控制面 | P2 | 是 |
| #76 | P2 | CONFIRMED | [认证] 启动读取配置与 watcher 注册之间的密码重置会被吞掉，旧密码持续有效 | Agent/控制面 | P2 | 是 |
| #77 | P2 | CONFIRMED | [升级] Agent install --force 仅 enable --now，已运行服务不会切换到新二进制和配置 | 安装器/Docker/面板 | P4 | 是 |
| #78 | P2 | CONFIRMED | [控制面] 禁止列表漏掉 ssh 短名，规范化前检查与 systemctl 解析不一致 | Agent/控制面 | P2 | 是 |
| #79 | P2 | CONFIRMED | [Docker] 已初始化 volume 属主为 10001，文档的 root install --force 重配置流程必被 prefix 校验拒绝 | 安装器/Docker/面板 | P4 | 是 |
| #80 | P3 | CONFIRMED | [文档] Docker README 的镜像构建命令漏掉 -f docker/Dockerfile | 文档/诊断 | P7 | 发布前文档 |
| #81 | P2 | CONFIRMED | [测试] 两处 RSS 门禁将 KiB 与字节直接比较，内存阈值被放宽 1024 倍 | 测试门禁 | P6 | 门禁修复 |
| #82 | P2 | CONFIRMED | [测试] 告警压力门禁不要求规则启用或实际评估，健康检查 503 也可能 PASS | 测试门禁 | P6 | 门禁修复 |
| #83 | P3 | CONFIRMED | [测试] 正常会话保持探针收到 Problem 后仍把 held 标记为 true | 测试门禁 | P6 | 门禁修复 |
| #84 | P3 | CONFIRMED | [测试] 面板控制审计检查可被此前管理 API 的旧记录满足 | 测试门禁 | P6 | 门禁修复 |
| #85 | P3 | CONFIRMED | [测试] DOS-04b 将 agent 在线状态只写入描述，掉线仍可通过 | 测试门禁 | P6 | 门禁修复 |
| #86 | P3 | CONFIRMED | [测试] ARCH-15b 声称校验归档大小，却未比较远端 size 与数据库 bytes | 测试门禁 | P6 | 门禁修复 |
| #87 | P2 | CONFIRMED | [测试] Docker PG 的真实 agent 落库断言可被 Hub 自采样完全满足 | 测试门禁 | P6 | 门禁修复 |
| #88 | P2 | CONFIRMED | [测试] Compose 回环发布断言丢弃 host_ip，改为全网绑定仍可通过 | 测试门禁 | P6 | 门禁修复 |
| #89 | P2 | CONFIRMED | [测试] ARM64 与离线门禁被 TERM 中断后可能以 0 退出 | 测试门禁 | P6 | 门禁修复 |
| #90 | P2 | CONFIRMED | [测试] ALLOW_UNVERIFIED 遇到一项缺源即跳过全部来源 hash 校验 | 测试门禁 | P6 | 门禁修复 |
| #91 | P3 | CONFIRMED | [文档] 手工 PG 恢复切换 postgres 用户后无法读取 root 的 0700/0600 备份 | 文档/诊断 | P7 | 发布前文档 |
| #92 | P3 | CONFIRMED | [文档] 首页本地验收仍指定 rc.2 包，当前 rc.3 构建后无法执行下一步 | 文档/诊断 | P7 | 发布前文档 |
| #93 | P3 | CONFIRMED | [文档] ACME 管理 HTTPS 安装示例漏传监听地址，与默认回环校验冲突 | 文档/诊断 | P7 | 发布前文档 |
| #94 | P3 | CONFIRMED | [文档] compose exec id 验证的是新 root 进程，不能证明主进程已降权 | 文档/诊断 | P7 | 发布前文档 |
| #95 | P3 | CONFIRMED | [文档] ACME 安装页把普通证书续期窗口写为 1/3，实际上限是 48 小时 | 文档/诊断 | P7 | 发布前文档 |
| #96 | P2 | CONFIRMED | [SFTP] 空 SSH Data 被 ChannelRx 当成 EOF，合法消息可使归档会话提前失败 | SFTP/russh | P5 | 是（SFTP 条件） |
| #97 | P2 | CONFIRMED | [SFTP] SSH 窗口归零后断连不唤醒写入，可遗留后台 writer 任务 | SFTP/russh | P5 | 是（SFTP 条件） |
| #98 | P2 | CONFIRMED | [SFTP] 协商时丢弃反向 cipher 列表，双向使用不同算法的合法后端无法连接 | SFTP/russh | P5 | 是（SFTP 条件） |
| #99 | P3 | CONFIRMED | [依赖] vendored ssh-key：RSA 私钥相等比较遗漏另一侧 iqmp | vendored ssh-key | P8 | 否（库级 P3） |
| #100 | P3 | CONFIRMED | [依赖] vendored ssh-key：证书算法解析器可返回违反不变量的 AlgorithmName | vendored ssh-key | P8 | 否（库级 P3） |
| #101 | P3 | CONFIRMED | [依赖] vendored ssh-key：带选项且无注释的 authorized_keys 合法行解析失败 | vendored ssh-key | P8 | 否（库级 P3） |
| #102 | P3 | CONFIRMED | [依赖] vendored ssh-key：拒绝规范编码不足 32 字节的合法 ECDSA 私钥标量 | vendored ssh-key | P8 | 否（库级 P3） |

> 结论说明：所有 issue 的根因均存在；但 #74、#81–#90 是测试门禁缺陷，#73、#80、#91–#95 是文档/诊断缺陷，#99–#102 是 vendored 库 API 缺陷且当前 RustBoard 业务路径未使用。其余 P1/P2 是产品行为缺陷。

## 2. 关键设计决定

### D1. schema v9：保守的 raw 归属与告警版本

**#51 是 P1，必须先解决。**

当前 v8 迁移按 `ROW_NUMBER() ... <= samples_1m.count` 认领 raw，无法证明现存 raw 就是历史聚合的那批行；旧 raw 被保留期删除后补传的迟到行会被误认领，随后 delta 跳过、retention 删除。

决定：**不再用“行数恰好”推断归属；引入 schema v9。**

1. `samples.aggregated_1m` 语义扩展为三态：
   - `0`：未聚合，可被 v8 delta 处理；
   - `1`：已确认进入历史聚合，可被 retention/archive 处理；
   - `2`：**quarantine/归属不明**，delta、retention、archive 全部跳过，只在状态/审计中报告，不能删除。
   不新增列（复用 INTEGER），但 schema 注释、所有查询、面板/CLI 状态必须显式处理 2。
2. v7→v9 认领规则：
   - 无 1m 桶：raw 全部为 0。
   - 有 1m 桶，且现存 raw 的 **count 与 sum/avg 精确等于 1m 聚合**：可证明全部是历史贡献，标 1。
   - 有 1m 桶，v7 `downsample_1m_last_raw_rowid` 仍可信且 raw rowid ≤ 水位：可作为“已处理”正证据；其余无法证明的行标 2。
   - 其他（部分 raw 被删、watermark 缺失/落后、行数不足/超出无法解释）：标 2，不猜。
   - `last_ts` 只能从可证明的行回填；quarantine 桶不得用 `bucket_ts+59999` 伪造 last_ts，避免阻止 late last_value 更新。
3. v8→v9 修复：
   - 对已升级到 v8 的 DB，不能把不确定的 `aggregated_1m=1` 当作已证明；只有在“现存 raw 与 1m 聚合完全一致”时保留 1，其余改为 2。
   - 已被 v8 retention 删除的数据无法自动恢复；rc.3 用户必须从 v7 备份恢复（文档明确写出），v9 只防止继续误删。
4. 所有 v8/v9 查询/测试：
   - delta: `WHERE aggregated_1m = 0`；
   - retention/archive: `WHERE aggregated_1m = 1`；
   - status/audit: 单独统计 2；
   - 面板/CLI 显示 quarantine 数量，不能静默。
5. 验收：旧 raw 全保留/部分清理/全部清理后补传/迁移重开/幂等；SQLite 与 PG parity；每条不确定 raw 在人工处理前恰好保留一次，不被 retention 提前删除。

同时 v9 增加：
- `alert_rules.revision INTEGER NOT NULL DEFAULT 0`（#69 CAS）；
- 数据迁移版本号 v9（#51/#69 都需要一次性数据修复）；
- #58 不需要 DDL，但复用 v9 迁移时恢复序列高水位；
- #70 不新增关系表，改为把渠道存在性校验放进规则写事务（避免大规模 schema 变更）。

> 备选：若评审认为 v8→v9 修复无法安全判定，可以把 rc.3 的 v8 DB 定义为“必须恢复 v7 备份”，v9 只支持 v7→v9。此决定需在实现前确认；本方案默认采用上面的保守 quarantine。

### D2. 迁移序列与校验（#58/#59）

- #58：迁移读取源 SQLite `sqlite_sequence`（至少 `alert_events`，建议全部 SERIAL_TABLES），目标序列取
  `max(source MAX(id), source sqlite_sequence, 持久化 notify cursor)`，`is_called=true`，保证新事件 id 严格大于 `notify_started_event_id`；增加 cursor 大于 max 时的防御钳制。
- #59：删除 `SUM(last_ts)::BIGINT` 校验；改为 Rust 侧 i128/分块有序摘要，或按 id 分批流式比较。禁止依赖可能溢出的 SQL 聚合；对 `ledger_version/attempts` 的 SUM 一并审计。
- 测试：事件全清理+旧游标迁移后首条事件可通知；5,152,722 行合法 last_ts 迁移（可 env-gated）；SQLite/PG parity。

### D3. 备份一致性与 PG TLS（#52/#64/#67）

- #52：`snapshot_to` 复制 certs 前获取与 rotate/ACME 相同的 `CertLock`；复制到临时目录后验证 server cert/key（及 CA 对）配套，再提交 manifest；restore 也做配对校验。锁冲突时有界重试或安全失败，不能产生“看似完整”的坏备份。
- #67：从 `HubConfig`/`PostgresStorage::resolve_dsn` 生成统一连接策略；pg_dump/pg_restore/migrate 显式传 `PGSSLMODE`（默认 verify-full，显式 disable 才 disable）和 `PGSSLROOTCERT`（`db_sslrootcert`）；清理父进程冲突环境变量；失败关闭。
- #64：复用 `postgres::Config` 或完全匹配驱动优先级（query password 覆盖 authority；重复 query 最后者；env 再覆盖）；备份/恢复/迁移统一 `PgDsnSecrets`。
- 测试：fake pg_dump/restore 捕获 env+argv；私有 CA 真库 E2E；双密码 DSN 矩阵；证书轮换交错。

### D4. 控制面与 Agent（#57/#63/#65/#66/#75/#76/#78）

- #57：续签等待中同时 select `control_rx` 与 `CertRenewed`，用单一发送者及时写已完成 ControlResponse；测试慢续签+在途完成，Hub 不误报 504。
- #63：校验 `max_batch_samples >= 1`；按上限切分样本，逐子批分配新 seq；保证总数/无重复。若产品不打算支持，应删除/拒绝配置，不能静默忽略。
- #65：`ControlCommand` 在 API 入队时携带绝对 deadline；最后派发前检查 `reply.is_closed()`/deadline；过期请求不发送并只记一次审计。
- #66：hub-self 使用存储中的有效间隔或 watch 更新；或明确拒绝该设置并禁用 UI。测试实际采样周期变化。
- #75：为 hub-self 增加有界持久缓冲/重试；成功入库后再移除，永久 Rejected 不重试；重启可恢复。
- #76：watcher 使用启动配置快照作为基线，或首轮无条件 reload；测试“load 与注册之间 reset”后新密码生效、旧密码失效。
- #78：统一 unit 规范化（无后缀补 `.service`），把 `ssh`/`ssh.socket` 纳入禁止项；配置、Hub、Agent 使用同一规则。

### D5. 告警与发布门禁（#54/#61/#62/#68/#69/#70）

- #54：release workflow 在正式 tag/latest/Release 前，按 `$GITHUB_SHA` 查询 CI 的 `test/postgres/e2e/web/audit` 结果；missing/in-progress/cancelled/failure/API 错误一律 fail closed。不能只看 main 最新提交，也不能只依赖人工 environment approval。
- #61：backup/restore/migrate 的 TOML 解析错误改为固定诊断（路径/类别），丢弃原始 source line；与 installer 的 `load_hub_config_checked` 一致；同时评估 `run` 的同类路径。
- #62：按驱动规则解码 query key 后再识别 password/sslpassword；畸形转义保守遮蔽；fragment 错误路径不得泄露后缀；所有 DB 展示共用脱敏函数。
- #68：alert engine 读取 listener 的 live cert 状态（`Arc<RwLock<CertStatus>>`），不直接读磁盘新证书；热加载失败继续使用旧 live 并继续告警。
- #69：使用 `alert_rules.revision`（v9）在 apply 事务内 CAS；规则删除/禁用/版本变化则跳过旧评估；notify worker 对已禁用规则不再发新事件（保留禁用前事件的产品选择）。
- #70：把渠道存在/启用校验放进 create/update 规则的同一 SQLite IMMEDIATE/PG 配置锁事务；并发删除必须使至少一方失败，不能留下 dangling channel_ids。已有悬挂记录需审计/修复策略。

### D6. 安装器、Docker、Panel（#53/#56/#60/#71/#72/#77/#79）

- #53：检查 `prompt.confirm` 的 bool，false 时在任何锁/写入前返回取消；PTY 测试 n/no/false/y/空/非 TTY。
- #56：Agent entrypoint 增加显式 TLS 模式（fingerprint/system-roots/custom-ca）、按模式要求 fingerprint 或 server CA，透传 `--tls-mode`/`--server-ca`；Compose/README 更新；本地双 CA mock 测纳管后重连。
- #60：按 UTF-8 安全切点 truncate，禁止对固定边界 pop 循环；测试边界内/边界/长 ASCII/中文，输出有界。
- #71：复用外部证书时保留原路径，或 source→destination 事务复制；配置必须指向实际写出的材料；测试外部路径 + 固定文件缺失/过期。
- #72：拆分 stop 与 disable；stop 失败或仍 active 时不得删除 unit/binary/purge；注入失败测试三角色保留文件/状态并非零退出。
- #77：`was_active` 时用 restart 而非 enable_now；验证新 PID/版本/配置生效；失败回滚旧服务。
- #79：提供受控的 Docker 重配置流程（停服→scoped chown→install→恢复 10001），文档 + 真实 volume E2E；不全局放松 prefix 校验。

### D7. SFTP/russh（#96/#97/#98）

- #96：`ChannelRx` 跳过空 Data/匹配的 ExtendedData，继续读取；只有真正 Eof/Close/接收端结束才 EOF；避免空帧忙循环。
- #97：窗口等待同时观察 channel/session close，唤醒并返回 BrokenPipe；`ChannelWriteHalf` 同类路径一并修复；russh-sftp writer 任务可取消/可 join，Hub 增加任务生命周期测试。
- #98：分别协商 c2s/s2c cipher，按方向派生密钥/MAC；保留两方向列表并在无共同算法时明确失败；更新 client/server/rekey 与测试。
- 实施方式：优先升级到已修复的 upstream；若必须 patch vendor，记录 vendor 偏差、更新 checksum/README，并在 CI 增加 `cargo test --manifest-path vendor/russh/Cargo.toml` 或对应 vendor 测试步骤。

### D8. vendored ssh-key P3（#99–#102）

这四条当前没有 RustBoard 业务路径调用：Hub SFTP 只接受 Ed25519 用户私钥，且 host certificate 默认关闭。它们不是 `v1.0.0` 的运行时阻塞项。

决定：
- #99 一行比较修复；
- #100 构造器重新校验空 name；
- #101 改为“先尝试完整 PublicKey，再尝试 options+key”，处理引号/tab；
- #102 去掉固定 32 字节下限，按 mpint 规范接受短标量并做曲线范围校验；
- 增加 vendor 单测/fixture；放到 `v1.0.0-rc.4` 之后、`v1.0.0` 前或独立 patch release，取决于评审时间；不能为了这些库级 P3 阻塞产品 P1/P2。
- 若上游已有修复，优先升级依赖而不是长期维护 fork。

### D9. 测试门禁修复（#74/#81–#90）

这些不是产品代码，但会伪造发布证据，必须在重新跑发布门禁前修：

- #74：按 stale id/完整范围断言自动 prune，禁用 DELETE 时测试必须失败。
- #81：统一 KiB/字节；采样失败返回错误，不能默认 0；展示单位正确；边界数值测试。
- #82：要求 20 条规则 enabled、health 全 200、实际评估/预算证据、fixture 时间/序列数正确；三类反例必须失败。
- #83：Problem 立即失败；必须实际坚持到 hold deadline。
- #84：记录最大 audit id，只接受本次新增记录，不能复用旧 admin 记录。
- #85：DOS-04b 同时要求 health 200 和 agent online；反例必须失败。
- #86：比较远端 size 与 DB bytes，并要求对象集合精确。
- #87：按 s4-agent id 断言 samples/ingest_batches/agents，禁止 Hub 自采样代偿。
- #88：保留 host_ip，要求 8080 显式回环；0.0.0.0/缺省负例失败。
- #89：EXIT 清理 + INT/TERM 显式 130/143；FAILS>0 非零；完整完成标记。
- #90：逐项处理可得来源，已可确定的不一致必须失败；ALLOW_UNVERIFIED 只跳过真正缺源项。

### D10. 文档/诊断（#73/#80/#91–#95）

- #73：腾讯云元数据改固定 IP/受控域名，测试所有生产端点常量，不放开任意 DNS。
- #80：Docker 构建命令补 `-f docker/Dockerfile`。
- #91：pg_restore 用 root 打开 stdin 后以 postgres 身份读取，不放宽 0700/0600。
- #92：README 从 Cargo 版本派生包名，更新 rc.2 叙述。
- #93：ACME 示例补 `--admin-listen` 或展示 loopback HTTP + 反代，并保留 fail-closed 安全说明。
- #94：用服务进程/PID1 的 UID 验证，不用 `compose exec id` 证明主进程。
- #95：统一为 `min(lifetime/3, 48h)`，给 90 天/6 天示例。

## 3. 执行阶段

### P0：设计与 schema v9（阻塞所有数据相关修复）

1. 评审 D1 的 quarantine 语义、v8→v9 修复边界、rc.3 用户恢复策略。
2. 定义 v9 DDL/data migration：`alert_rules.revision`、raw 三态、序列高水位、迁移校验摘要。
3. 写失败测试：`v8_schema_claim` 修订、v8→v9 歧义、SQLite/PG parity、序列/游标。
4. 通过后冻结 schema，其他阶段不得再改。

### P1：数据、迁移、备份（#51/#52/#58/#59/#64/#67）

- 先 #51/#58/#59（同一迁移链），再 #52/#64/#67（备份工具）。
- 产物：v9 迁移、quarantine 查询、迁移序列/摘要、备份锁/TLS/密码解析。
- 门禁：全 workspace + 真实 PG；v7→v9、v8→v9、v9 重开；verification/backup interleaving；PG TLS fake/real。

### P2：Agent/控制面（#57/#63/#65/#66/#75/#76/#78）

- 可并行四组：#57/#65；#63；#66/#75；#76；#78。
- 门禁：agent 170+；慢续签/队列/超时；批次上限；hub-self 失败恢复；密码 watcher；unit 规范化。

### P3：告警与发布门禁（#54/#61/#62/#68/#69/#70）

- 依赖 P0 的 revision；#69/#70 同一告警写路径。
- #54 是发布前硬门禁，必须在其他修复完成后、tag 前生效。
- 门禁：alert engine barrier/并发、channel dangling、日志脱敏、workflow fixture（失败/取消/缺失/错 SHA）。

### P4：安装器/Docker/Panel（#53/#56/#60/#71/#72/#77/#79）

- 可与 P2/P3 并行；#79 需 Docker 真卷 E2E。
- 门禁：PTY 取消失败、中文截断、外部证书复用、stop 失败注入、active agent restart、容器重配置。

### P5：SFTP/russh（#96/#97/#98）

- 优先 upstream；否则 vendor patch + vendor 测试。
- 门禁：空 Data、零窗口断连、非对称 cipher；真实 SFTP 29/29 复跑 + leak/task 测试。

### P6：测试门禁（#74/#81–#90）

- 必须在重新跑 3h/24h 与发布门禁前完成，否则证据不可信。
- 门禁：每个门禁做 mutation/负例，确认原实现会 PASS、修复后 FAIL。

### P7：文档/诊断（#73/#80/#91–#95）

- 发布前完成；Docker/ACME/PG 文档命令实测。

### P8：vendored ssh-key P3（#99–#102）

- 不阻塞 v1.0.0；在 rc.4 后独立提交，或与 upstream 升级一起做。
- 需要用户确认是否必须在本轮关闭；默认保持 OPEN 直到修复。

## 4. 兼容性、回滚与发布

### 4.1 schema v9

- v9 一次性迁移，**不可降级**；升级前必须备份 v7/v8。
- v7→v9：按 D1 保守认领/quarantine；未知 raw 不删除。
- v8→v9：已误删的数据无法恢复；rc.3 用户必须恢复 v7 备份；v9 仅阻止继续删除。
- SQLite/PG 必须同语义；quarantine 状态在 API/DB 中可见。
- 发布说明必须写明“rc.3 v8 不能直接升级到 rc.4；先备份/恢复”；这是重大兼容性变更，需要用户确认。

### 4.2 版本与 tag

- `v1.0.0-rc.2`、`v1.0.0-rc.3` 不移动；新修复用 `v1.0.0-rc.4`。
- 只有全部 P1/P2、P6 门禁、SFTP（若启用）和 P7 完成后，才考虑 `v1.0.0`。
- `v1.0.0` 的版本号变更会改变二进制 hash；必须重新构建并在最终二进制上跑 3h+24h，或明确接受“仅版本字符串变化”的窄例外并由用户确认。

### 4.3 24h/发布门禁

当前 rc.3 24h 已中止，证据无效。rc.4 必须重新：
1. 全 workspace + 真实 PG、fmt/clippy/audit、web、CI；
2. install/offline/Docker PG/security/panel/arm64；
3. TLS PG、100/500/1000 agent；
4. 3h 预检（2h warmup）通过后，24h 200-agent；
5. #54 release gate 生效、最终评审/渗透；
6. tag/release/镜像；issue 评论但不关闭。

## 5. 测试矩阵（新增）

| 区域 | 必测 |
|---|---|
| v9 迁移 | v7 全 raw/部分/全删+late、v8→v9 歧义、重开幂等、SQLite/PG parity、quarantine 不被删除 |
| 序列/游标 | 100 事件+cursor 100+清空→迁移→新事件 id>100 且通知 |
| 摘要 | sum>i64::MAX 的合法 last_ts，迁移成功 |
| 备份 | cert rotation interleaving；PG TLS env/私有 CA；双密码 DSN |
| Agent | 慢续签中 control response；队列 504 取消；max_batch；self interval/retry；password watcher；ssh 短名 |
| 告警 | disable/delete 与旧评估并发；channel 删除交错；live cert vs disk |
| 安装器 | confirm n；UTF8 截断；外部 cert；stop 失败；agent restart；Docker volume |
| SFTP | 空 Data；零窗口 close；非对称 cipher；writer 任务不泄漏 |
| 测试门禁 | 每个假阳性注入一个 mutation，修复后必须失败 |
| 发布 | SHA 级 CI gate；tag/Release 不得在安全 E2E 红时执行 |

## 6. 风险与需要用户确认

1. **#51 的 rc.3 v8 数据**：保守 v9 只能防止继续丢失；已被删除的 late raw 无法恢复。是否接受“rc.3 用户恢复 v7 备份”，还是投入更大 v8→v9 自动修复？
2. **#51 方案选择**：三态 quarantine 会影响 retention/archive/面板语义；是否同意把不确定 raw 长期保留并显式报告，而不是猜测归属？
3. **#54 发布门禁**：是否允许 release workflow 查询 GitHub API/check-runs；如不允许，需改成可复用的 security E2E job。
4. **#99–#102**：是否要求在本轮 v1.0.0 前修完 vendored 库 P3，还是作为 post-1.0.0 patch（当前无产品路径）？
5. **#70 已有悬挂 channel_ids**：实现严格事务校验后，旧数据可能无法直接更新；需要决定“自动清理/拒绝/容忍并报告”。
6. **时间**：51 条中 30+ 条产品/门禁修复，仍需完整 3h+24h；不要复用 rc.3 证据，也不要移动 rc.2/rc.3。

## 7. 验收完成定义

- 51 条 OPEN issue 均有明确结论与修复/文档测试；P8 若延后需用户书面确认。
- 所有 P1/P2 产品修复合入；P6 门禁负例可证；P7 文档命令可执行。
- CI 全绿；全量 workspace+PG、install/offline/Docker/security/panel/arm64 通过。
- rc.4 最终二进制 3h 预检 + 24h 长稳通过；100/500/1000 agent 通过。
- #54 release gate 对失败/缺失/运行中 CI fail closed。
- 独立评审 + 全量渗透无未修复高危/中危。
- issue 只补证据评论，关闭由用户确认；不移动 rc.2/rc.3。
