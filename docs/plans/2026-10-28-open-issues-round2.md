# 2026-10-28 开放 issue 第二轮核实与修复方案

> **执行状态（2026-10-28）**：P0–P8 已完成，另补修 #33/#39/#58/#59；
> 代码提交与门禁证据见 [执行记录](2026-10-28-open-issues-round2-execution.md)。
> 仅 #51（v7→v8 旧迁移，v1.0.0 fresh install 不可达）保持延后；当前等待
> 200 agent / 24h 与其余发布门禁，`v1.0.0` 未 tag、未发布。

## 0. 状态、范围与用户决策

- 核实基线：`c5316b4`（产品代码与 `745d2f9` 相同；两者之间只有 docs/plans 和 v041 测试断言变更）。
- 上一轮 #43–#50、#55 已按用户确认关闭；本方案不重开、不移动 `v1.0.0-rc.2`，也不移动已推送的 `v1.0.0-rc.3`。
- 新一批 **#51–#102 中 51 条仍 OPEN**（#55 已关闭）。本轮只核实和写方案，**未修改产品代码**。
- 核实方式：6 个独立只读子代理 + 主 Agent 抽查；静态证明为主，#51/#59 有仓库外最小复现，#81/#88/#89 有独立数值/Bash 复现。
- 结论：**51 条 OPEN issue 全部 CONFIRMED，没有 REFUTED**。其中 #74、#81–#90 是测试门禁缺陷，#73、#80、#91–#95 是文档/诊断，#99–#102 是 vendored 库 P3；其余是产品行为缺陷。
- 用户已确认：
  1. **当前无任何旧数据**，`v1.0.0` 只支持全新安装；旧数据兼容放到第一版发布之后。
  2. #54 发布门禁 **两者都做**：查目标 SHA 的 CI 结果 + 发布流程内重跑关键安全 E2E。
  3. #99–#102 **必须在 `v1.0.0` 前修完**。
  4. #70 当前无旧数据，采用**最佳方案**，不迁就旧悬挂记录。
- 当前 release：`v1.0.0-rc.3` 已 tag；rc.3 的 24h soak 在约 12.5h 时因本轮要改代码主动中止，证据目录
  `target/load/20261027T025506Z-200a-aborted/`，**不是有效 24h 证据**；`v1.0.0` 未发布。
- 新修复进入 `v1.0.0-rc.4`；全部门禁通过后才发布 `v1.0.0`。

## 1. 核实总表

| Issue | 级别 | 结论 | 主题 | 集群 | 阶段 | 发布阻塞 |
|---|---|---|---|---|---|---|
| #51 | P1 | CONFIRMED | [升级数据丢失] v7→v8 按聚合 count 认领现存 raw，会误删尚未聚合的迟到数据 | 数据/备份 | P9 | 否（P9 post-1.0，当前无旧数据） |
| #52 | P2 | CONFIRMED | [备份] 在线快照未与证书轮换互斥，可能备份不配套的证书和私钥 | 数据/备份 | P1 | 是 |
| #53 | P2 | CONFIRMED | [安装器] Hub 安装确认回答 n 后仍继续写入系统 | 安装器/Docker/面板 | P4 | 是 |
| #54 | P2 | CONFIRMED | [发布] Release 未检查目标提交的安全 E2E，CI 红灯仍可进入正式发布 | 告警/日志/发布 | P3 | 是 |
| #56 | P2 | CONFIRMED | [Docker] Agent 入口固定 fingerprint 模式，无法完成 ACME Hub 的纳管后连接 | 安装器/Docker/面板 | P4 | 是 |
| #57 | P2 | CONFIRMED | [控制面] 周期续签期间已执行命令的应答滞留，导致 Hub 误报超时 | Agent/控制面 | P2 | 是 |
| #58 | P1 | CONFIRMED | [迁移] 事件清理后迁移会重置自增编号，旧通知游标持续跳过新告警 | 数据/备份 | P9 | 否（P9 post-1.0，当前无旧数据） |
| #59 | P2 | CONFIRMED | [迁移] 聚合时间戳用 i64 求和，约 515 万条分钟聚合即可使合法库迁移失败 | 数据/备份 | P9 | 否（P9 post-1.0，当前无旧数据） |
| #60 | P2 | CONFIRMED | [安装器] ACME 长输出截断检查固定 UTF-8 边界，中文输出可让安装进程永久循环 | 安装器/Docker/面板 | P4 | 是 |
| #61 | P2 | CONFIRMED | [日志] backup/restore/migrate 的 TOML 解析错误会回显含 token 的配置原文 | 告警/日志/发布 | P3 | 是 |
| #62 | P2 | CONFIRMED | [日志] PostgreSQL 密码参数名百分号编码后绕过 DSN 脱敏 | 告警/日志/发布 | P3 | 是 |
| #63 | P2 | CONFIRMED | [Agent] max_batch_samples 配置从未读取，采集批次不遵守上限 | Agent/控制面 | P2 | 是 |
| #64 | P2 | CONFIRMED | [备份] DSN 同时含两处 password 时，备份选用的密码与 Hub 驱动不同 | 数据/备份 | P1 | 是 |
| #65 | P2 | CONFIRMED | [控制面] 排队期间已返回 504 的未派发请求，稍后仍会执行 | Agent/控制面 | P2 | 是 |
| #66 | P2 | CONFIRMED | [采样] hub-self 的间隔设置保存成功，但本机采集始终使用启动配置 | Agent/控制面 | P2 | 是 |
| #67 | P1 | CONFIRMED | [备份] pg_dump/pg_restore 未继承 Hub TLS 策略，缺省可退回不校验证书的 prefer 模式 | 数据/备份 | P1 | 是 |
| #68 | P2 | CONFIRMED | [告警] 证书热加载失败时，到期告警读取磁盘新证书而忽略仍在服务的旧证书 | 告警/日志/发布 | P3 | 是 |
| #69 | P2 | CONFIRMED | [告警] 停用规则并清空状态后，旧评估仍可重建状态并产生通知 | 告警/日志/发布 | P3 | 是 |
| #70 | P2 | CONFIRMED | [告警] 渠道存在性校验与规则写入分离，并发删除可留下悬空 channel_ids | 告警/日志/发布 | P3 | 是 |
| #71 | P2 | CONFIRMED | [安装] Panel --force 复用外部 TLS 证书时改写为固定路径却不复制文件 | 安装器/Docker/面板 | P4 | 是 |
| #72 | P2 | CONFIRMED | [卸载] 三个角色忽略停服失败，仍删除 unit、二进制并可清空运行中的数据 | 安装器/Docker/面板 | P4 | 是 |
| #73 | P3 | CONFIRMED | [安装诊断] 腾讯云固定元数据域名被仅支持字面 IP 的探测器直接拒绝 | 文档/诊断 | P7 | 发布前文档 |
| #74 | P3 | CONFIRMED | [测试] 自动审计清理用例只查询最新10条，旧记录未删除也会通过 | 测试门禁 | P6 | 门禁修复 |
| #75 | P2 | CONFIRMED | [采集] Hub 本机采样入库失败后直接丢弃，缺少约定的缓冲与重试 | Agent/控制面 | P2 | 是 |
| #76 | P2 | CONFIRMED | [认证] 启动读取配置与 watcher 注册之间的密码重置会被吞掉，旧密码持续有效 | Agent/控制面 | P2 | 是 |
| #77 | P2 | CONFIRMED | [升级] Agent install --force 仅 enable --now，已运行服务不会切换到新二进制和配置 | 安装器/Docker/面板 | P4 | 是 |
| #78 | P2 | CONFIRMED | [控制面] 禁止列表漏掉 ssh 短名，规范化前检查与 systemctl 解析不一致 | Agent/控制面 | P2 | 是 |
| #79 | P2 | CONFIRMED | [Docker] 已初始化 volume 属主为10001，文档的 root install --force 重配置流程必被 prefix 校验拒绝 | 安装器/Docker/面板 | P4 | 是 |
| #80 | P3 | CONFIRMED | [文档] Docker README 的镜像构建命令漏掉 -f docker/Dockerfile，按步骤执行会找不到 Dockerfile | 文档/诊断 | P7 | 发布前文档 |
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
| #99 | P3 | CONFIRMED | [依赖] vendored ssh-key：RSA 私钥相等比较遗漏另一侧 iqmp | vendored ssh-key | P8 | 是（用户要求） |
| #100 | P3 | CONFIRMED | [依赖] vendored ssh-key：证书算法解析器可返回违反不变量的 AlgorithmName | vendored ssh-key | P8 | 是（用户要求） |
| #101 | P3 | CONFIRMED | [依赖] vendored ssh-key：带选项且无注释的 authorized_keys 合法行解析失败 | vendored ssh-key | P8 | 是（用户要求） |
| #102 | P3 | CONFIRMED | [依赖] vendored ssh-key：拒绝规范编码不足 32 字节的合法 ECDSA 私钥标量 | vendored ssh-key | P8 | 是（用户要求） |

> 说明：所有根因均存在；级别按 issue 标注。`P9` 的 #51/#58/#59 是旧数据兼容问题，按用户“当前无旧数据、先发第一版”的决定不作为 `v1.0.0` 阻塞项，但仍保持 OPEN，发布后立即处理。`P8` 的 #99–#102 已按用户要求改为发布前必修。

## 2. 关键设计与决策

### D1. schema v9：全新安装 + 告警一致性

`v1.0.0` **只支持全新数据库**，不执行 v7→v8/v9 的旧数据回填；若检测到 schema <9，启动/迁移必须 fail closed，并提示“v1.0.0 不支持旧数据升级；旧数据兼容将在首个正式版本之后提供”。这样不会把 #51/#58/#59 的已知迁移缺陷带入新安装。

v9 只为当前产品需要的一次性结构变更：

1. `alert_rules.revision INTEGER NOT NULL DEFAULT 0`，每次规则更新递增；#69 在 apply 事务内做 CAS。
2. 新增 `alert_rule_channels(rule_id, channel_id, PRIMARY KEY(rule_id, channel_id), FOREIGN KEY(rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE, FOREIGN KEY(channel_id) REFERENCES notification_channels(id) ON DELETE RESTRICT)`；#70 用关系表取代 JSON 字符串中的隐式引用。
3. JSON `channel_ids` 在 API 层可继续作为输入/输出兼容字段，但存储层以关系表为准；新写入在同一事务中写两张表，删除渠道由 FK RESTRICT 保底。
4. 全新安装建 v9；无旧数据迁移。v9 之后不得再降级到 v8。

> #51/#58/#59 的具体迁移修复（quarantine、SQLite `sqlite_sequence`、溢出摘要）放到 P9；在 P9 之前，任何 v7/v8 数据库都不能升级到 v1.0.0。这个限制必须写进 release notes 和 issue 评论。

### D2. 备份与 PG 连接（#52/#64/#67）

- #52：`snapshot_to` 复制 certs 前获取与 rotate/ACME 相同的 `CertLock`；复制到临时目录后验证 server cert/key（及 CA 对）配套，再提交 manifest；restore 也校验。锁冲突有界重试或安全失败。
- #67：从 `HubConfig`/`PostgresStorage::resolve_dsn` 生成统一策略；pg_dump/pg_restore/migrate 显式传 `PGSSLMODE`（默认 verify-full，只有显式 disable 才 disable）和 `PGSSLROOTCERT`（`db_sslrootcert`）；清理冲突环境变量；失败关闭。
- #64：复用 `postgres::Config` 或完全匹配驱动优先级（query password 覆盖 authority，重复 query 最后者，env 再覆盖）；备份/恢复/迁移统一 `PgDsnSecrets`。
- 测试：fake pg_dump/restore 捕获 env+argv；私有 CA 真库 E2E；双密码 DSN；证书轮换交错。

### D3. 控制面与 Agent（#57/#63/#65/#66/#75/#76/#78）

- #57：续签等待中同时 select `control_rx` 与 `CertRenewed`，单一发送者及时写已完成 ControlResponse；慢续签下 Hub 不误报 504。
- #63：校验 `max_batch_samples >= 1`；按上限拆批，每子批新 seq；总数无丢失/重复。若不支持则拒绝配置，不能静默忽略。
- #65：API 入队时携带绝对 deadline；派发前检查 `reply.is_closed()`/deadline；过期不发送，只记一次审计。
- #66：hub-self 使用存储中的有效间隔或 watch 更新；或明确拒绝设置并禁用 UI；测试实际周期变化。
- #75：hub-self 有界持久缓冲/重试；成功入库后移除，永久 Rejected 不重试；重启可恢复。
- #76：watcher 使用启动配置快照作为基线，或首轮无条件 reload；测试 load 与注册之间的 reset。
- #78：统一 unit 规范化（无后缀补 `.service`），把 `ssh`/`ssh.socket` 纳入禁止项；配置、Hub、Agent 同规则。

### D4. 告警、日志与发布门禁（#54/#61/#62/#68/#69/#70）

- #68：alert engine 读取 live cert 状态（`Arc<RwLock<CertStatus>>`），不直接读磁盘新证书；热加载失败继续旧 live 并继续告警。
- #69：`alert_rules.revision` 在 apply 事务内 CAS；规则删除/禁用/版本变化跳过旧评估；worker 对已禁用规则不发新事件（禁用前事件的产品选择保留）。
- #70：关系表 + FK；create/update 事务写规则和关联；并发删除至少一方失败，不能留下 dangling。当前无旧数据，v9 直接建新表；未来 P9 才需要从 JSON 迁移。
- #61：backup/restore/migrate 的 TOML 解析错误改为固定诊断，丢弃 source line；与 installer 一致；同时评估 `run` 同类路径。
- #62：按驱动规则解码 query key 后再识别 password/sslpassword；畸形转义保守遮蔽；fragment 错误路径不泄露后缀。
- #54：**两层门禁**：
  1. release 开始前按 `$GITHUB_SHA` 查询 CI 的 test/postgres/e2e/web/audit；缺失、运行中、取消、失败、API 错误全部 fail closed；
  2. release 内重跑关键 security E2E（可复用 workflow_call 或直接运行脚本）；重跑失败也 fail closed。
  只允许人工 approval 作为附加，不得替代自动门禁。

### D5. 安装器、Docker、Panel（#53/#56/#60/#71/#72/#77/#79）

- #53：检查 `prompt.confirm` 返回 bool；false 在任何写入前取消；PTY 覆盖 n/no/false/y/空/非 TTY。
- #56：Agent entrypoint 增加显式 TLS 模式（fingerprint/system-roots/custom-ca），按模式要求 fingerprint 或 server CA，透传 `--tls-mode`/`--server-ca`；Compose/README 更新；本地双 CA mock 测纳管后重连。
- #60：UTF-8 安全切点 truncate，禁止固定边界 pop 循环；测试边界内/边界/长 ASCII/中文，输出有界。
- #71：复用外部证书时保留原路径，或 source→destination 事务复制；配置必须指向实际写出的材料。
- #72：拆分 stop 与 disable；stop 失败或仍 active 时不得删除 unit/binary/purge；三角色失败注入。
- #77：`was_active` 时 restart 而非 enable_now；验证新 PID/版本/配置；失败回滚旧服务。
- #79：受控 Docker 重配置流程（停服→scoped chown→install→恢复 10001），文档 + 真实 volume E2E。

### D6. SFTP/russh（#96/#97/#98）

- #96：`ChannelRx` 跳过空 Data/匹配 ExtendedData，继续读取；只有真正 Eof/Close/接收端结束才 EOF；避免忙循环。
- #97：窗口等待同时观察 channel/session close，唤醒返回 BrokenPipe；`ChannelWriteHalf` 同类路径一并修复；writer 任务可取消/可 join。
- #98：分别协商 c2s/s2c cipher，按方向派生密钥/MAC；无共同算法明确失败；更新 client/server/rekey 和测试。
- 优先 upstream；必须 patch vendor 时记录偏差、更新 checksum，并在 CI 增加 vendor 测试步骤。

### D7. vendored ssh-key（#99–#102，发布前必修）

用户要求 `v1.0.0` 前修完；这些都是库级 P3，但必须带测试：

- #99：`self.iqmp.ct_eq(&other.iqmp)`。
- #100：构造器对空 name 重新校验，成功后 `certificate_type` 不 panic。
- #101：先尝试完整 PublicKey，再尝试 options+key；处理引号/tab/空 comment。
- #102：移除固定 32 字节下限，按 mpint 规范接受短标量，补曲线范围校验。
- 增加 vendor 单测/fixture，并在 CI 执行 vendor crate 测试；若上游已有修复，优先升级依赖。

### D8. 测试门禁（#74/#81–#90）

这些会伪造发布证据，必须在重跑 3h/24h 和发布前一并修复：

- #81：统一 KiB/字节，采样失败不得默认为 0；边界数值测试。
- #82：强制 20 条规则 enabled、health 全 200、至少一次真实评估/预算证据；fixture 时间和序列数正确。
- #87：按 s4-agent id 断言 samples/ingest_batches/agents，禁止 hub-self 代偿。
- #88：保留 host_ip，要求 8080 显式回环；0.0.0.0/缺省负例失败。
- #89：EXIT 清理 + INT/TERM 130/143；FAILS>0 非零；完成标记。
- #90：逐项处理可得来源，已可确定的不一致必须失败。
- #74/#83/#84/#85/#86：按方案修正断言，增加 mutation/负例。

### D9. 文档/诊断（#73/#80/#91–#95）

- #73 固定腾讯云元数据地址并测生产常量；#80 补 `-f docker/Dockerfile`；#91 用 root 打开 stdin 后以 postgres 读；#92 从 Cargo 版本派生包；#93 补 `--admin-listen` 或反代方案；#94 用服务进程 UID；#95 统一续期公式 `min(lifetime/3, 48h)`。

### D10. P9：旧数据兼容（#51/#58/#59）

按用户决定，`v1.0.0` 之后立即做，不作为首版阻塞项：

- #51：v7/v8 数据保守认领/quarantine；无法证明的 raw 不删；rc.3 已删数据只能从 v7 备份恢复。
- #58：迁移恢复 `sqlite_sequence` 高水位，保证新事件 id > 旧 notify cursor。
- #59：用 i128/流式摘要替代 `SUM(last_ts)`，覆盖总和超 i64 的合法库。
- 在 P9 完成前，v1.0.0 遇到 schema <9 必须明确拒绝，不得运行旧回填。

## 3. 执行阶段

### P0：schema v9 与旧库拒绝

- 新增 `alert_rules.revision`、`alert_rule_channels` 关系表/FK；全新安装建 v9。
- `SCHEMA_VERSION=9`；检测旧 schema 时 fail closed，提示“首版不支持旧数据升级”。
- 写失败测试：v9 建库、revision、FK、旧库拒绝。
- 完成后再改告警存储。

### P1：备份与 PG 连接（#52/#64/#67）

- 证书锁/配对校验；PG TLS env/root CA；DSN 密码优先级。
- 门禁：fake pg_dump/restore env+argv、私有 CA 真库、双密码 DSN、轮换交错。

### P2：Agent/控制面（#57/#63/#65/#66/#75/#76/#78）

- 慢续签控制应答、队列 deadline、批次上限、self 间隔/重试、密码 watcher、unit 规范化。

### P3：告警/日志/发布（#54/#61/#62/#68/#69/#70）

- #69/#70 依赖 P0；#54 两层门禁；#61/#62 脱敏。
- 门禁：并发/禁用/渠道删除、live cert、workflow 反例。

### P4：安装器/Docker/Panel（#53/#56/#60/#71/#72/#77/#79）

- 可与 P2/P3 并行；#79 需 Docker 真卷 E2E。

### P5：SFTP/russh（#96/#97/#98）

- vendor 或 upstream；空 Data/零窗口/非对称 cipher；SFTP 29/29 复跑 + 任务泄漏测试。

### P6：测试门禁（#74/#81–#90）

- 必须在重跑 3h/24h 前完成；每个假阳性做 mutation 反例。

### P7：文档/诊断（#73/#80/#91–#95）

- 发布前完成；命令实测。

### P8：vendored ssh-key（#99–#102）

- 发布前必修；vendor 单测/fixture + CI。
- 若上游修复，优先升级而非长期 fork。

### P9：旧数据兼容（#51/#58/#59）

- `v1.0.0` 之后立即做；不阻塞首版。
- 完成后才允许 v1.0.0 接受 v7/v8 数据；在此之前发布说明必须写明“fresh install only”。

## 4. 兼容性、回滚与发布

### 4.1 兼容性

- `v1.0.0` **只支持全新安装**；schema <9 必须拒绝启动迁移，不能运行当前 v8 回填。
- rc.3 v8 数据不自动升级；如曾写入旧数据，先保留/恢复 v7 备份，等 P9 兼容。
- schema v9 一旦写入不可降级；回滚需恢复备份。
- SQLite/PG 同 schema 语义；#70 关系表在两端一致。
- `v1.0.0-rc.2`、`v1.0.0-rc.3` 不移动；新 tag 为 `v1.0.0-rc.4`。

### 4.2 版本与 tag

- rc.4 完成 P0–P8 和门禁后打 tag；最终 `v1.0.0` 只在 24h/全量门禁通过后。
- 版本号从 rc.3→v1.0.0 会改变二进制 hash；最终 24h 必须在 `v1.0.0` 最终二进制上跑，或由用户明确接受“仅版本字符串变化”例外；默认不例外。

### 4.3 发布门禁

1. 全 workspace + 真实 PG、fmt/clippy/audit、web、CI 全绿；
2. install/offline/Docker PG/security/panel/arm64；
3. TLS PG、100/500/1000 agent；
4. 3h 预检（2h warmup）+ 24h 200 agent；
5. #54 两层门禁生效；
6. 独立评审 + 全量渗透；无未修复高危/中危；
7. 更新 CHANGELOG/版本、tag/release/镜像；
8. issue 只补评论，关闭由用户确认。

## 5. 测试矩阵（新增）

| 区域 | 必测 |
|---|---|
| schema v9 | 建库、revision、alert_rule_channels FK、旧 schema 拒绝 |
| 备份 | cert rotation interleaving；PG TLS env/私有 CA；双密码 DSN |
| Agent | 慢续签 control response；队列 504 取消；max_batch；self interval/retry；password watcher；ssh 短名 |
| 告警 | disable/delete 与旧评估并发；channel 删除交错；live cert vs disk |
| 安装器 | confirm n；UTF8 截断；外部 cert；stop 失败；agent restart；Docker volume |
| SFTP | 空 Data；零窗口 close；非对称 cipher；writer 任务不泄漏 |
| 测试门禁 | 每个假阳性注入 mutation，修复后必须失败 |
| 发布 | SHA CI 查询 + release 内重跑 security E2E；红/缺失/运行中不得发布 |
| P9（post-1.0） | v7/v8 迁移、序列高水位、溢出摘要、quarantine |

## 6. 风险与待确认

1. **首版不支持旧数据**：这是用户明确决定；release notes、CLI 错误和 issue 评论必须一致写明。若发布前发现任何需要保留的旧数据，立即停止，先做 P9。
2. **#54 两层门禁**：查询 GitHub API 需要合适权限；release 内重跑安全 E2E 会增加时长。两者都失败关闭。
3. **#99–#102**：用户已要求发布前修完；必须验证 vendor 偏差/checksum 和 CI 测试入口。
4. **#70 关系表**：当前无旧数据，v9 直接建新表；未来 P9 才需要 JSON→关系表迁移。
5. **#51/#58/#59 仍 OPEN**：首版不修，但发布后立即 P9；不得关闭，直到修复并经用户确认。
6. **24h 证据**：rc.3 的 24h 已中止且无效；rc.4 必须从最终二进制重跑，不能拼接。

## 7. 验收完成定义（首版）

- P0–P8 完成；48 条非 P9 issue 有代码/测试/文档结论（#51/#58/#59 除外，明确 deferred）。
- v1.0.0 fresh install 可创建 v9；旧 schema 明确拒绝，不静默迁移。
- 全 workspace+PG、install/offline/Docker/security/panel/arm64、TLS PG、100/500/1000 通过。
- rc.4 最终二进制 3h+24h 通过；#54 两层门禁可证明红 CI 无法发布。
- 独立评审/渗透无未修复高危/中危；issue 评论不关闭，等待用户确认。
- `v1.0.0-rc.2`/`v1.0.0-rc.3` 未移动；`v1.0.0` 只在全部通过后发布。
