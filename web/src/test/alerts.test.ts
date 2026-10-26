import { describe, expect, it } from "vitest";
import {
  ALERT_COMPARATOR_OPTIONS,
  ALERT_SOURCE_OPTIONS,
  MAX_RULE_DURATION_SECS,
  MAX_RULE_LABELS,
  MAX_SILENCE_SECS,
  alertSourceLabel,
  buildChannelInput,
  buildFilterLabels,
  buildRuleCreatePayload,
  buildRuleUpdatePayload,
  buildSilenceInput,
  channelFields,
  channelFormFromView,
  channelSecretSummary,
  describeAlertError,
  emptyChannelForm,
  emptyRuleForm,
  emptySilenceForm,
  eventStateClass,
  formatAlertValue,
  formatDurationSecs,
  formatEventAgent,
  formatEventRule,
  formatEventState,
  formatNotifyStatus,
  formatRuleFilter,
  formatRuleTarget,
  formatRuleThreshold,
  formatSilenceScope,
  formatSilenceUntil,
  hasRuleChanges,
  isSecretConfigured,
  ruleFormFromRule,
  validateChannelForm,
  validateRuleForm,
  validateSilenceForm,
  type RuleFormState,
} from "../alerts";
import { ApiError } from "../api";
import type { AlertEvent, AlertRule, AlertSilence, ChannelView } from "../types";

function alertRule(partial: Partial<AlertRule> = {}): AlertRule {
  return {
    id: "0b6c7d8e-1234-4abc-9def-0123456789ab",
    name: "磁盘使用率过高",
    enabled: true,
    source: "metric",
    metric: "disk.used_percent",
    comparator: "gt",
    threshold: 90,
    duration_secs: 300,
    cooldown_secs: 1800,
    filter_agent_id: "hub-self",
    filter_labels: { mount: "/data", env: "prod" },
    channel_ids: ["ch-1", "ch-2"],
    notify_on_resolve: true,
    is_builtin: false,
    updated_by: "admin",
    created_at: 1_700_000_000_000,
    updated_at: 1_700_000_000_000,
    ...partial,
  };
}

function ruleForm(partial: Partial<RuleFormState> = {}): RuleFormState {
  return {
    ...emptyRuleForm(),
    name: "磁盘使用率过高",
    metric: "disk.used_percent",
    threshold: "90",
    ...partial,
  };
}

function alertEvent(partial: Partial<AlertEvent> = {}): AlertEvent {
  return {
    id: 1,
    ts: 1_700_000_000_000,
    rule_id: "rule-1",
    rule_name: "磁盘使用率过高",
    agent_id: "hub-self",
    state: "firing",
    value: 93.5,
    message: "磁盘使用率 93.5% 超过阈值",
    notified: true,
    notify_error: "",
    silenced: false,
    ...partial,
  };
}

function channelView(partial: Partial<ChannelView> = {}): ChannelView {
  return {
    id: "ch-1",
    name: "运维群",
    kind: "telegram",
    enabled: true,
    chat_id: "123456",
    secret_fields: ["bot_token"],
    updated_by: "admin",
    created_at: 1_700_000_000_000,
    updated_at: 1_700_000_000_000,
    ...partial,
  };
}

describe("规则表单校验", () => {
  it("接受合法的指标规则与内置来源规则", () => {
    expect(validateRuleForm(ruleForm())).toBeNull();
    for (const source of ["agent_offline", "hub_cert"] as const) {
      expect(
        validateRuleForm(ruleForm({ source, metric: "", threshold: "90" })),
      ).toBeNull();
    }
    expect(
      validateRuleForm(
        ruleForm({
          durationSecs: String(MAX_RULE_DURATION_SECS),
          cooldownSecs: "0",
        }),
      ),
    ).toBeNull();
  });

  it("拒绝空名称、超长名称与非法 metric", () => {
    expect(validateRuleForm(ruleForm({ name: "  " }))).toContain("名称");
    expect(validateRuleForm(ruleForm({ name: "规".repeat(30) }))).toContain("64 字节");
    expect(validateRuleForm(ruleForm({ metric: "" }))).toContain("metric");
    expect(validateRuleForm(ruleForm({ metric: "Disk.Used" }))).toContain("metric");
    expect(validateRuleForm(ruleForm({ metric: "a".repeat(65) }))).toContain("metric");
    // 非 metric 来源不要求 metric，即使残留内容也不阻塞表单。
    expect(
      validateRuleForm(ruleForm({ source: "agent_offline", metric: "ignored" })),
    ).toBeNull();
  });

  it("拒绝非法阈值、持续时间与冷却时间", () => {
    for (const threshold of ["", "  ", "abc", "NaN", "Infinity"]) {
      expect(validateRuleForm(ruleForm({ threshold })), threshold).toContain("阈值");
    }
    expect(validateRuleForm(ruleForm({ threshold: "-1" }))).toBeNull();
    for (const durationSecs of ["-1", "1.5", "abc", String(MAX_RULE_DURATION_SECS + 1)]) {
      expect(validateRuleForm(ruleForm({ durationSecs })), durationSecs).toContain(
        "持续时间",
      );
    }
    expect(validateRuleForm(ruleForm({ cooldownSecs: "604801" }))).toContain("冷却时间");
    expect(validateRuleForm(ruleForm({ cooldownSecs: "1.5" }))).toContain("冷却时间");
  });

  it("拒绝非法 agent 过滤与 labels", () => {
    expect(validateRuleForm(ruleForm({ filterAgentId: "hub self" }))).toContain(
      "filter_agent_id",
    );
    expect(
      validateRuleForm(ruleForm({ filterAgentId: "a".repeat(65) })),
    ).toContain("filter_agent_id");

    expect(
      validateRuleForm(ruleForm({ labels: [{ key: "", value: "x" }] })),
    ).toContain("键不能为空");
    expect(
      validateRuleForm(ruleForm({ labels: [{ key: "a b", value: "x" }] })),
    ).toContain("不含空白");
    expect(
      validateRuleForm(ruleForm({ labels: [{ key: "k".repeat(65), value: "x" }] })),
    ).toContain("键");
    expect(
      validateRuleForm(
        ruleForm({
          labels: [
            { key: "env", value: "prod" },
            { key: "env", value: "dev" },
          ],
        }),
      ),
    ).toContain("重复");
    expect(
      validateRuleForm(
        ruleForm({ labels: [{ key: "env", value: "v".repeat(257) }] }),
      ),
    ).toContain("值");
    const tooMany = Array.from({ length: MAX_RULE_LABELS + 1 }, (_, index) => ({
      key: `k${index}`,
      value: "v",
    }));
    expect(validateRuleForm(ruleForm({ labels: tooMany }))).toContain("最多");
  });

  it("限制绑定渠道数与渠道 id 字符集", () => {
    expect(
      validateRuleForm(ruleForm({ channelIds: ["ch-1", "ch-1", "ch-2"] })),
    ).toBeNull();
    expect(
      validateRuleForm(
        ruleForm({
          channelIds: Array.from({ length: 17 }, (_, index) => `ch-${index}`),
        }),
      ),
    ).toContain("最多绑定");
    expect(validateRuleForm(ruleForm({ channelIds: ["../bad"] }))).toContain(
      "channel_ids",
    );
  });
});

describe("规则 payload", () => {
  it("创建 payload 覆盖全部字段，非 metric 来源清空 metric", () => {
    const payload = buildRuleCreatePayload(
      ruleForm({
        source: "agent_offline",
        metric: "leftover",
        threshold: "90.5",
        durationSecs: "90",
        cooldownSecs: "600",
        filterAgentId: " hub-self ",
        labels: [
          { key: "env", value: "prod" },
          { key: "", value: "" },
        ],
        channelIds: ["ch-1", "ch-1", "ch-2"],
        notifyOnResolve: false,
      }),
    );
    expect(payload).toEqual({
      name: "磁盘使用率过高",
      enabled: true,
      source: "agent_offline",
      metric: "",
      comparator: "gt",
      threshold: 90.5,
      duration_secs: 90,
      cooldown_secs: 600,
      filter_agent_id: "hub-self",
      filter_labels: { env: "prod" },
      channel_ids: ["ch-1", "ch-2"],
      notify_on_resolve: false,
    });
  });

  it("启停开关只产生 {enabled}", () => {
    const original = alertRule();
    const form = { ...ruleFormFromRule(original), enabled: false };
    expect(buildRuleUpdatePayload(original, form)).toEqual({ enabled: false });
    expect(hasRuleChanges({})).toBe(false);
    expect(hasRuleChanges({ enabled: false })).toBe(true);
  });

  it("没有变更时不发送任何字段", () => {
    const original = alertRule();
    expect(buildRuleUpdatePayload(original, ruleFormFromRule(original))).toEqual({});
    // 数字字符串的等价写法（90.0 / 090）不应制造无意义的 PUT。
    expect(
      buildRuleUpdatePayload(original, {
        ...ruleFormFromRule(original),
        threshold: "90.0",
        durationSecs: "0300",
      }),
    ).toEqual({});
    // labels 的键顺序变化同样视为未修改。
    expect(
      buildRuleUpdatePayload(
        original,
        ruleFormFromRule({
          ...original,
          filter_labels: { env: "prod", mount: "/data" },
        }),
      ),
    ).toEqual({});
  });

  it("只发送实际变化的字段", () => {
    const original = alertRule();
    const form = ruleFormFromRule(original);
    expect(buildRuleUpdatePayload(original, { ...form, name: "新名称" })).toEqual({
      name: "新名称",
    });
    expect(
      buildRuleUpdatePayload(original, { ...form, durationSecs: "60" }),
    ).toEqual({ duration_secs: 60 });
    expect(
      buildRuleUpdatePayload(original, { ...form, filterAgentId: "" }),
    ).toEqual({ filter_agent_id: null });
    expect(
      buildRuleUpdatePayload(original, {
        ...form,
        labels: [{ key: "env", value: "dev" }, { key: "mount", value: "/data" }],
      }),
    ).toEqual({ filter_labels: { env: "dev", mount: "/data" } });
    expect(
      buildRuleUpdatePayload(original, {
        ...form,
        channelIds: ["ch-2", "ch-1"],
      }),
    ).toEqual({});
    expect(
      buildRuleUpdatePayload(original, {
        ...form,
        channelIds: ["ch-1"],
      }),
    ).toEqual({ channel_ids: ["ch-1"] });
  });

  it("从 metric 切到内置来源时显式清空 metric", () => {
    const original = alertRule();
    const form = { ...ruleFormFromRule(original), source: "agent_offline" as const };
    expect(buildRuleUpdatePayload(original, form)).toEqual({
      source: "agent_offline",
      metric: "",
    });
  });
});

describe("filter_labels 的原型键 (#41)", () => {
  // 后端允许 `__proto__` / `constructor` 作为标签键；对象字面量里的
  // `__proto__` 是原型 setter，必须用 JSON.parse 生成“自带属性”的规则。
  const specialLabels = (): Record<string, string> =>
    JSON.parse('{"__proto__":"sentinel","constructor":"ctor","mount":"/data"}');

  it("buildFilterLabels 保留 __proto__ / constructor 的自有属性", () => {
    const labels = buildFilterLabels([
      { key: "__proto__", value: "sentinel" },
      { key: "constructor", value: "ctor" },
      { key: "mount", value: "/data" },
    ]);
    expect(Object.keys(labels).sort()).toEqual([
      "__proto__",
      "constructor",
      "mount",
    ]);
    expect(Object.prototype.hasOwnProperty.call(labels, "__proto__")).toBe(true);
    expect(labels["__proto__"]).toBe("sentinel");
    expect(labels["constructor"]).toBe("ctor");
    expect(labels["mount"]).toBe("/data");

    const roundtrip = JSON.parse(JSON.stringify(labels)) as Record<string, string>;
    expect(Object.keys(roundtrip).sort()).toEqual([
      "__proto__",
      "constructor",
      "mount",
    ]);
    expect(roundtrip["__proto__"]).toBe("sentinel");
    expect(roundtrip["constructor"]).toBe("ctor");
  });

  it("创建规则时特殊标签完整进入 JSON 请求体", () => {
    const payload = buildRuleCreatePayload(
      ruleForm({
        labels: [
          { key: "__proto__", value: "sentinel" },
          { key: "constructor", value: "ctor" },
          { key: "env", value: "prod" },
        ],
      }),
    );
    const json = JSON.parse(JSON.stringify(payload.filter_labels)) as Record<
      string,
      string
    >;
    expect(json).toEqual(specialLabelsWithEnv());
    expect(json["__proto__"]).toBe("sentinel");
    expect(json["constructor"]).toBe("ctor");
  });

  it("编辑规则时未修改标签不发送 filter_labels（不会清空特殊键）", () => {
    const original = alertRule({ filter_labels: specialLabels() });
    const form = ruleFormFromRule(original);
    expect(form.labels).toEqual([
      { key: "__proto__", value: "sentinel" },
      { key: "constructor", value: "ctor" },
      { key: "mount", value: "/data" },
    ]);

    expect(buildRuleUpdatePayload(original, { ...form, name: "新名称" })).toEqual({
      name: "新名称",
    });
    // 普通键顺序变化也不应触发 PUT。
    expect(
      buildRuleUpdatePayload(original, {
        ...form,
        labels: [
          { key: "mount", value: "/data" },
          { key: "constructor", value: "ctor" },
          { key: "__proto__", value: "sentinel" },
        ],
      }),
    ).toEqual({});
  });

  it("编辑特殊标签值时仍保留其它键并序列化完整", () => {
    const original = alertRule({ filter_labels: specialLabels() });
    const payload = buildRuleUpdatePayload(original, {
      ...ruleFormFromRule(original),
      labels: [
        { key: "__proto__", value: "sentinel" },
        { key: "constructor", value: "ctor" },
        { key: "mount", value: "/srv" },
      ],
    });
    const labels = payload.filter_labels as Record<string, string>;
    expect(Object.keys(labels).sort()).toEqual([
      "__proto__",
      "constructor",
      "mount",
    ]);
    const json = JSON.parse(JSON.stringify(labels)) as Record<string, string>;
    expect(json["__proto__"]).toBe("sentinel");
    expect(json["constructor"]).toBe("ctor");
    expect(json["mount"]).toBe("/srv");
  });
});

function specialLabelsWithEnv(): Record<string, string> {
  return JSON.parse(
    '{"__proto__":"sentinel","constructor":"ctor","env":"prod"}',
  ) as Record<string, string>;
}

describe("事件格式化", () => {
  it("状态、agent 与规则名都有稳定中文展示", () => {
    expect(formatEventState("firing")).toBe("触发");
    expect(formatEventState("resolved")).toBe("恢复");
    expect(formatEventState("pending")).toBe("等待中");
    expect(formatEventState("weird")).toBe("weird");
    expect(eventStateClass("firing")).toBe("event-firing");
    expect(eventStateClass("resolved")).toBe("event-resolved");
    expect(eventStateClass("pending")).toBe("event-unknown");
    expect(formatEventAgent("")).toBe("全局");
    expect(formatEventAgent("hub-self")).toBe("hub-self");
    expect(formatEventRule(alertEvent({ rule_name: "" }))).toBe("rule-1");
    expect(formatEventRule(alertEvent())).toBe("磁盘使用率过高");
    expect(formatAlertValue(90)).toBe("90");
    expect(formatAlertValue(93.456)).toBe("93.46");
    expect(formatAlertValue(null)).toBe("—");
    expect(formatAlertValue(Number.NaN)).toBe("—");
  });

  it("通知状态优先展示静默与错误", () => {
    expect(formatNotifyStatus(alertEvent())).toBe("已通知");
    expect(formatNotifyStatus(alertEvent({ notified: false }))).toBe("未通知");
    expect(
      formatNotifyStatus(alertEvent({ notified: false, silenced: true })),
    ).toBe("静默中，未通知");
    expect(
      formatNotifyStatus(
        alertEvent({ notified: false, notify_error: "queue_full", silenced: false }),
      ),
    ).toBe("通知失败：queue_full");
    // 静默优先级高于 notify_error：静默期间不会尝试发送。
    expect(
      formatNotifyStatus(alertEvent({ silenced: true, notify_error: "x" })),
    ).toBe("静默中，未通知");
  });

  it("规则展示辅助函数", () => {
    expect(formatDurationSecs(0)).toBe("0 秒");
    expect(formatDurationSecs(90)).toBe("90 秒");
    expect(formatDurationSecs(300)).toBe("5 分钟");
    expect(formatDurationSecs(7200)).toBe("2 小时");
    expect(formatDurationSecs(172800)).toBe("2 天");
    expect(formatRuleThreshold(alertRule())).toBe("> 90");
    expect(formatRuleThreshold(alertRule({ comparator: "lte", threshold: 95.5 }))).toBe(
      "≤ 95.50",
    );
    expect(formatRuleTarget(alertRule())).toBe("disk.used_percent");
    expect(formatRuleTarget(alertRule({ source: "agent_offline", metric: "" }))).toBe(
      "agent 离线",
    );
    expect(formatRuleFilter(alertRule())).toBe("agent=hub-self · 2 个 label");
    expect(formatRuleFilter(alertRule({ filter_agent_id: null, filter_labels: {} }))).toBe(
      "全部",
    );
    expect(alertSourceLabel("hub_cert")).toBe("hub 证书剩余时间");
    expect(ALERT_SOURCE_OPTIONS).toHaveLength(3);
    expect(ALERT_COMPARATOR_OPTIONS.map((item) => item.value)).toEqual([
      "gt",
      "gte",
      "lt",
      "lte",
      "eq",
      "ne",
    ]);
  });
});

describe("渠道 secret 保留逻辑", () => {
  it("编辑回填只读取扁平 chat_id，响应里没有任何 secret 值", () => {
    const view = channelView();
    const form = channelFormFromView(view);
    expect(form).toEqual({
      name: "运维群",
      kind: "telegram",
      enabled: true,
      config: { chat_id: "123456" },
    });
    // ChannelView 只有 secret 字段名；序列化后不可能出现 secret 原文。
    expect(JSON.stringify(view)).not.toContain("should-never-render");
    expect(isSecretConfigured(view, "bot_token")).toBe(true);
    expect(channelSecretSummary(view)).toBe("1/1 项 secret 已配置");

    // 非 Telegram 渠道的 chat_id 为 null，不应回填到表单。
    expect(
      channelFormFromView(
        channelView({ kind: "wecom", chat_id: null, secret_fields: ["webhook_key"] }),
      ).config,
    ).toEqual({});
  });

  it("编辑时 secret 留空不写入 config（保留原值）", () => {
    const view = channelView();
    const form = channelFormFromView(view);
    expect(validateChannelForm(form, { bot_token: "" }, true)).toBeNull();
    const input = buildChannelInput(form, { bot_token: "   " });
    expect(input.config).toEqual({ chat_id: "123456" });
    expect(JSON.stringify(input)).not.toContain("bot_token");

    const withSecret = buildChannelInput(form, { bot_token: "new-token" });
    expect(withSecret.config).toEqual({
      chat_id: "123456",
      bot_token: "new-token",
    });
  });

  it("新建时 secret 必填且按渠道类型只读取对应字段", () => {
    const telegram = emptyChannelForm("telegram");
    telegram.name = "群";
    telegram.config = { chat_id: "42" };
    expect(validateChannelForm(telegram, {}, false)).toContain("bot_token");
    expect(validateChannelForm(telegram, { bot_token: "  " }, false)).toContain(
      "bot_token",
    );
    expect(validateChannelForm(telegram, { bot_token: "token" }, false)).toBeNull();
    expect(validateChannelForm(telegram, { bot_token: "x".repeat(129) }, false)).toContain(
      "128",
    );

    const dingtalk = emptyChannelForm("dingtalk");
    dingtalk.name = "钉钉群";
    expect(validateChannelForm(dingtalk, {}, false)).toContain("access_token");
    expect(
      validateChannelForm(dingtalk, { access_token: "a", secret: "s" }, false),
    ).toBeNull();
    expect(channelFields("dingtalk").secret.map((field) => field.key)).toEqual([
      "access_token",
      "secret",
    ]);
    expect(channelFields("wecom").nonSecret).toEqual([]);
  });

  it("Telegram chat_id 必填，渠道名称限长", () => {
    const telegram = emptyChannelForm("telegram");
    telegram.name = "群";
    expect(validateChannelForm(telegram, { bot_token: "token" }, false)).toContain(
      "chat_id",
    );
    expect(
      validateChannelForm(
        { ...telegram, name: "", config: { chat_id: "42" } },
        { bot_token: "token" },
        false,
      ),
    ).toContain("名称");
    expect(
      validateChannelForm(
        { ...telegram, name: "名".repeat(30), config: { chat_id: "42" } },
        { bot_token: "token" },
        false,
      ),
    ).toContain("64 字节");
  });

  it("列表只展示字段名与配置数量", () => {
    const view = channelView({ secret_fields: [] });
    expect(channelSecretSummary(view)).toBe("0/1 项 secret 已配置");
    expect(channelSecretSummary(channelView({ kind: "wecom" }))).toBe(
      "0/1 项 secret 已配置",
    );
  });
});

describe("静默表单", () => {
  it("校验时长范围与 agent 字符集", () => {
    expect(validateSilenceForm(emptySilenceForm())).toBeNull();
    expect(
      validateSilenceForm({ ...emptySilenceForm(), durationSecs: "1" }),
    ).toBeNull();
    expect(
      validateSilenceForm({
        ...emptySilenceForm(),
        durationSecs: String(MAX_SILENCE_SECS),
      }),
    ).toBeNull();
    for (const durationSecs of ["0", "-1", "1.5", "abc", "604801", ""]) {
      expect(
        validateSilenceForm({ ...emptySilenceForm(), durationSecs }),
        durationSecs,
      ).toContain("静默时长");
    }
    expect(
      validateSilenceForm({ ...emptySilenceForm(), agentId: "a/b" }),
    ).toContain("agent_id");
    expect(
      validateSilenceForm({ ...emptySilenceForm(), ruleId: "../x" }),
    ).toContain("rule_id");
  });

  it("构造请求体时空规则 / agent 变为 null", () => {
    expect(
      buildSilenceInput({ ruleId: "", agentId: "  ", durationSecs: "3600" }),
    ).toEqual({ rule_id: null, agent_id: null, duration_secs: 3600 });
    expect(
      buildSilenceInput({
        ruleId: "builtin-disk-percent",
        agentId: "hub-self",
        durationSecs: "60",
      }),
    ).toEqual({
      rule_id: "builtin-disk-percent",
      agent_id: "hub-self",
      duration_secs: 60,
    });
  });

  it("范围与截止时间展示", () => {
    const rules = [alertRule({ id: "builtin-disk-percent", name: "磁盘使用率" })];
    const silence: AlertSilence = {
      id: 1,
      rule_id: "builtin-disk-percent",
      agent_id: "hub-self",
      until_ts: 1_700_000_600_000,
      created_by: "admin",
      created_at: 1_700_000_000_000,
    };
    expect(formatSilenceScope(silence, rules)).toBe("磁盘使用率 · hub-self");
    expect(
      formatSilenceScope({ ...silence, rule_id: null, agent_id: null }, rules),
    ).toBe("全部规则 · 全部 agent");
    expect(formatSilenceScope({ ...silence, rule_id: "missing" }, rules)).toBe(
      "missing · hub-self",
    );
    expect(formatSilenceUntil(1_700_000_600_000, 1_700_000_000_000)).toContain("结束");
    expect(formatSilenceUntil(1_700_000_000_000, 1_700_000_000_000)).toBe("已结束");
    expect(formatSilenceUntil(Number.NaN)).toBe("—");
  });
});

describe("错误展示", () => {
  it("优先使用服务端 message，并附带 code", () => {
    expect(
      describeAlertError(new ApiError(409, "conflict", "规则名称重复")),
    ).toBe("规则名称重复（conflict）");
    expect(describeAlertError(new ApiError(403, "builtin_rule"))).toBe(
      "没有权限执行该操作（builtin_rule）",
    );
    expect(describeAlertError(new ApiError(502, "notify_failed", "测试消息发送失败"))).toBe(
      "测试消息发送失败（notify_failed）",
    );
    expect(describeAlertError(new TypeError("Failed to fetch"))).toContain("网络错误");
  });
});
