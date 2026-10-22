import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, describeError } from "../api";
import {
  CONTROL_CAPABILITIES,
  actionLabel,
  describeControlError,
  enabledCapabilities,
  isActionFailed,
  isDangerousAction,
  isMutationAction,
} from "../control";
import { formatBytes } from "../format";
import { isAbortError } from "../rate";
import type {
  ControlCapability,
  ControlLogLines,
  ControlRequestPayload,
  ControlResponse,
  ControlStatus,
  DockerContainer,
  LogSourceInfo,
  ProcessInfo,
  SystemdUnit,
} from "../types";

const LOG_TAIL_LINES = 200;

/** 面板请求异常统一转成控制错误；AbortError 继续向上抛，交给 effect 忽略。 */
async function requestControl(
  agentId: string,
  payload: ControlRequestPayload,
  signal?: AbortSignal,
): Promise<ControlResponse> {
  try {
    return await api.control(agentId, payload, signal);
  } catch (error) {
    if (isAbortError(error)) throw error;
    return {
      ok: false,
      error: { code: "network_error", message: describeError(error) },
    };
  }
}

/** 只读动作不带 confirm；所有变更动作都显式带 confirm:true。 */
function mutationConfirm(action: string): { confirm?: true } {
  return isMutationAction(action) ? { confirm: true } : {};
}

function ActionFeedback({
  title,
  response,
}: {
  title: string;
  response: ControlResponse;
}) {
  if (!response.ok) {
    return (
      <div className="banner error action-result" role="alert">
        <span>{describeControlError(response.error, response.status)}</span>
      </div>
    );
  }
  if (response.result.type !== "action_output") {
    return <div className="banner info action-result">{title}：操作成功。</div>;
  }
  const { stdout, stderr, exit_code } = response.result;
  // 与 hub 审计一致：null（被信号终止）也按失败展示。
  const failed = isActionFailed(exit_code);
  return (
    <div className={`action-result ${failed ? "action-failed" : "action-ok"}`}>
      <div className="action-result-head">
        <span>{title}</span>
        <span className={`exit-code ${failed ? "bad" : "good"}`}>
          退出码：{exit_code === null ? "—（被信号终止）" : exit_code}
        </span>
      </div>
      <div className="output-block">
        <span className="output-label">stdout</span>
        <pre className="command-output">{stdout === "" ? "（空）" : stdout}</pre>
      </div>
      <div className="output-block">
        <span className="output-label">stderr</span>
        <pre className="command-output stderr">{stderr === "" ? "（空）" : stderr}</pre>
      </div>
    </div>
  );
}

function CapabilityNotice({ text }: { text: string }) {
  return (
    <div className="empty-state control-empty">
      <h2>暂不可用</h2>
      <p className="muted">{text}</p>
    </div>
  );
}

function SystemdPanel({ agentId }: { agentId: string }) {
  const [units, setUnits] = useState<SystemdUnit[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{
    title: string;
    response: ControlResponse;
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const response = await requestControl(agentId, {
      capability: "systemd",
      action: "list",
    });
    setLoading(false);
    if (!response.ok) {
      setError(describeControlError(response.error, response.status));
      return;
    }
    if (response.result.type !== "systemd_units") {
      setError("服务端返回了意外的结果类型");
      return;
    }
    setError(null);
    setUnits(response.result.units);
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  const execute = async (unit: SystemdUnit, action: "start" | "stop" | "restart") => {
    if (busy !== null) return;
    if (isDangerousAction(action)) {
      const confirmed = window.confirm(
        `确认${actionLabel(action)} ${unit.unit}？\n该操作会改变服务状态，请确认目标无误。`,
      );
      if (!confirmed) return;
    }
    setBusy(`${unit.unit}:${action}`);
    setFeedback(null);
    const response = await requestControl(agentId, {
      capability: "systemd",
      action,
      target: unit.unit,
      ...mutationConfirm(action),
    });
    setBusy(null);
    setFeedback({
      title: `${actionLabel(action)} ${unit.unit}`,
      response,
    });
    if (response.ok) await load();
  };

  return (
    <div className="control-panel">
      <div className="panel-toolbar">
        <div>
          <h2>systemd unit</h2>
          <p className="muted">仅展示白名单内的 unit；停止 / 重启需要二次确认。</p>
        </div>
        <button
          type="button"
          className="button small"
          onClick={() => void load()}
          disabled={loading || busy !== null}
        >
          {loading ? "读取中…" : "刷新列表"}
        </button>
      </div>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="button small" onClick={() => void load()}>
            重试
          </button>
        </div>
      ) : null}

      {loading && units === null ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在读取 unit 列表…
        </div>
      ) : null}

      {units !== null && units.length === 0 ? (
        <div className="empty-state control-empty">
          <h2>没有可管理的 unit</h2>
          <p className="muted">agent 的 systemd 白名单为空，或当前没有匹配的 unit。</p>
        </div>
      ) : null}

      {units !== null && units.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Unit</th>
                <th>Load</th>
                <th>Active</th>
                <th>Sub</th>
                <th>描述</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {units.map((unit) => (
                <tr key={unit.unit}>
                  <td className="mono">{unit.unit}</td>
                  <td>{unit.load || "—"}</td>
                  <td>{unit.active || "—"}</td>
                  <td>{unit.sub || "—"}</td>
                  <td className="wrap-cell">{unit.description || "—"}</td>
                  <td>
                    <div className="row-actions">
                      {(["start", "stop", "restart"] as const).map((action) => (
                        <button
                          key={action}
                          type="button"
                          className={`button small ${
                            isDangerousAction(action) ? "danger" : ""
                          }`}
                          disabled={busy !== null}
                          onClick={() => void execute(unit, action)}
                        >
                          {busy === `${unit.unit}:${action}`
                            ? "执行中…"
                            : actionLabel(action)}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {feedback ? (
        <ActionFeedback title={feedback.title} response={feedback.response} />
      ) : null}
    </div>
  );
}

function DockerPanel({ agentId }: { agentId: string }) {
  const [containers, setContainers] = useState<DockerContainer[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{
    title: string;
    response: ControlResponse;
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const response = await requestControl(agentId, {
      capability: "docker",
      action: "list",
    });
    setLoading(false);
    if (!response.ok) {
      setError(describeControlError(response.error, response.status));
      return;
    }
    if (response.result.type !== "docker_containers") {
      setError("服务端返回了意外的结果类型");
      return;
    }
    setError(null);
    setContainers(response.result.containers);
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  const execute = async (
    container: DockerContainer,
    action: "start" | "stop" | "restart",
  ) => {
    if (busy !== null) return;
    if (isDangerousAction(action)) {
      const confirmed = window.confirm(
        `确认${actionLabel(action)}容器 ${container.name}？\n该操作会改变容器状态，请确认目标无误。`,
      );
      if (!confirmed) return;
    }
    setBusy(`${container.name}:${action}`);
    setFeedback(null);
    const response = await requestControl(agentId, {
      capability: "docker",
      action,
      target: container.name,
      ...mutationConfirm(action),
    });
    setBusy(null);
    setFeedback({
      title: `${actionLabel(action)}容器 ${container.name}`,
      response,
    });
    if (response.ok) await load();
  };

  return (
    <div className="control-panel">
      <div className="panel-toolbar">
        <div>
          <h2>Docker 容器</h2>
          <p className="muted">仅展示白名单内的容器；停止 / 重启需要二次确认。</p>
        </div>
        <button
          type="button"
          className="button small"
          onClick={() => void load()}
          disabled={loading || busy !== null}
        >
          {loading ? "读取中…" : "刷新列表"}
        </button>
      </div>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="button small" onClick={() => void load()}>
            重试
          </button>
        </div>
      ) : null}

      {loading && containers === null ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在读取容器列表…
        </div>
      ) : null}

      {containers !== null && containers.length === 0 ? (
        <div className="empty-state control-empty">
          <h2>没有可管理的容器</h2>
          <p className="muted">agent 的 Docker 白名单为空，或当前没有匹配的容器。</p>
        </div>
      ) : null}

      {containers !== null && containers.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>容器</th>
                <th>名称</th>
                <th>镜像</th>
                <th>State</th>
                <th>Status</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {containers.map((container) => (
                <tr key={container.id || container.name}>
                  <td className="mono" title={container.id}>
                    {container.id.length > 12 ? container.id.slice(0, 12) : container.id}
                  </td>
                  <td className="mono">{container.name}</td>
                  <td className="wrap-cell mono">{container.image || "—"}</td>
                  <td>{container.state || "—"}</td>
                  <td className="wrap-cell">{container.status || "—"}</td>
                  <td>
                    <div className="row-actions">
                      {(["start", "stop", "restart"] as const).map((action) => (
                        <button
                          key={action}
                          type="button"
                          className={`button small ${
                            isDangerousAction(action) ? "danger" : ""
                          }`}
                          disabled={busy !== null}
                          onClick={() => void execute(container, action)}
                        >
                          {busy === `${container.name}:${action}`
                            ? "执行中…"
                            : actionLabel(action)}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {feedback ? (
        <ActionFeedback title={feedback.title} response={feedback.response} />
      ) : null}
    </div>
  );
}

function ProcessPanel({ agentId }: { agentId: string }) {
  const [processes, setProcesses] = useState<ProcessInfo[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<ProcessInfo | null>(null);
  const [killName, setKillName] = useState("");
  const [busyPid, setBusyPid] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<{
    title: string;
    response: ControlResponse;
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const response = await requestControl(agentId, {
      capability: "process",
      action: "list",
    });
    setLoading(false);
    if (!response.ok) {
      setError(describeControlError(response.error, response.status));
      return;
    }
    if (response.result.type !== "processes") {
      setError("服务端返回了意外的结果类型");
      return;
    }
    setError(null);
    setProcesses(response.result.processes);
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  const openKill = (process: ProcessInfo) => {
    if (busyPid !== null) return;
    setKillName("");
    setPending(process);
  };

  const submitKill = async () => {
    if (pending === null || busyPid !== null) return;
    const target = pending;
    const enteredName = killName.trim();
    if (enteredName === "") return;
    setPending(null);
    setKillName("");
    setBusyPid(target.pid);
    setFeedback(null);
    const response = await requestControl(agentId, {
      capability: "process",
      action: "kill",
      pid: target.pid,
      // 使用用户输入的名称，由 agent 侧再次校验 /proc/<pid>/comm；
      // 名称错误时展示服务端错误，且不刷新列表。
      name: enteredName,
      signal: "term",
      confirm: true,
    });
    setBusyPid(null);
    setFeedback({
      title: `结束进程 ${target.pid}（${target.name}）`,
      response,
    });
    if (response.ok) await load();
  };

  return (
    <div className="control-panel">
      <div className="panel-toolbar">
        <div>
          <h2>进程列表</h2>
          <p className="muted">
            结束进程需要输入进程名二次确认；服务端会再次校验 PID 与名称。
          </p>
        </div>
        <button
          type="button"
          className="button small"
          onClick={() => void load()}
          disabled={loading || busyPid !== null}
        >
          {loading ? "读取中…" : "刷新列表"}
        </button>
      </div>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="button small" onClick={() => void load()}>
            重试
          </button>
        </div>
      ) : null}

      {loading && processes === null ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在读取进程列表…
        </div>
      ) : null}

      {processes !== null && processes.length === 0 ? (
        <div className="empty-state control-empty">
          <h2>没有可展示的进程</h2>
          <p className="muted">agent 返回的进程列表为空。</p>
        </div>
      ) : null}

      {processes !== null && processes.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>PID</th>
                <th>名称</th>
                <th>UID</th>
                <th>RSS</th>
                <th>命令行</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {processes.map((process) => (
                <tr key={process.pid}>
                  <td className="mono">{process.pid}</td>
                  <td className="mono">{process.name || "—"}</td>
                  <td>{process.uid}</td>
                  <td>{formatBytes(process.rss)}</td>
                  <td className="cmdline mono" title={process.cmdline}>
                    {process.cmdline || "—"}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="button small danger"
                      disabled={busyPid !== null}
                      onClick={() => openKill(process)}
                    >
                      {busyPid === process.pid ? "结束中…" : "结束"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {feedback ? (
        <ActionFeedback title={feedback.title} response={feedback.response} />
      ) : null}

      {pending ? (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={() => setPending(null)}
        >
          <div
            className="confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="kill-process-title"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 id="kill-process-title">结束进程</h2>
            <p className="muted">
              PID <span className="mono">{pending.pid}</span> ·{" "}
              <span className="mono">{pending.name}</span>
            </p>
            <p>请输入进程名以确认（服务端会再次校验 PID 与名称）：</p>
            <input
              type="text"
              value={killName}
              onChange={(event) => setKillName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void submitKill();
                }
                if (event.key === "Escape") setPending(null);
              }}
              placeholder={pending.name || "进程名"}
              aria-label="进程名"
              autoFocus
            />
            <div className="button-row confirm-actions">
              <button type="button" className="button" onClick={() => setPending(null)}>
                取消
              </button>
              <button
                type="button"
                className="button danger"
                onClick={() => void submitKill()}
                disabled={killName.trim() === ""}
              >
                确认结束
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function LogsPanel({ agentId }: { agentId: string }) {
  const [sources, setSources] = useState<LogSourceInfo[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<LogSourceInfo | null>(null);
  const [tail, setTail] = useState<ControlLogLines | null>(null);
  const [tailError, setTailError] = useState<string | null>(null);
  const [tailLoading, setTailLoading] = useState(false);
  const tailRequest = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    const response = await requestControl(agentId, {
      capability: "logs",
      action: "list",
    });
    setLoading(false);
    if (!response.ok) {
      setError(describeControlError(response.error, response.status));
      return;
    }
    if (response.result.type !== "log_sources") {
      setError("服务端返回了意外的结果类型");
      return;
    }
    setError(null);
    setSources(response.result.sources);
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  const viewSource = async (source: LogSourceInfo) => {
    const requestId = tailRequest.current + 1;
    tailRequest.current = requestId;
    setSelected(source);
    setTail(null);
    setTailError(null);
    setTailLoading(true);
    const response = await requestControl(agentId, {
      capability: "logs",
      action: "tail",
      source: source.id,
      lines: LOG_TAIL_LINES,
      ...mutationConfirm("tail"),
    });
    if (tailRequest.current !== requestId) return;
    setTailLoading(false);
    if (!response.ok) {
      setTailError(describeControlError(response.error, response.status));
      return;
    }
    if (response.result.type !== "log_lines") {
      setTailError("服务端返回了意外的结果类型");
      return;
    }
    setTail(response.result);
  };

  return (
    <div className="control-panel">
      <div className="panel-toolbar">
        <div>
          <h2>日志来源</h2>
          <p className="muted">只读；点击来源查看最近 {LOG_TAIL_LINES} 行。</p>
        </div>
        <button
          type="button"
          className="button small"
          onClick={() => void load()}
          disabled={loading || tailLoading}
        >
          {loading ? "读取中…" : "刷新列表"}
        </button>
      </div>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="button small" onClick={() => void load()}>
            重试
          </button>
        </div>
      ) : null}

      {loading && sources === null ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在读取日志来源…
        </div>
      ) : null}

      {sources !== null && sources.length === 0 ? (
        <div className="empty-state control-empty">
          <h2>没有配置日志来源</h2>
          <p className="muted">在 agent 的 control.log_sources 中添加白名单日志后重试。</p>
        </div>
      ) : null}

      {sources !== null && sources.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>来源 ID</th>
                <th>名称</th>
                <th>类型</th>
                <th>目标</th>
                <th>大小</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((source) => (
                <tr
                  key={source.id}
                  className={selected?.id === source.id ? "active-row" : undefined}
                >
                  <td className="mono">{source.id}</td>
                  <td className="wrap-cell">{source.name || "—"}</td>
                  <td className="mono">{source.kind || "—"}</td>
                  <td className="mono wrap-cell" title={source.target}>
                    {source.target || "—"}
                  </td>
                  <td>
                    {source.size !== undefined ? formatBytes(source.size) : "—"}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="button small"
                      onClick={() => void viewSource(source)}
                      disabled={tailLoading}
                    >
                      {tailLoading && selected?.id === source.id ? "读取中…" : "查看日志"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {selected ? (
        <section className="log-panel">
          <div className="section-head">
            <h2>
              {selected.name || selected.id}
              <span className="mono muted"> · {selected.id}</span>
            </h2>
            <span className="muted">
              {tailLoading
                ? "正在读取…"
                : tail
                  ? `最近 ${LOG_TAIL_LINES} 行 · ${formatBytes(tail.size_bytes)}`
                  : "尚未读取"}
            </span>
          </div>
          {tailError ? (
            <div className="banner error" role="alert">
              <span>{tailError}</span>
            </div>
          ) : null}
          {tailLoading ? (
            <div className="loading-state">
              <span className="spinner" aria-hidden="true" />
              正在读取日志…
            </div>
          ) : null}
          {tail?.truncated ? (
            <div className="banner info">
              日志内容超过展示上限，已截断（仅显示最后 {LOG_TAIL_LINES} 行）。
            </div>
          ) : null}
          {tail && !tailLoading ? (
            <pre className="log-output" aria-label="日志内容">
              {tail.lines.length > 0 ? tail.lines.join("\n") : "（日志为空）"}
            </pre>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}

function capabilityChipState(
  status: ControlStatus,
  capability: ControlCapability,
): { enabled: boolean; title: string } {
  const agent = status.capabilities.includes(capability);
  const hub = status.hub_capabilities.includes(capability);
  if (!status.control_enabled) return { enabled: false, title: "hub 控制面总开关未启用" };
  if (!hub && !agent) return { enabled: false, title: "hub 与 agent 均未启用" };
  if (!hub) return { enabled: false, title: "hub 未启用该能力" };
  if (!agent) return { enabled: false, title: "agent 未上报该能力" };
  return { enabled: true, title: "hub 与 agent 均已启用" };
}

export default function AgentControlPage() {
  const { id } = useParams<{ id: string }>();
  const agentId = id ?? "";

  const [status, setStatus] = useState<ControlStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [active, setActive] = useState<ControlCapability | null>(null);

  useEffect(() => {
    if (!agentId) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .controlStatus(agentId, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setStatus(value);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setError(describeError(loadError));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [agentId, reloadKey]);

  if (!agentId) {
    return (
      <div className="page">
        <div className="banner error">缺少 agent id</div>
        <Link className="button" to="/">
          返回概览
        </Link>
      </div>
    );
  }

  const enabled = status ? enabledCapabilities(status) : [];
  const activeTab: ControlCapability =
    active ?? enabled[0] ?? CONTROL_CAPABILITIES[0].key;
  const activeEnabled = enabled.includes(activeTab);

  const unavailableReason = !status
    ? ""
    : !status.control_enabled
      ? "hub 控制面总开关未启用（[control] enabled = false），所有控制能力不可用。"
      : !activeEnabled
        ? "该能力未启用：需要在 hub 与 agent 的 [control] 配置中同时开启。"
        : !status.online
          ? "agent 当前离线，控制操作暂不可用；能力状态来自最近一次上报。"
          : "";

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <Link className="back-link" to={`/agents/${encodeURIComponent(agentId)}`}>
            ← 返回节点详情
          </Link>
          <h1 className="mono">{agentId}</h1>
          <p className="muted">控制台 · systemd / Docker / 进程 / 日志</p>
        </div>
        <div className="button-row">
          <Link
            className="button"
            to={`/agents/${encodeURIComponent(agentId)}`}
          >
            节点详情
          </Link>
          <button
            type="button"
            className="button"
            onClick={() => setReloadKey((value) => value + 1)}
            disabled={loading}
          >
            {loading ? "刷新中…" : "刷新状态"}
          </button>
        </div>
      </header>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button
            type="button"
            className="button small"
            onClick={() => setReloadKey((value) => value + 1)}
          >
            重试
          </button>
        </div>
      ) : null}

      {loading && status === null ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在读取控制能力状态…
        </div>
      ) : null}

      {status ? (
        <>
          <section className="panel control-status">
            <div className="status-grid">
              <div className="status-item">
                <span className="control-label">控制面</span>
                <span
                  className={`status-pill ${
                    status.control_enabled ? "status-online" : "status-offline"
                  }`}
                >
                  {status.control_enabled ? "已启用" : "未启用"}
                </span>
              </div>
              <div className="status-item">
                <span className="control-label">Agent</span>
                <span
                  className={`status-pill ${
                    status.online ? "status-online" : "status-offline"
                  }`}
                >
                  {status.online ? "在线" : "离线"}
                </span>
              </div>
              <div className="status-item status-capabilities">
                <span className="control-label">能力</span>
                <div className="capability-chips">
                  {CONTROL_CAPABILITIES.map((capability) => {
                    const state = capabilityChipState(status, capability.key);
                    return (
                      <span
                        key={capability.key}
                        className={`capability-chip ${
                          state.enabled ? "enabled" : "disabled"
                        }`}
                        title={state.title}
                      >
                        {capability.label}
                        <span className="capability-state">
                          {state.enabled ? "已启用" : "未启用"}
                        </span>
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>
          </section>

          {!status.control_enabled ? (
            <div className="banner info">
              hub 控制面未启用；所有能力只展示状态，不会向 agent 发送控制请求。
            </div>
          ) : null}
          {status.control_enabled && !status.online ? (
            <div className="banner info">
              agent 当前离线，控制操作暂不可用；能力状态来自最近一次上报。
            </div>
          ) : null}

          <section className="panel control-panel-shell">
            <div className="control-tabs" role="tablist" aria-label="控制能力">
              {CONTROL_CAPABILITIES.map((capability) => {
                const state = capabilityChipState(status, capability.key);
                const selected = activeTab === capability.key;
                return (
                  <button
                    key={capability.key}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    aria-disabled={!state.enabled}
                    className={`control-tab ${selected ? "active" : ""} ${
                      state.enabled ? "" : "disabled"
                    }`}
                    title={state.title}
                    onClick={() => setActive(capability.key)}
                  >
                    <span>{capability.label}</span>
                    <span className="tab-state">
                      {!status.control_enabled || !state.enabled
                        ? "未启用"
                        : status.online
                          ? "可用"
                          : "离线"}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="control-tab-body" role="tabpanel">
              {unavailableReason !== "" ? (
                <CapabilityNotice text={unavailableReason} />
              ) : activeTab === "systemd" ? (
                <SystemdPanel agentId={agentId} />
              ) : activeTab === "docker" ? (
                <DockerPanel agentId={agentId} />
              ) : activeTab === "process" ? (
                <ProcessPanel agentId={agentId} />
              ) : (
                <LogsPanel agentId={agentId} />
              )}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
