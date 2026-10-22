import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ApiError, describeError } from "../api";
import { useAuth } from "../auth";

interface LocationState {
  from?: string;
}

function loginErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "密码错误";
    if (error.status === 429) return "尝试次数过多，已锁定 15 分钟";
    if (error.status === 415) return "登录请求格式不正确";
  }
  return describeError(error);
}

export default function LoginPage() {
  const { authenticated, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const state = (location.state ?? null) as LocationState | null;
  const target =
    state?.from && state.from.startsWith("/") && !state.from.startsWith("//")
      ? state.from
      : "/";
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  if (authenticated === true) {
    return <Navigate to={target} replace />;
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (pending) return;
    if (!password) {
      setError("请输入密码");
      return;
    }
    setPending(true);
    setError(null);
    try {
      await login(password);
      setPassword("");
      navigate(target, { replace: true });
    } catch (submitError) {
      setError(loginErrorMessage(submitError));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          <span className="brand-mark large">R</span>
          <div>
            <h1>RustBoard</h1>
            <p className="muted">服务器监控面板</p>
          </div>
        </div>
        <label className="field">
          <span>管理员密码</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoFocus
            autoComplete="current-password"
            placeholder="输入面板密码"
            disabled={pending}
          />
        </label>
        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="button primary wide" disabled={pending}>
          {pending ? "正在登录…" : "登录"}
        </button>
        <p className="login-note muted">
          单管理员 · Argon2id 校验 · 失败 5 次锁定 15 分钟
        </p>
      </form>
    </div>
  );
}
