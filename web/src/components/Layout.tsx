import { useState, type ReactNode } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";

export default function Layout({ children }: { children: ReactNode }) {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);

  const handleLogout = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await logout();
    } catch {
      // 网络失败也要回到登录页；AuthProvider 已在本地清除会话状态。
    } finally {
      navigate("/login", { replace: true });
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <Link to="/" className="brand-link">
            <span className="brand-mark">R</span>
            <span>RustBoard</span>
          </Link>
          <span className="brand-sub">监控面板</span>
        </div>
        <div className="topbar-actions">
          <nav className="topnav" aria-label="主导航">
            <NavLink
              to="/"
              end
              className={({ isActive }) => `topnav-link ${isActive ? "active" : ""}`}
            >
              概览
            </NavLink>
            <NavLink
              to="/audit"
              className={({ isActive }) => `topnav-link ${isActive ? "active" : ""}`}
            >
              审计
            </NavLink>
          </nav>
          <button
            type="button"
            className="button ghost"
            onClick={handleLogout}
            disabled={busy}
          >
            {busy ? "正在退出…" : "退出登录"}
          </button>
        </div>
      </header>
      <main className="content">{children}</main>
      <footer className="footer">
        <span>RustBoard · M3 控制面</span>
        <span className="muted">hub 管理 API 由面板服务端代理，浏览器不接触管理 token</span>
      </footer>
    </div>
  );
}
