import { useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
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
        <button type="button" className="button ghost" onClick={handleLogout} disabled={busy}>
          {busy ? "正在退出…" : "退出登录"}
        </button>
      </header>
      <main className="content">{children}</main>
      <footer className="footer">
        <span>RustBoard · M2 面板</span>
        <span className="muted">hub 管理 API 由面板服务端代理，浏览器不接触管理 token</span>
      </footer>
    </div>
  );
}
