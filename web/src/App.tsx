import { Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import Layout from "./components/Layout";
import AgentControlPage from "./pages/AgentControl";
import AgentDetailPage from "./pages/AgentDetail";
import AuditPage from "./pages/Audit";
import LoginPage from "./pages/Login";
import OverviewPage from "./pages/Overview";

function ProtectedLayout() {
  const { authenticated } = useAuth();
  const location = useLocation();

  if (authenticated === null) {
    return (
      <div className="fullscreen-status">
        <span className="spinner" aria-hidden="true" />
        正在确认登录状态…
      </div>
    );
  }
  if (!authenticated) {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: `${location.pathname}${location.search}` }}
      />
    );
  }
  return (
    <Layout>
      <Outlet />
    </Layout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedLayout />}>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/agents/:id/control" element={<AgentControlPage />} />
          <Route path="/agents/:id" element={<AgentDetailPage />} />
          <Route path="/audit" element={<AuditPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
