import { NavLink, Route, Routes, Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from './auth';
import Login from './pages/Login';
import Servers from './pages/Servers';
import ServerDetail from './pages/ServerDetail';
import TerminalPage from './pages/TerminalPage';
import FilesPage from './pages/FilesPage';
import MetricsPage from './pages/MetricsPage';
import ProcessesPage from './pages/ProcessesPage';
import UsersPage from './pages/UsersPage';
import RolesPage from './pages/RolesPage';
import AuditPage from './pages/AuditPage';

export function StatusBadge({ status }: { status: string }) {
  const cls = status === 'ONLINE' ? 'ok' : status === 'OFFLINE' || status === 'ERROR' ? 'bad' : status === 'CONNECTING' ? 'warn' : 'dim';
  return <span className={`badge ${cls}`}>{status}</span>;
}

function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout, can } = useAuth();
  const navigate = useNavigate();
  return (
    <div>
      {user?.default_credentials_warning && (
        <div className="banner">
          Default administrator credentials are still in use. Change them immediately.
        </div>
      )}
      <div className="app">
        <aside className="sidebar">
          <h1>Next.Panel</h1>
          <nav>
            <NavLink to="/servers">Servers</NavLink>
            {can('users.read') && <NavLink to="/users">Users</NavLink>}
            {can('users.read') && <NavLink to="/roles">Roles</NavLink>}
            {can('audit.read') && <NavLink to="/audit">Audit</NavLink>}
          </nav>
          <div className="who">
            {user?.username}{' '}
            <button
              onClick={async () => {
                await logout();
                navigate('/login');
              }}
            >
              Logout
            </button>
          </div>
        </aside>
        <main className="main">{children}</main>
      </div>
    </div>
  );
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="main">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/servers" element={<RequireAuth><Servers /></RequireAuth>} />
      <Route path="/servers/:id" element={<RequireAuth><ServerDetail /></RequireAuth>} />
      <Route path="/servers/:id/terminal" element={<RequireAuth><TerminalPage /></RequireAuth>} />
      <Route path="/servers/:id/files" element={<RequireAuth><FilesPage /></RequireAuth>} />
      <Route path="/servers/:id/metrics" element={<RequireAuth><MetricsPage /></RequireAuth>} />
      <Route path="/servers/:id/processes" element={<RequireAuth><ProcessesPage /></RequireAuth>} />
      <Route path="/users" element={<RequireAuth><UsersPage /></RequireAuth>} />
      <Route path="/roles" element={<RequireAuth><RolesPage /></RequireAuth>} />
      <Route path="/audit" element={<RequireAuth><AuditPage /></RequireAuth>} />
      <Route path="/" element={<Navigate to="/servers" replace />} />
      <Route path="*" element={<div className="main">Not found</div>} />
    </Routes>
  );
}
