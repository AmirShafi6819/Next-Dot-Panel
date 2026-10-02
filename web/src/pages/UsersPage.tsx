import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';

interface UserRow {
  id: number;
  username: string;
  display_name: string;
  is_active: boolean;
  must_change_password: boolean;
  version: number;
  roles: { id: number; name: string }[];
}

export default function UsersPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ username: '', display_name: '', password: '', is_active: true });
  const [history, setHistory] = useState<{ username: string; attempts: { id: number; ip: string; success: boolean; failure_reason?: string; timestamp: string }[] } | null>(null);

  async function load() {
    try {
      const res = await api.users();
      setUsers(res.users);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createUser({ ...form });
      setShowCreate(false);
      setForm({ username: '', display_name: '', password: '', is_active: true });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Create failed');
    }
  }

  async function toggleActive(u: UserRow) {
    try {
      await api.updateUser(u.id, { display_name: u.display_name, is_active: !u.is_active, version: u.version });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Update failed (version conflict — reload and retry)');
    }
  }

  async function remove(u: UserRow) {
    if (!confirm(`Delete user ${u.username}? Sessions are revoked; audit history is kept.`)) return;
    try {
      await api.deleteUser(u.id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Delete failed');
    }
  }

  async function reset(u: UserRow) {
    const pw = prompt(`New password for ${u.username} (min 12 chars):`);
    if (!pw) return;
    try {
      await api.resetPassword(u.id, pw);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Reset failed');
    }
  }

  async function showHistory(u: UserRow) {
    try {
      const res = await api.userLoginHistory(u.id);
      setHistory({ username: u.username, attempts: res.attempts });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'History failed');
    }
  }

  return (
    <div>
      <div className="row">
        <h2>Users ({users.length})</h2>
        <button onClick={() => setShowCreate(!showCreate)}>Create user</button>
      </div>
      {error && <div className="alert bad">{error}</div>}
      {showCreate && (
        <div className="card">
          <form onSubmit={create} className="narrow">
            <label>Username</label>
            <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
            <label>Display name</label>
            <input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
            <label>Password (min 12 chars)</label>
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
            <p>
              <button className="primary" type="submit">Create</button>{' '}
              <button type="button" onClick={() => setShowCreate(false)}>Cancel</button>
            </p>
          </form>
        </div>
      )}
      <div className="card">
        <table>
          <thead><tr><th>Username</th><th>Display name</th><th>Active</th><th>Roles</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td className="mono">{u.username}</td>
                <td>{u.display_name || '—'}</td>
                <td>{u.is_active ? 'yes' : 'no'}</td>
                <td className="dim">{u.roles.map((r) => r.name).join(', ') || '—'}</td>
                <td>
                  <span className="row">
                    <button onClick={() => toggleActive(u)}>{u.is_active ? 'Disable' : 'Enable'}</button>
                    <button onClick={() => reset(u)}>Reset password</button>
                    <button onClick={() => showHistory(u)}>Logins</button>
                    <button className="danger" onClick={() => remove(u)}>Delete</button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {history && (
        <div className="card">
          <h3>Login history — {history.username}</h3>
          <table>
            <thead><tr><th>Time</th><th>IP</th><th>Result</th><th>Reason</th></tr></thead>
            <tbody>
              {history.attempts.map((a) => (
                <tr key={a.id}>
                  <td>{new Date(a.timestamp).toLocaleString()}</td>
                  <td className="mono">{a.ip}</td>
                  <td>{a.success ? 'success' : 'failure'}</td>
                  <td className="dim">{a.failure_reason || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
