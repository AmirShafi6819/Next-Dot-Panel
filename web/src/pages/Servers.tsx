import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, Server, ApiError } from '../api';
import { StatusBadge } from '../App';
import { useAuth } from '../auth';

export default function Servers() {
  const { can } = useAuth();
  const [servers, setServers] = useState<Server[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: '', host: '', port: 22, username: 'root', auth_method: 'key',
    host_key_policy: 'TOFU', password: '', private_key: '', passphrase: '',
  });

  async function load() {
    try {
      const res = await api.servers();
      setServers(res.servers);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load servers');
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api.createServer({ ...form });
      setShowCreate(false);
      setForm({ name: '', host: '', port: 22, username: 'root', auth_method: 'key', host_key_policy: 'TOFU', password: '', private_key: '', passphrase: '' });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Create failed');
    }
  }

  return (
    <div>
      <div className="row">
        <h2>Servers ({total})</h2>
        {can('servers.create') && <button onClick={() => setShowCreate(!showCreate)}>Add server</button>}
      </div>
      {error && <div className="alert bad">{error}</div>}
      {showCreate && (
        <div className="card">
          <h3>Add server</h3>
          <form onSubmit={create} className="narrow">
            <label>Name</label>
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <label>Host</label>
            <input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} required />
            <label>Port</label>
            <input type="number" value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
            <label>Username</label>
            <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
            <label>Auth method</label>
            <select value={form.auth_method} onChange={(e) => setForm({ ...form, auth_method: e.target.value })}>
              <option value="key">SSH key</option>
              <option value="password">Password</option>
              <option value="agent">SSH agent</option>
            </select>
            {form.auth_method === 'password' && (
              <>
                <label>Password</label>
                <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              </>
            )}
            {form.auth_method === 'key' && (
              <>
                <label>Private key</label>
                <textarea value={form.private_key} onChange={(e) => setForm({ ...form, private_key: e.target.value })} rows={4} />
                <label>Passphrase (optional)</label>
                <input type="password" value={form.passphrase} onChange={(e) => setForm({ ...form, passphrase: e.target.value })} />
              </>
            )}
            <p>
              <button className="primary" type="submit">Save</button>{' '}
              <button type="button" onClick={() => setShowCreate(false)}>Cancel</button>
            </p>
          </form>
        </div>
      )}
      {servers.length === 0 ? (
        <div className="empty">No servers yet. Add your first Linux server to get started.</div>
      ) : (
        <div className="grid">
          {servers.map((s) => (
            <div className="card" key={s.id}>
              <div className="row">
                <strong><Link to={`/servers/${s.id}`}>{s.name}</Link></strong>
                <StatusBadge status={s.status} />
              </div>
              <p className="dim mono">{s.username}@{s.host}:{s.port}</p>
              <p className="dim">{[s.os, s.arch].filter(Boolean).join(' · ')}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
