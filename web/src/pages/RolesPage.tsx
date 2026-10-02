import { useEffect, useState } from 'react';
import { api, Role, PermissionInfo, ApiError } from '../api';

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [perms, setPerms] = useState<PermissionInfo[]>([]);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());

  async function load() {
    try {
      const [r, p] = await Promise.all([api.roles(), api.permissions()]);
      setRoles(r.roles);
      setPerms(p.permissions);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }

  useEffect(() => {
    load();
  }, []);

  function toggle(p: string) {
    const next = new Set(selected);
    if (next.has(p)) next.delete(p);
    else next.add(p);
    setSelected(next);
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createRole({ name, description: '', permissions: Array.from(selected) });
      setName('');
      setSelected(new Set());
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Create failed');
    }
  }

  async function remove(r: Role) {
    if (r.is_system) return;
    if (!confirm(`Delete role ${r.name}?`)) return;
    try {
      await api.deleteRole(r.id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Delete failed');
    }
  }

  return (
    <div>
      <h2>Roles</h2>
      {error && <div className="alert bad">{error}</div>}
      <div className="card">
        <h3>Create role</h3>
        <form onSubmit={create} className="narrow">
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
          <label>Permissions</label>
          <div style={{ maxHeight: 240, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8, padding: 8 }}>
            {perms.map((p) => (
              <label key={p.name} className="row" style={{ margin: '2px 0' }}>
                <input type="checkbox" style={{ width: 'auto' }} checked={selected.has(p.name)} onChange={() => toggle(p.name)} />
                <span className="mono">{p.name}</span>
                <span className="dim">{p.description}</span>
              </label>
            ))}
          </div>
          <p><button className="primary" type="submit">Create</button></p>
        </form>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>Name</th><th>System</th><th>Permissions</th><th></th></tr></thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.name}</td>
                <td>{r.is_system ? 'yes' : 'no'}</td>
                <td className="dim">{r.permissions.length} permissions</td>
                <td>{!r.is_system && <button className="danger" onClick={() => remove(r)}>Delete</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
