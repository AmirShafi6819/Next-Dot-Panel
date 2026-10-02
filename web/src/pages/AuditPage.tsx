import { useCallback, useEffect, useState } from 'react';
import { api, AuditEvent, ApiError } from '../api';

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [action, setAction] = useState('');
  const [result, setResult] = useState('');
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    try {
      const params: Record<string, string> = {};
      if (action) params.action = action;
      if (result) params.result = result;
      if (search) params.search = search;
      const res = await api.audit(params);
      setEvents(res.events);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }, [action, result, search]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div>
      <h2>Audit ({total})</h2>
      {error && <div className="alert bad">{error}</div>}
      <div className="row">
        <input placeholder="Action (e.g. LOGIN_FAILED)" value={action} onChange={(e) => setAction(e.target.value)} style={{ maxWidth: 220 }} />
        <select value={result} onChange={(e) => setResult(e.target.value)} style={{ width: 'auto' }}>
          <option value="">Any result</option>
          <option value="SUCCESS">Success</option>
          <option value="FAILURE">Failure</option>
          <option value="DENIED">Denied</option>
        </select>
        <input placeholder="Search…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ maxWidth: 220 }} />
        <button onClick={load}>Filter</button>
      </div>
      <div className="card">
        {events.length === 0 ? (
          <div className="empty">No audit events match.</div>
        ) : (
          <table>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>IP</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td className="dim">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="mono">{e.actor_name || '—'}</td>
                  <td className="mono">{e.action}</td>
                  <td className="mono dim">{e.target}</td>
                  <td>{e.result}</td>
                  <td className="mono dim">{e.ip || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
