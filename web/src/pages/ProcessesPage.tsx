import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api, RemoteProcess, ApiError } from '../api';

export default function ProcessesPage() {
  const { id } = useParams();
  const sid = Number(id);
  const [procs, setProcs] = useState<RemoteProcess[]>([]);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await api.processes(sid);
      setProcs(res.processes);
      setError('');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }, [sid]);

  useEffect(() => {
    load();
  }, [load]);

  async function signal(pid: number, name: string, force: boolean) {
    const what = force ? 'SIGKILL' : 'SIGTERM';
    if (!confirm(`Send ${what} to ${name} (pid ${pid})? Killing system processes can crash services.`)) return;
    try {
      await api.signalProcess(sid, pid, force);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Signal failed');
    }
  }

  const q = filter.toLowerCase();
  const visible = procs.filter(
    (p) => !q || p.name.toLowerCase().includes(q) || p.command?.toLowerCase().includes(q) || String(p.pid).includes(q),
  );

  return (
    <div>
      <div className="row">
        <h2>Processes ({visible.length})</h2>
        <input placeholder="Search…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ maxWidth: 240 }} />
        <button onClick={load}>Refresh</button>
      </div>
      {error && <div className="alert bad">{error}</div>}
      <div className="card">
        <table>
          <thead><tr><th>PID</th><th>Name</th><th>User</th><th>State</th><th>Memory</th><th>Command</th><th></th></tr></thead>
          <tbody>
            {visible.slice(0, 500).map((p) => (
              <tr key={p.pid}>
                <td className="mono">{p.pid}</td>
                <td>{p.name}</td>
                <td>{p.username}</td>
                <td className="mono dim">{p.state}</td>
                <td>{p.memory_bytes !== undefined ? `${(p.memory_bytes / 1048576).toFixed(1)} MiB` : '—'}</td>
                <td className="mono dim" title={p.command}>{(p.command ?? '').slice(0, 80)}</td>
                <td>
                  <span className="row">
                    <button onClick={() => signal(p.pid, p.name, false)}>Terminate</button>
                    <button className="danger" onClick={() => signal(p.pid, p.name, true)}>Kill</button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
