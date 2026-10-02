import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, Server, ApiError } from '../api';
import { StatusBadge } from '../App';
import { useAuth } from '../auth';

export default function ServerDetail() {
  const { id } = useParams();
  const sid = Number(id);
  const navigate = useNavigate();
  const { can } = useAuth();
  const [server, setServer] = useState<Server | null>(null);
  const [error, setError] = useState('');
  const [testResult, setTestResult] = useState('');
  const [pendingKey, setPendingKey] = useState<{ algorithm: string; fingerprint: string; public_key: string } | null>(null);
  const [hostKeys, setHostKeys] = useState<{ id: number; algorithm: string; fingerprint: string; state: string }[]>([]);

  async function load() {
    try {
      setServer(await api.server(sid));
      const hk = await api.hostKeys(sid);
      setHostKeys(hk.host_keys);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }

  useEffect(() => {
    load();
  }, [sid]);

  async function test() {
    setTestResult('');
    setPendingKey(null);
    try {
      const res = await api.testServer(sid);
      setTestResult(`${res.status}${res.detail ? ` (${res.detail})` : ''}${res.latency_ms ? ` — ${res.latency_ms}ms` : ''}`);
      if (res.host_key) {
        setPendingKey(res.host_key);
      }
      await load();
    } catch (err) {
      setTestResult(err instanceof ApiError ? err.message : 'Test failed');
    }
  }

  async function trust(fp: { algorithm: string; fingerprint: string; public_key: string }) {
    if (!confirm(`Trust host key ${fp.fingerprint}? Only do this if you verified it out of band.`)) return;
    try {
      await api.trustHostKey(sid, fp);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Trust failed');
    }
  }

  async function remove() {
    if (!confirm(`Delete server ${server?.name}? This removes the panel configuration, not the remote machine.`)) return;
    try {
      await api.deleteServer(sid);
      navigate('/servers');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Delete failed');
    }
  }

  if (!server) return <div>{error || 'Loading…'}</div>;

  return (
    <div>
      <div className="row">
        <h2>{server.name}</h2>
        <StatusBadge status={server.status} />
      </div>
      {error && <div className="alert bad">{error}</div>}
      <div className="row">
        <Link className="btn" to={`/servers/${sid}/terminal`}>Terminal</Link>
        <Link className="btn" to={`/servers/${sid}/files`}>Files</Link>
        <Link className="btn" to={`/servers/${sid}/metrics`}>Metrics</Link>
        <Link className="btn" to={`/servers/${sid}/processes`}>Processes</Link>
        {can('servers.connect') && <button onClick={test}>Test connection</button>}
        {can('servers.delete') && <button className="danger" onClick={remove}>Delete</button>}
      </div>
      {testResult && <p>{testResult}</p>}
      {pendingKey && (
        <div className="alert warn">
          Unknown host key <span className="mono">{pendingKey.fingerprint}</span> ({pendingKey.algorithm}).
          Only trust it if you verified it out of band.{' '}
          <button onClick={() => trust(pendingKey)}>Trust this key</button>
        </div>
      )}
      <div className="card">
        <dl className="kv">
          <dt>Address</dt><dd>{server.username}@{server.host}:{server.port}</dd>
          <dt>Auth</dt><dd>{server.auth_method} · {server.host_key_policy}</dd>
          <dt>OS</dt><dd>{[server.os, server.kernel, server.arch].filter(Boolean).join(' ') || '—'}</dd>
          <dt>Status</dt><dd>{server.status_detail || '—'}</dd>
          <dt>Tags</dt><dd>{server.tags.join(', ') || '—'}</dd>
          <dt>Notes</dt><dd>{server.notes || '—'}</dd>
        </dl>
      </div>
      <div className="card">
        <h3>Host keys</h3>
        {hostKeys.length === 0 ? (
          <p className="dim">No pinned keys. Connect once to see the presented key, then trust it explicitly.</p>
        ) : (
          <table>
            <thead><tr><th>Algorithm</th><th>Fingerprint</th><th>State</th></tr></thead>
            <tbody>
              {hostKeys.map((k) => (
                <tr key={k.id}><td className="mono">{k.algorithm}</td><td className="mono">{k.fingerprint}</td><td>{k.state}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
