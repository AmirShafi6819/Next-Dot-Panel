import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api, MetricPoint, DiskUsage, ApiError } from '../api';

function fmtBytes(v?: number): string {
  if (v === undefined) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let n = v;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(1)} ${units[i]}`;
}

function Line({ values, max, unit }: { values: (number | undefined)[]; max?: number; unit: string }) {
  const nums = values.map((v) => (v === undefined ? null : v));
  const peak = max ?? Math.max(1, ...nums.filter((n): n is number => n !== null));
  const W = 600;
  const H = 120;
  const pts = nums
    .map((v, i) => {
      if (v === null) return null;
      const x = (i / Math.max(1, nums.length - 1)) * W;
      const y = H - (v / peak) * (H - 10) - 5;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .filter((p): p is string => p !== null)
    .join(' ');
  return (
    <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`chart ${unit}`}>
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

export default function MetricsPage() {
  const { id } = useParams();
  const sid = Number(id);
  const [latest, setLatest] = useState<MetricPoint | null>(null);
  const [disks, setDisks] = useState<DiskUsage[]>([]);
  const [history, setHistory] = useState<MetricPoint[]>([]);
  const [range, setRange] = useState('1h');
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await api.metricsLatest(sid);
      setLatest(res.sample ?? null);
      setDisks(res.filesystems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }, [sid]);

  const loadHistory = useCallback(async () => {
    const hours: Record<string, number> = { '5m': 1 / 12, '15m': 0.25, '1h': 1, '6h': 6, '24h': 24 };
    const to = new Date();
    const from = new Date(to.getTime() - (hours[range] ?? 1) * 3600 * 1000);
    try {
      const res = await api.metricsRange(sid, from.toISOString(), to.toISOString());
      setHistory(res.samples);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'History failed');
    }
  }, [sid, range]);

  useEffect(() => {
    load();
    loadHistory();
    const t = setInterval(() => {
      load();
    }, 30000);
    return () => clearInterval(t);
  }, [load, loadHistory]);

  async function collect() {
    try {
      await api.metricsCollect(sid);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Collect failed');
    }
  }

  return (
    <div>
      <div className="row">
        <h2>Metrics</h2>
        <button onClick={collect}>Collect now</button>
        <select value={range} onChange={(e) => setRange(e.target.value)} style={{ width: 'auto' }}>
          {['5m', '15m', '1h', '6h', '24h'].map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>
      </div>
      {error && <div className="alert bad">{error}</div>}
      {latest ? (
        <div className="grid">
          <div className="card"><h3>CPU</h3><p>{latest.cpu_pct !== undefined ? `${latest.cpu_pct.toFixed(1)} %` : 'Unavailable'}</p></div>
          <div className="card"><h3>Load</h3><p>{[latest.load1, latest.load5, latest.load15].map((v) => (v === undefined ? '—' : v.toFixed(2))).join(' / ')}</p></div>
          <div className="card"><h3>Memory</h3><p>{latest.mem_available !== undefined && latest.mem_total ? `${fmtBytes(latest.mem_total - latest.mem_available)} / ${fmtBytes(latest.mem_total)}` : 'Unavailable'}</p></div>
          <div className="card"><h3>Swap</h3><p>{latest.swap_used !== undefined ? fmtBytes(latest.swap_used) : 'Unavailable'}</p></div>
          <div className="card"><h3>Network</h3><p>↓ {fmtBytes(latest.net_rx_bytes)} · ↑ {fmtBytes(latest.net_tx_bytes)}</p></div>
          <div className="card"><h3>Uptime</h3><p>{latest.uptime_secs !== undefined ? `${Math.floor(latest.uptime_secs / 86400)}d ${Math.floor((latest.uptime_secs % 86400) / 3600)}h` : 'Unavailable'}</p></div>
        </div>
      ) : (
        <div className="empty">No metrics yet. Collect a sample to begin.</div>
      )}
      {history.length > 0 && (
        <div className="card">
          <h3>CPU history ({range})</h3>
          <Line values={history.map((s) => s.cpu_pct)} max={100} unit="%" />
        </div>
      )}
      {disks.length > 0 && (
        <div className="card">
          <h3>Filesystems</h3>
          <table>
            <thead><tr><th>Mount</th><th>Device</th><th>Used</th><th>Total</th><th>Use%</th></tr></thead>
            <tbody>
              {disks.map((d) => (
                <tr key={d.mount_point}>
                  <td className="mono">{d.mount_point}</td>
                  <td className="mono dim">{d.device}</td>
                  <td>{fmtBytes(d.used_bytes)}</td>
                  <td>{fmtBytes(d.total_bytes)}</td>
                  <td>{d.used_pct !== undefined ? `${d.used_pct.toFixed(1)}%` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
