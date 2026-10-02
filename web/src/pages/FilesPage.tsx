import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api, FileEntry, ApiError } from '../api';

function parentOf(p: string): string {
  if (p === '/' || !p.includes('/', 1)) return '/';
  return p.slice(0, p.lastIndexOf('/')) || '/';
}

function join(a: string, b: string): string {
  return (a === '/' ? '' : a) + '/' + b;
}

export default function FilesPage() {
  const { id } = useParams();
  const sid = Number(id);
  const [path, setPath] = useState('/');
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showHidden, setShowHidden] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await api.files(sid, path);
      setEntries(res.entries);
      setError('');
      setSelected(new Set());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Load failed');
    }
  }, [sid, path]);

  useEffect(() => {
    load();
  }, [load]);

  function toggle(name: string) {
    const next = new Set(selected);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setSelected(next);
  }

  async function mkdir() {
    const name = prompt('Directory name:');
    if (!name) return;
    try {
      await api.mkdir(sid, join(path, name));
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  async function rename(entry: FileEntry) {
    const to = prompt('New name:', entry.name);
    if (!to || to === entry.name) return;
    try {
      await api.rename(sid, entry.path, join(path, to));
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  async function remove() {
    const paths = entries.filter((e) => selected.has(e.name)).map((e) => e.path);
    if (paths.length === 0) return;
    if (!confirm(`Delete ${paths.length} item(s)?`)) return;
    try {
      await api.deleteFiles(sid, paths, true);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  async function upload(files: FileList | null) {
    if (!files) return;
    for (const f of Array.from(files)) {
      try {
        const res = await fetch(`/api/v1/servers/${sid}/files/content?path=${encodeURIComponent(join(path, f.name))}`, {
          method: 'PUT',
          credentials: 'include',
          body: f,
        });
        if (!res.ok) throw new Error(`Upload failed (${res.status})`);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Upload failed');
        return;
      }
    }
    await load();
  }

  async function extract(entry: FileEntry) {
    const dest = prompt('Extract to directory:', path);
    if (!dest) return;
    try {
      await api.extract(sid, entry.path, dest);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Extract failed');
    }
  }

  const visible = showHidden ? entries : entries.filter((e) => !e.name.startsWith('.'));

  return (
    <div>
      <h2>Files <span className="dim mono">{path}</span></h2>
      {error && <div className="alert bad">{error}</div>}
      <div className="row">
        <button onClick={() => setPath(parentOf(path))} disabled={path === '/'}>Up</button>
        <button onClick={mkdir}>New directory</button>
        <button onClick={remove} disabled={selected.size === 0} className="danger">Delete selected</button>
        <label className="row" style={{ gap: 4 }}>
          <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} style={{ width: 'auto' }} />
          Hidden
        </label>
        <label className="btn">Upload
          <input type="file" multiple hidden onChange={(e) => upload(e.target.files)} />
        </label>
      </div>
      <div className="card">
        {visible.length === 0 ? (
          <div className="empty">Empty directory.</div>
        ) : (
          <table>
            <thead><tr><th></th><th>Name</th><th>Size</th><th>Mode</th><th>Modified</th><th></th></tr></thead>
            <tbody>
              {visible.map((e) => (
                <tr key={e.path}>
                  <td><input type="checkbox" checked={selected.has(e.name)} onChange={() => toggle(e.name)} style={{ width: 'auto' }} /></td>
                  <td>
                    {e.is_dir ? (
                      <a href="#" onClick={(ev) => { ev.preventDefault(); setPath(e.path); }}>{e.name}/</a>
                    ) : (
                      <span className="mono">{e.name}</span>
                    )}
                  </td>
                  <td>{e.is_dir ? '—' : e.size.toLocaleString()}</td>
                  <td className="mono">{e.mode}</td>
                  <td className="dim">{new Date(e.modified_at).toLocaleString()}</td>
                  <td>
                    <span className="row">
                      {!e.is_dir && <a className="btn" href={api.downloadUrl(sid, e.path)}>Download</a>}
                      <button onClick={() => rename(e)}>Rename</button>
                      {!e.is_dir && /\.(tar\.gz|tgz|tar|zip)$/i.test(e.name) && (
                        <button onClick={() => extract(e)}>Extract</button>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
