import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { wsUrl } from '../api';

export default function TerminalPage() {
  const { id } = useParams();
  const ref = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState('connecting…');

  useEffect(() => {
    const term = new Terminal({ cursorBlink: true, fontSize: 14 });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(ref.current!);
    fit.fit();

    const ws = new WebSocket(wsUrl(`/api/v1/servers/${id}/terminal`));
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => setStatus('connected');
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === 'exit') {
            setStatus(`shell exited (${msg.data})`);
            term.writeln(`\r\n[session ended: exit ${msg.data}]`);
          } else if (msg.type === 'error') {
            setStatus(`error: ${msg.data}`);
          }
        } catch {
          term.write(ev.data);
        }
      } else {
        term.write(new Uint8Array(ev.data));
      }
    };
    ws.onclose = () => setStatus((s) => (s.startsWith('shell exited') ? s : 'disconnected'));
    ws.onerror = () => setStatus('connection error');

    const dataDisp = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }));
      }
    });
    const onResize = () => {
      fit.fit();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    };
    window.addEventListener('resize', onResize);

    return () => {
      window.removeEventListener('resize', onResize);
      dataDisp.dispose();
      try {
        ws.send(JSON.stringify({ type: 'close' }));
      } catch {
        /* already gone */
      }
      ws.close();
      term.dispose();
    };
  }, [id]);

  return (
    <div>
      <h2>Terminal <span className="dim">— server {id}</span></h2>
      <p className="dim">{status}</p>
      <div className="terminal-box" ref={ref} />
    </div>
  );
}
