// Central API client. All requests send cookies, parse the standard error
// envelope, and raise ApiError with a stable machine-readable code.

export class ApiError extends Error {
  code: string;
  status: number;
  requestId: string;
  constructor(code: string, message: string, status: number, requestId: string) {
    super(message);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'include', ...init });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = body?.error;
    throw new ApiError(
      err?.code ?? 'unknown_error',
      err?.message ?? `Request failed (${res.status})`,
      res.status,
      err?.request_id ?? '',
    );
  }
  return body as T;
}

function json<T>(path: string, method: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export interface User {
  id: number;
  username: string;
  display_name: string;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at?: string;
  created_at: string;
}

export interface Me extends User {
  permissions: string[];
  default_credentials_warning: boolean;
}

export interface Session {
  id: string;
  ip?: string;
  user_agent?: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

export interface Role {
  id: number;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
}

export interface PermissionInfo {
  name: string;
  description: string;
}

export interface Server {
  id: number;
  name: string;
  target_type: string;
  host?: string;
  port?: number;
  username?: string;
  auth_method: string;
  host_key_policy: string;
  tags: string[];
  notes?: string;
  is_favourite: boolean;
  status: string;
  status_detail?: string;
  os?: string;
  kernel?: string;
  arch?: string;
  last_seen_at?: string;
  last_error_at?: string;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface FileEntry {
  name: string;
  path: string;
  type: 'file' | 'dir' | 'symlink';
  size: number;
  mode: string;
  owner?: string;
  group?: string;
  is_dir: boolean;
  is_symlink: boolean;
  link_target?: string;
  modified_at: string;
}

export interface MetricPoint {
  timestamp: string;
  cpu_pct?: number;
  load1?: number;
  load5?: number;
  load15?: number;
  mem_total?: number;
  mem_available?: number;
  mem_cached?: number;
  swap_total?: number;
  swap_used?: number;
  net_rx_bytes?: number;
  net_tx_bytes?: number;
  uptime_secs?: number;
}

export interface DiskUsage {
  mount_point: string;
  device: string;
  fstype: string;
  total_bytes?: number;
  used_bytes?: number;
  avail_bytes?: number;
  used_pct?: number;
  timestamp: string;
}

export interface RemoteProcess {
  pid: number;
  name: string;
  state: string;
  username: string;
  cpu_pct?: number;
  memory_bytes?: number;
  command?: string;
}

export interface AuditEvent {
  id: number;
  timestamp: string;
  actor_id?: number;
  actor_name: string;
  action: string;
  target: string;
  server_id?: number;
  server_name?: string;
  result: string;
  request_id?: string;
  ip?: string;
  user_agent?: string;
  metadata?: Record<string, unknown>;
}

export const api = {
  login: (username: string, password: string) =>
    json<{ user: User; session: Session; csrf_token: string; default_credentials_warning: boolean }>(
      '/api/v1/auth/login', 'POST', { username, password },
    ),
  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),
  me: () => request<{ user: User; permissions: string[]; default_credentials_warning: boolean }>('/api/v1/auth/me'),
  changePassword: (current_password: string, new_password: string) =>
    json<void>('/api/v1/auth/password', 'POST', { current_password, new_password }),
  reauth: (password: string) => json<{ reauth_at: string }>('/api/v1/auth/reauth', 'POST', { password }),
  sessions: () => request<{ sessions: Session[] }>('/api/v1/auth/sessions'),
  revokeSession: (id: string) => request<void>(`/api/v1/auth/sessions/${id}`, { method: 'DELETE' }),

  servers: (params?: Record<string, string>) => {
    const q = new URLSearchParams(params).toString();
    return request<{ servers: Server[]; total: number; page: number; per_page: number }>(
      `/api/v1/servers${q ? `?${q}` : ''}`,
    );
  },
  server: (id: number) => request<Server>(`/api/v1/servers/${id}`),
  createServer: (body: Record<string, unknown>) => json<Server>('/api/v1/servers', 'POST', body),
  updateServer: (id: number, body: Record<string, unknown>) =>
    json<Server>(`/api/v1/servers/${id}`, 'PATCH', body),
  deleteServer: (id: number) => request<void>(`/api/v1/servers/${id}`, { method: 'DELETE' }),
  testServer: (id: number) =>
    json<{ status: string; latency_ms?: number; detail?: string; host_key?: { algorithm: string; fingerprint: string; public_key: string } }>(
      `/api/v1/servers/${id}/test`, 'POST',
    ),
  hostKeys: (id: number) =>
    request<{ host_keys: { id: number; algorithm: string; fingerprint: string; state: string; first_seen: string }[] }>(
      `/api/v1/servers/${id}/hostkeys`,
    ),
  trustHostKey: (id: number, body: { algorithm: string; fingerprint: string; public_key: string }) =>
    json<void>(`/api/v1/servers/${id}/hostkeys/trust`, 'POST', body),

  files: (id: number, path: string) =>
    request<{ path: string; entries: FileEntry[] }>(`/api/v1/servers/${id}/files?path=${encodeURIComponent(path)}`),
  fileStat: (id: number, path: string) =>
    request<FileEntry>(`/api/v1/servers/${id}/files/stat?path=${encodeURIComponent(path)}`),
  downloadUrl: (id: number, path: string) =>
    `/api/v1/servers/${id}/files/content?path=${encodeURIComponent(path)}`,
  mkdir: (id: number, path: string) => json<void>(`/api/v1/servers/${id}/files/mkdir`, 'POST', { path }),
  rename: (id: number, from: string, to: string) =>
    json<void>(`/api/v1/servers/${id}/files/rename`, 'POST', { from, to }),
  deleteFiles: (id: number, paths: string[], recursive: boolean) =>
    json<void>(`/api/v1/servers/${id}/files/delete`, 'POST', { paths, recursive }),
  extract: (id: number, archive: string, destination: string) =>
    json<void>(`/api/v1/servers/${id}/files/extract`, 'POST', { archive, destination }),

  metricsLatest: (id: number) =>
    request<{ sample?: MetricPoint; filesystems: DiskUsage[] }>(`/api/v1/servers/${id}/metrics/latest`),
  metricsRange: (id: number, from: string, to: string) =>
    request<{ samples: MetricPoint[] }>(
      `/api/v1/servers/${id}/metrics?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    ),
  metricsCollect: (id: number) => request<void>(`/api/v1/servers/${id}/metrics/collect`, { method: 'POST' }),

  processes: (id: number) =>
    request<{ processes: RemoteProcess[] }>(`/api/v1/servers/${id}/processes`),
  signalProcess: (id: number, pid: number, force: boolean) =>
    json<void>(`/api/v1/servers/${id}/processes/${pid}/signal`, 'POST', { force }),

  users: () => request<{ users: (User & { roles: Role[]; version: number })[]; total: number }>('/api/v1/users'),
  createUser: (body: Record<string, unknown>) => json<User>('/api/v1/users', 'POST', body),
  updateUser: (id: number, body: Record<string, unknown>) =>
    json<User>(`/api/v1/users/${id}`, 'PATCH', body),
  deleteUser: (id: number) => request<void>(`/api/v1/users/${id}`, { method: 'DELETE' }),
  resetPassword: (id: number, new_password: string) =>
    json<void>(`/api/v1/users/${id}/reset-password`, 'POST', { new_password }),
  userLoginHistory: (id: number) =>
    request<{ attempts: { id: number; username: string; ip: string; success: boolean; failure_reason?: string; timestamp: string }[] }>(
      `/api/v1/users/${id}/login-history`,
    ),

  roles: () => request<{ roles: Role[] }>('/api/v1/roles'),
  createRole: (body: Record<string, unknown>) => json<Role>('/api/v1/roles', 'POST', body),
  updateRole: (id: number, body: Record<string, unknown>) =>
    json<Role>(`/api/v1/roles/${id}`, 'PATCH', body),
  deleteRole: (id: number) => request<void>(`/api/v1/roles/${id}`, { method: 'DELETE' }),
  permissions: () => request<{ permissions: PermissionInfo[] }>('/api/v1/permissions'),

  audit: (params?: Record<string, string>) => {
    const q = new URLSearchParams(params).toString();
    return request<{ events: AuditEvent[]; total: number }>(`/api/v1/audit${q ? `?${q}` : ''}`);
  },
};

export function wsUrl(path: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${path}`;
}
