import { createContext, useCallback, useContext, useEffect, useState, ReactNode } from 'react';
import { api, Me } from './api';

interface AuthState {
  user: Me | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<{ warning: boolean }>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  can: (perm: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await api.me();
      setUser({ ...me.user, permissions: me.permissions, default_credentials_warning: me.default_credentials_warning });
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(
    async (username: string, password: string) => {
      const res = await api.login(username, password);
      await refresh();
      return { warning: res.default_credentials_warning };
    },
    [refresh],
  );

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  const can = useCallback((perm: string) => user?.permissions.includes(perm) ?? false, [user]);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refresh, can }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
