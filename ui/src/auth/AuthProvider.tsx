import {
  createContext,
  useCallback,
  startTransition,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { ApiError, apiFetch, apiJSON, messageFromError } from '../lib/api';
import type { AuthSession } from '../lib/types';

interface AuthContextValue {
  error: string | null;
  loading: boolean;
  session: AuthSession | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshSession = useCallback(async () => {
    try {
      const minDelay = new Promise(res => setTimeout(res, 1200));
      const req = apiFetch<AuthSession>('/v1/auth/session');
      const [nextSession] = await Promise.all([req, minDelay]);
      startTransition(() => {
        setSession(nextSession);
        setError(null);
        setLoading(false);
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        startTransition(() => {
          setSession(null);
          setError(null);
          setLoading(false);
        });
        return;
      }

      startTransition(() => {
        setSession(null);
        setError(messageFromError(err));
        setLoading(false);
      });
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const login = async (username: string, password: string) => {
    setError(null);
    const minDelay = new Promise(res => setTimeout(res, 1200));
    const req = apiJSON<{ status: string }>('/v1/auth/login', { username, password }, { method: 'POST' });
    await Promise.all([req, minDelay]);
    
    startTransition(() => {
      setLoading(true);
    });
    await refreshSession();
  };

  const logout = async () => {
    try {
      await apiFetch<{ status: string }>('/v1/auth/logout', { method: 'POST' });
    } catch (err) {
      setError(messageFromError(err));
    } finally {
      startTransition(() => {
        setSession(null);
      });
    }
  };

  const value = useMemo<AuthContextValue>(
    () => ({
      error,
      loading,
      session,
      login,
      logout,
      refreshSession,
    }),
    [error, loading, refreshSession, session],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return value;
}
