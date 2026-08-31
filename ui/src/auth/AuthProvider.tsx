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
import { preloadAnalysisRoute } from '../routes/lazyRoutes';
import type { AuthSession } from '../lib/types';

interface AuthContextValue {
  error: string | null;
  loading: boolean;
  session: AuthSession | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: (options?: { minDelayMs?: number }) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// Single source of truth for the intentional minimum loader display time.
// It is consumed once per loading sequence — never stacked on top of a
// caller that already waited. 2.2s keeps the Moody Dog scene transition
// smooth while the Analysis chunk preloads in parallel.
const MIN_LOADER_DURATION_MS = 2200;

const minLoaderDelay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const preloadBackgroundImage = () =>
  new Promise<void>((resolve) => {
    if (typeof window === 'undefined') {
      resolve();
      return;
    }
    const img = new Image();
    img.src = '/app-background.avif?v=1';
    img.onload = () => resolve();
    img.onerror = () => resolve();
  });

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshSession = useCallback(async (options?: { minDelayMs?: number }) => {
    try {
      // Prepare the default landing route's static chunk in parallel with
      // session verification. Static module fetch only — no protected API,
      // never rejects, and not an authorization check of any kind.
      const analysisChunk = preloadAnalysisRoute();
      const bgImage = preloadBackgroundImage();
      const req = apiFetch<AuthSession>('/v1/auth/session');
      const [nextSession] = await Promise.all([
        req,
        minLoaderDelay(options?.minDelayMs ?? MIN_LOADER_DURATION_MS),
        bgImage,
      ]);
      if (!nextSession || typeof nextSession !== 'object' || Array.isArray(nextSession)) {
        throw new Error('The Safe Zone API returned an invalid session response. Check the API origin and restart the UI after changing it.');
      }
      // Keep the single continuous loader until the landing module is ready
      // to paint, so the overlay never hides and re-shows.
      await analysisChunk;
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
    setLoading(true);

    try {
      // Preload the Analysis chunk and app background image alongside the auth request
      // and the single intentional minimum loader duration — one wait, one loader chain.
      const analysisChunk = preloadAnalysisRoute();
      const bgImage = preloadBackgroundImage();
      const req = apiJSON<{ status: string }>('/v1/auth/login', { username, password }, { method: 'POST' });
      await Promise.all([req, minLoaderDelay(MIN_LOADER_DURATION_MS), analysisChunk, bgImage]);
      // Session already covered the minimum delay above; verify at the
      // server without stacking a second wait onto the same sequence.
      await refreshSession({ minDelayMs: 0 });
    } catch (err) {
      startTransition(() => {
        setSession(null);
        setError(messageFromError(err));
        setLoading(false);
      });
      throw err;
    }
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
