import React, { Suspense, useEffect, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import { AppShell } from './components/AppShell';
import { LoginScreen } from './components/LoginScreen';
import { useAuth } from './auth/AuthProvider';
import { useAntiInspect } from './hooks/useAntiInspect';
import './app.css';

// --- Global Loader Engine ---
let loaderCount = 0;
let hideTimeout: any = null;
let listeners: ((visible: boolean) => void)[] = [];

export const globalLoader = {
  show: () => {
    if (hideTimeout) clearTimeout(hideTimeout);
    loaderCount++;
    if (loaderCount === 1) {
      listeners.forEach(l => l(true));
    }
  },
  hide: () => {
    loaderCount = Math.max(0, loaderCount - 1);
    if (loaderCount === 0) {
      // 50ms debounce prevents blinking when handing off between Auth and Route loading
      hideTimeout = setTimeout(() => {
        listeners.forEach(l => l(false));
      }, 50);
    }
  }
};

export function ScreenLoader() {
  const [visible, setVisible] = useState(loaderCount > 0);
  
  useEffect(() => {
    const l = (v: boolean) => setVisible(v);
    listeners.push(l);
    return () => { listeners = listeners.filter(x => x !== l); };
  }, []);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 z-[999] flex items-center justify-center bg-slate-50/80 backdrop-blur-md">
      {React.createElement('dotlottie-wc', {
        src: "https://lottie.host/4d159429-fadb-46ea-8674-69760c81ad64/IRJeMelDRC.lottie",
        style: { width: 450, height: 450 },
        autoplay: true,
        loop: true
      })}
    </div>
  );
}

// --- Custom Async Loader (Bypasses React Suspense to allow immediate URL updates) ---
function lazyWithLoader<T extends React.ComponentType<any>>(factory: () => Promise<{ default: T }>) {
  let CachedComponent: T | null = null;
  let pending: Promise<T> | null = null;

  const load = () => {
    if (CachedComponent) return Promise.resolve(CachedComponent);
    if (!pending) {
      pending = factory()
        .then((moduleExports) => {
          CachedComponent = moduleExports.default;
          return moduleExports.default;
        })
        .finally(() => {
          pending = null;
        });
    }
    return pending;
  };

  return function AsyncWrapper(props: any) {
    const [Component, setComponent] = useState<T | null>(() => CachedComponent);
    const [loadError, setLoadError] = useState<unknown>(null);

    useEffect(() => {
      if (Component) return; // Already loaded from cache

      let cancelled = false;
      let loaderVisible = false;
      let loaderFinished = false;
      const loaderTimer = window.setTimeout(() => {
        loaderVisible = true;
        globalLoader.show();
      }, 160);

      const finishLoader = () => {
        window.clearTimeout(loaderTimer);
        if (loaderVisible && !loaderFinished) {
          loaderFinished = true;
          globalLoader.hide();
        }
      };

      void load()
        .then((LoadedComponent) => {
          if (!cancelled) setComponent(() => LoadedComponent);
        })
        .catch((error) => {
          if (!cancelled) setLoadError(error);
        })
        .finally(finishLoader);

      return () => {
        cancelled = true;
        finishLoader();
      };
    }, [Component]);

    if (loadError) throw loadError;

    if (!Component) {
      // Empty container while loading, global loader handles the visual overlay
      return <div className="min-h-screen" />;
    }

    return <Component {...props} />;
  };
}

const AnalysisPage = lazyWithLoader(() =>
  import('./routes/analysis/AnalysisPage').then((module) => ({ default: module.AnalysisPage })),
);
const SettingsPage = lazyWithLoader(() =>
  import('./routes/settings/SettingsPage').then((module) => ({ default: module.SettingsPage })),
);
const TelemetryPage = lazyWithLoader(() =>
  import('./routes/telemetry/TelemetryPage').then((module) => ({ default: module.TelemetryPage })),
);
const EndpointsPage = lazyWithLoader(() =>
  import('./routes/EndpointsPage').then((module) => ({ default: module.EndpointsPage })),
);
const OverridesPage = lazyWithLoader(() =>
  import('./routes/OverridesPage').then((module) => ({ default: module.OverridesPage })),
);
const UserReportsPage = lazyWithLoader(() =>
  import('./routes/UserReportsPage').then((module) => ({ default: module.UserReportsPage })),
);
const SystemPage = lazyWithLoader(() =>
  import('./routes/SystemPage').then((module) => ({ default: module.SystemPage })),
);

function ProtectedRoutes() {
  const { session } = useAuth();

  return (
    <AppShell session={session!}>
      <Suspense fallback={<div className="min-h-screen bg-transparent" />}>
        <Routes>
          <Route path="/" element={<Navigate to="/analysis" replace />} />
          <Route path="/analysis" element={<AnalysisPage />} />
          <Route path="/telemetry" element={<TelemetryPage />} />
          <Route path="/endpoints" element={<EndpointsPage />} />
          <Route path="/overrides" element={<OverridesPage />} />
          <Route path="/reports" element={<UserReportsPage />} />
          <Route path="/system" element={<SystemPage />} />
          <Route
            path="/settings"
            element={
              session?.can_view_settings ? <SettingsPage /> : <Navigate to="/analysis" replace />
            }
          />
          <Route path="*" element={<Navigate to="/analysis" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}

export function App() {
  useAntiInspect();
  const { loading, session, error } = useAuth();

  useEffect(() => {
    if (loading) {
      globalLoader.show();
      return () => globalLoader.hide();
    }
  }, [loading]);

  return (
    <>
      <ScreenLoader />
      {(!loading && !session) ? (
        <LoginScreen initialError={error} />
      ) : (
        (!loading && session) ? <ProtectedRoutes /> : null
      )}
    </>
  );
}
