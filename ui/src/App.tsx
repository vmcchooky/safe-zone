import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import { AppShell } from './components/AppShell';
import { LoginScreen } from './components/LoginScreen';
import { useAuth } from './auth/AuthProvider';
import './app.css';

const AnalysisPage = lazy(() =>
  import('./routes/analysis/AnalysisPage').then((module) => ({ default: module.AnalysisPage })),
);
const SettingsPage = lazy(() =>
  import('./routes/settings/SettingsPage').then((module) => ({ default: module.SettingsPage })),
);
const TelemetryPage = lazy(() =>
  import('./routes/telemetry/TelemetryPage').then((module) => ({ default: module.TelemetryPage })),
);
const EndpointsPage = lazy(() =>
  import('./routes/EndpointsPage').then((module) => ({ default: module.EndpointsPage })),
);
const OverridesPage = lazy(() =>
  import('./routes/OverridesPage').then((module) => ({ default: module.OverridesPage })),
);
const UserReportsPage = lazy(() =>
  import('./routes/UserReportsPage').then((module) => ({ default: module.UserReportsPage })),
);
const SystemPage = lazy(() =>
  import('./routes/SystemPage').then((module) => ({ default: module.SystemPage })),
);

function LoadingScreen() {
  return (
    <div className="auth-screen">
      <div className="auth-card auth-card-compact">
        <div className="auth-kicker">Safe Zone</div>
        <h1>Syncing operator session</h1>
        <p>Checking the current dashboard session before loading the React workspace.</p>
        <div className="auth-loading-bar" aria-hidden="true">
          <span />
        </div>
      </div>
    </div>
  );
}

function RouteLoading() {
  return (
    <div className="surface-card route-loading-card">
      <div className="auth-kicker">Route chunk</div>
      <h2>Loading workspace panel</h2>
      <p>The selected React route is streaming in with its own chunk and dependencies.</p>
      <div className="auth-loading-bar" aria-hidden="true">
        <span />
      </div>
    </div>
  );
}

function ProtectedRoutes() {
  const { session } = useAuth();

  return (
    <AppShell session={session!}>
      <Suspense fallback={<RouteLoading />}>
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
  const { loading, session, error } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (!session) {
    return <LoginScreen initialError={error} />;
  }

  return <ProtectedRoutes />;
}
