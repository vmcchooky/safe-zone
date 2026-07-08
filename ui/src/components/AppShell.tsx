import { LogOut, RadioTower, Settings2, Shield, Sparkles } from 'lucide-react';
import { NavLink } from 'react-router-dom';

import { useAuth } from '../auth/AuthProvider';
import type { AuthSession } from '../lib/types';

export function AppShell({
  children,
  session,
}: {
  children: React.ReactNode;
  session: AuthSession;
}) {
  const { logout } = useAuth();

  return (
    <div className="shell">
      <header className="shell-header">
        <div className="shell-header-inner">
          <div className="shell-brand">
            <div className="shell-brand-mark">
              <Shield size={20} />
            </div>
            <div className="shell-brand-copy">
              <strong>Safe Zone UI Workspace</strong>
              <span>React sandbox wired to the live Core API contract</span>
            </div>
          </div>

          <div className="shell-header-actions">
            <div className="shell-badge">
              <Sparkles size={14} />
              Role <strong>{session.role}</strong>
            </div>
            <div className="shell-badge">
              User <strong>{session.username}</strong>
            </div>
            <a className="button-secondary shell-toolbar-button" href="/dashboard">
              Open legacy dashboard
            </a>
            <button className="button-danger shell-toolbar-button" type="button" onClick={() => void logout()}>
              <LogOut size={16} />
              Sign out
            </button>
          </div>
        </div>

        <nav className="shell-nav" aria-label="Workspace routes">
          <NavLink to="/telemetry">
            <RadioTower size={16} />
            Telemetry
          </NavLink>
          <NavLink to="/analysis">Analysis</NavLink>
          {session.can_view_settings ? (
            <NavLink to="/settings">
              <Settings2 size={16} />
              Settings
            </NavLink>
          ) : null}
        </nav>
      </header>

      <main className="shell-main">
        {session.read_only && session.guest_message ? (
          <div className="shell-banner">{session.guest_message}</div>
        ) : null}
        {children}
      </main>
    </div>
  );
}
