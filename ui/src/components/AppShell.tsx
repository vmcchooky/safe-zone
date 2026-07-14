import { LogOut, RadioTower, Settings2, Shield, Sparkles, MonitorSmartphone, ShieldAlert, Flag, HardDrive } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import logoImg from '../assets/logo.png';
import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect } from 'react';

import { useAuth } from '../auth/AuthProvider';
import type { AuthSession } from '../lib/types';

const preloadTelemetry = () => import('../routes/telemetry/TelemetryPage');

export function AppShell({
  children,
  session,
}: {
  children: React.ReactNode;
  session: AuthSession;
}) {
  const { logout } = useAuth();
  const [showNav, setShowNav] = useState(true);

  // Auto-hide navigation logic based on mouse movement (macOS Dock style)
  useEffect(() => {
    let hideTimeout: ReturnType<typeof setTimeout>;
    let isVisible = true;

    const handleMouseMove = (e: MouseEvent) => {
      // Check if mouse is in the bottom 160px
      const isNearBottom = window.innerHeight - e.clientY < 160;

      if (isNearBottom) {
        clearTimeout(hideTimeout);
        if (!isVisible) {
          isVisible = true;
          setShowNav(true);
        }
      } else {
        if (isVisible) {
          clearTimeout(hideTimeout);
          // Wait 1.2s before hiding after mouse leaves the bottom area
          hideTimeout = setTimeout(() => {
            isVisible = false;
            setShowNav(false);
          }, 1200);
        }
      }
    };

    window.addEventListener('mousemove', handleMouseMove);
    
    // Initial hide after 2.5 seconds so user knows it's there
    hideTimeout = setTimeout(() => {
      isVisible = false;
      setShowNav(false);
    }, 2500);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      clearTimeout(hideTimeout);
    };
  }, []);

  useEffect(() => {
    const preloadTimer = window.setTimeout(() => {
      void preloadTelemetry();
    }, 800);
    return () => window.clearTimeout(preloadTimer);
  }, []);

  return (
    <div className="shell">
      {/* Top Floating Header for Brand and User Actions */}
      <div className="shell-floating-header">
        <div className="flex items-center" style={{ pointerEvents: 'auto' }}>
          <div className="shrink-0 flex items-center justify-center shadow-sm relative z-10" style={{ width: 76, height: 76, borderRadius: '50%', backgroundColor: '#fff', border: '1px solid rgba(0,0,0,0.06)' }}>
            <img src={logoImg} alt="Logo" style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }} />
          </div>
          <div className="shell-brand relative z-0" style={{ padding: '6px 14px 6px 28px', borderRadius: '0 12px 12px 0', marginLeft: '-20px', backgroundColor: '#fff' }}>
            <div className="shell-brand-copy">
              <strong>Safe Zone</strong>
              <span style={{ fontSize: '0.7rem' }}>Quorix Engine</span>
            </div>
          </div>
        </div>

        <div className="shell-header-actions">
          <div className="shell-badge">
            <Sparkles size={14} />
            <span className="hidden sm:inline">Role </span><strong>{session.role}</strong>
          </div>
          <div className="shell-badge">
            <span className="hidden sm:inline">User </span><strong>{session.username}</strong>
          </div>
          <a className="button-secondary shell-toolbar-button" href="/dashboard" title="Legacy Dashboard">
            Legacy
          </a>
          <button className="button-danger shell-toolbar-button" type="button" onClick={() => void logout()} title="Sign Out">
            <LogOut size={16} />
          </button>
        </div>
      </div>

      <main className="shell-main">
        {session.read_only && session.guest_message ? (
          <div className="shell-banner">{session.guest_message}</div>
        ) : null}
        <div className="shell-content">
          {children}
        </div>
      </main>

      {/* Bottom Floating Dock */}
      <div className="shell-floating-dock-wrapper">
        <AnimatePresence>
          {showNav && (
            <motion.nav 
              className="shell-floating-dock-inner"
              initial={{ y: 100, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: 100, opacity: 0 }}
              transition={{ type: 'spring', stiffness: 260, damping: 20 }}
              aria-label="Workspace routes"
              onMouseEnter={() => setShowNav(true)}
            >
              <NavLink to="/analysis" className={({ isActive }) => isActive ? 'active' : ''}>
                <Shield size={20} />
                <span className="dock-label">Analysis</span>
              </NavLink>
              <NavLink
                to="/telemetry"
                className={({ isActive }) => isActive ? 'active' : ''}
                onPointerEnter={() => void preloadTelemetry()}
                onFocus={() => void preloadTelemetry()}
              >
                <RadioTower size={20} />
                <span className="dock-label">Telemetry</span>
              </NavLink>
              <NavLink to="/endpoints" className={({ isActive }) => isActive ? 'active' : ''}>
                <MonitorSmartphone size={20} />
                <span className="dock-label">Endpoints</span>
              </NavLink>
              <NavLink to="/overrides" className={({ isActive }) => isActive ? 'active' : ''}>
                <ShieldAlert size={20} />
                <span className="dock-label">Overrides</span>
              </NavLink>
              <NavLink to="/reports" className={({ isActive }) => isActive ? 'active' : ''}>
                <Flag size={20} />
                <span className="dock-label">Reports</span>
              </NavLink>
              <NavLink to="/system" className={({ isActive }) => isActive ? 'active' : ''}>
                <HardDrive size={20} />
                <span className="dock-label">System</span>
              </NavLink>
              {session.can_view_settings ? (
                <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
                  <Settings2 size={20} />
                  <span className="dock-label">Settings</span>
                </NavLink>
              ) : null}
            </motion.nav>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
