import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { setWasmUrl } from '@lottiefiles/dotlottie-wc';

import moodyDogLoader from './assets/moody-dog.lottie';
import dotLottieWasm from '@lottiefiles/dotlottie-web/dotlottie-player.wasm?url';
import { AppShell } from './components/AppShell';
import { LoginScreen } from './components/LoginScreen';
import { useAuth } from './auth/AuthProvider';
import { useAntiInspect } from './hooks/useAntiInspect';
import { subscribeLoader, globalLoader } from './lib/globalLoader';
import {
  AnalysisPage,
  EndpointsPage,
  OverridesPage,
  SettingsPage,
  SystemPage,
  TelemetryPage,
  UserReportsPage,
} from './routes/lazyRoutes';
import './app.css';

// Keep the renderer local so Moody Dog works when the browser cannot reach a CDN.
setWasmUrl(dotLottieWasm);

export { globalLoader };

// How long the player gets to load the local asset and render its first
// frame before the loader gives up on the animation and falls back to a
// static, motionless placeholder.
const ANIMATION_READY_TIMEOUT_MS = 4000;

// Minimal structural view of the DotLottie instance the <dotlottie-wc>
// custom element exposes. The element dispatches no DOM events itself;
// these are the real event names from the installed dotlottie-web core.
interface DotLottieInstance {
  isLoaded?: boolean;
  addEventListener(type: 'load' | 'loadError', listener: () => void): void;
  removeEventListener(type: 'load' | 'loadError', listener: () => void): void;
}

type LoaderAnimState = 'animation-pending' | 'animation-ready' | 'fallback';

function usePrefersReducedMotion() {
  const [reducedMotion, setReducedMotion] = useState(() => (
    typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  ));

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handleChange = () => setReducedMotion(mediaQuery.matches);
    handleChange();
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  return reducedMotion;
}

export function ScreenLoader({ forceVisible = false }: { forceVisible?: boolean }) {
  const [visible, setVisible] = useState(false);
  const isVisible = forceVisible || visible;
  const reducedMotion = usePrefersReducedMotion();
  const [animState, setAnimState] = useState<LoaderAnimState>(() => (
    typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
      ? 'fallback'
      : 'animation-pending'
  ));
  const animationRef = useRef<(HTMLElement & { dotLottie?: DotLottieInstance | null }) | null>(null);

  useEffect(() => subscribeLoader(setVisible), []);

  // Each new overlay appearance retries the animation from scratch, and a
  // fresh appearance after a previous fallback gets a new chance to animate.
  useLayoutEffect(() => {
    if (!isVisible) return;
    setAnimState(reducedMotion ? 'fallback' : 'animation-pending');
  }, [isVisible, reducedMotion]);

  // Drive the fallback exclusively from real player signals:
  // - 'load'  → the local .lottie asset parsed and the player is rendering.
  // - 'loadError' → asset fetch/parse or player failure.
  // - bounded timeout → player never became ready.
  // With prefers-reduced-motion the animation is never mounted at all.
  useEffect(() => {
    if (!isVisible || reducedMotion || animState !== 'animation-pending') return;

    let cancelled = false;
    let attached: DotLottieInstance | null = null;
    let retryFrames = 0;

    const markReady = () => {
      if (!cancelled) setAnimState('animation-ready');
    };
    const markFallback = () => {
      if (!cancelled) setAnimState('fallback');
    };

    const tryAttach = () => {
      const instance = animationRef.current?.dotLottie ?? null;
      if (!instance || attached === instance) return Boolean(attached);
      attached = instance;
      instance.addEventListener('load', markReady);
      instance.addEventListener('loadError', markFallback);
      if (instance.isLoaded) markReady();
      return true;
    };

    if (!tryAttach()) {
      // The instance is created synchronously on connect; retry across a
      // few frames only to absorb custom-element upgrade timing.
      const retryAttach = () => {
        if (cancelled || tryAttach()) return;
        retryFrames += 1;
        if (retryFrames < 20) requestAnimationFrame(retryAttach);
      };
      requestAnimationFrame(retryAttach);
    }

    const timeoutId = setTimeout(markFallback, ANIMATION_READY_TIMEOUT_MS);

    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
      if (attached) {
        attached.removeEventListener('load', markReady);
        attached.removeEventListener('loadError', markFallback);
      }
    };
  }, [isVisible, reducedMotion, animState]);

  if (!isVisible) return null;

  return (
    <div className="app-loader-backdrop is-visible" role="status" aria-label="Loading Safe Zone">
      <div className={`app-loader is-${animState}`} aria-hidden="true">
        {!reducedMotion && animState !== 'fallback' && React.createElement('dotlottie-wc', {
          ref: animationRef,
          'data-testid': 'moody-dog-loader',
          src: moodyDogLoader,
          autoplay: true,
          loop: true,
        })}
        {animState === 'fallback' && (
          <div className="app-loader-fallback" data-testid="moody-dog-fallback">
            <svg viewBox="0 0 64 64" className="app-loader-fallback-paw" aria-hidden="true">
              <ellipse cx="32" cy="41" rx="13" ry="10" />
              <ellipse cx="15" cy="26" rx="5.5" ry="7.5" transform="rotate(-22 15 26)" />
              <ellipse cx="26.5" cy="18" rx="5.5" ry="7.5" transform="rotate(-7 26.5 18)" />
              <ellipse cx="37.5" cy="18" rx="5.5" ry="7.5" transform="rotate(7 37.5 18)" />
              <ellipse cx="49" cy="26" rx="5.5" ry="7.5" transform="rotate(22 49 26)" />
            </svg>
          </div>
        )}
      </div>
    </div>
  );
}

function ProtectedRoutes() {
  const { session } = useAuth();

  return (
    <AppShell session={session!}>
      <Routes>
        <Route path="/" element={<Navigate to="/analysis" replace />} />
        <Route path="/analysis" element={<AnalysisPage />} />
        <Route path="/telemetry" element={<TelemetryPage />} />
        <Route path="/endpoints" element={<EndpointsPage />} />
        <Route path="/overrides" element={<OverridesPage />} />
        <Route
          path="/reports"
          element={session?.can_mutate ? <UserReportsPage /> : <Navigate to="/analysis" replace />}
        />
        <Route path="/system" element={<SystemPage />} />
        <Route
          path="/settings"
          element={
            session?.can_view_settings ? <SettingsPage /> : <Navigate to="/analysis" replace />
          }
        />
        <Route path="*" element={<Navigate to="/analysis" replace />} />
      </Routes>
    </AppShell>
  );
}

export function App() {
  useAntiInspect();
  const { loading, session, error } = useAuth();

  // Hold a globalLoader reference for the whole auth phase so the overlay
  // stays mounted continuously across the login → protected-route handoff:
  // when `loading` flips to false, this effect's cleanup (a passive effect)
  // runs after the newly mounted route's layout effect has already taken
  // over its own loader reference, so the count never drops to zero in
  // between and the animation never unmounts/remounts mid-handoff.
  useEffect(() => {
    if (!loading) return;
    globalLoader.show();
    return () => globalLoader.hide();
  }, [loading]);

  return (
    <>
      <ScreenLoader forceVisible={loading} />
      {(!loading && !session) ? (
        <LoginScreen initialError={error} />
      ) : (
        (!loading && session) ? <ProtectedRoutes /> : null
      )}
    </>
  );
}
