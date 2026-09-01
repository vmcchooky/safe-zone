import React, { useLayoutEffect, useState } from 'react';

import { globalLoader } from './globalLoader';

const staleChunkReloadKey = 'safe-zone:stale-chunk-reload';

function isDynamicImportFailure(error: unknown) {
  const message = error instanceof Error ? error.message : String(error ?? '');
  return /dynamically imported module|module script|failed to fetch/i.test(message);
}

function reloadOnceForStaleChunk(error: unknown) {
  if (typeof window === 'undefined' || !isDynamicImportFailure(error)) return false;

  try {
    const marker = window.sessionStorage.getItem(staleChunkReloadKey);
    if (marker === window.location.pathname) return false;
    window.sessionStorage.setItem(staleChunkReloadKey, window.location.pathname);
    window.location.reload();
    return true;
  } catch {
    return false;
  }
}

// Minimal structural view of the DotLottie instance the <dotlottie-wc>
// custom element exposes. Event names verified against the installed
// @lottiefiles/dotlottie-web EventType union ('load' | 'loadError' | ...);
// the custom element itself dispatches no DOM events of its own.
interface DotLottieInstance {
  isLoaded?: boolean;
  addEventListener(type: 'load' | 'loadError', listener: () => void): void;
  removeEventListener(type: 'load' | 'loadError', listener: () => void): void;
}

export interface LazyRoute<T extends React.ComponentType<any>> {
  Component: T;
  /**
   * Preload the route's static chunk. Shares the same cache/pending promise
   * as the rendered component, never rejects, and touches no API endpoint —
   * it is a static-module fetch only, not authorization.
   */
  preload: () => Promise<void>;
}

export function createLazyRoute<T extends React.ComponentType<any>>(
  factory: () => Promise<T>,
): LazyRoute<T> {
  let CachedComponent: T | null = null;
  let pending: Promise<T> | null = null;

  const load = (): Promise<T> => {
    if (CachedComponent) return Promise.resolve(CachedComponent);
    if (!pending) {
      pending = factory()
        .then((component) => {
          CachedComponent = component;
          return component;
        })
        .finally(() => {
          pending = null;
        });
    }
    return pending;
  };

  const preload = (): Promise<void> => load().then(
    () => undefined,
    () => undefined,
  );

  function AsyncWrapper(props: any) {
    const [Component, setComponent] = useState<T | null>(() => CachedComponent);
    const [loadError, setLoadError] = useState<unknown>(null);

    useLayoutEffect(() => {
      if (Component) {
        // Clear the marker only when the route that failed has actually
        // mounted. A different route may preload successfully during auth;
        // clearing there would turn a persistent failure into a reload loop.
        if (typeof window !== 'undefined' && window.sessionStorage.getItem(staleChunkReloadKey) === window.location.pathname) {
          window.sessionStorage.removeItem(staleChunkReloadKey);
        }
        return;
      }
      if (loadError) return;

      // Chunk already prepared (e.g. preloaded while the login loader was
      // running): mount synchronously so the overlay never hides and
      // re-shows, and the global loader is not touched a second time.
      if (CachedComponent) {
        setComponent(() => CachedComponent);
        return;
      }

      let cancelled = false;
      let loaderFinished = false;
      globalLoader.show();

      const finishLoader = () => {
        if (!loaderFinished) {
          loaderFinished = true;
          globalLoader.hide();
        }
      };

      void load()
        .then((LoadedComponent) => {
          if (!cancelled) setComponent(() => LoadedComponent);
        })
        .catch((error) => {
          if (!cancelled && !reloadOnceForStaleChunk(error)) setLoadError(error);
        })
        .finally(finishLoader);

      return () => {
        cancelled = true;
        finishLoader();
      };
    }, [Component, loadError]);

    if (loadError) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
          <p className="text-slate-700" role="alert">
            This page could not be loaded. Check your connection and try again.
          </p>
          {/* The browser memoizes a failed dynamic import for the lifetime of
              the document, so re-importing cannot succeed — reloading is the
              only honest recovery. The session cookie survives the reload and
              the server re-verifies it. */}
          <button
            type="button"
            className="rounded-2xl bg-sky-600 px-5 py-2.5 font-semibold text-white shadow-sm transition hover:bg-sky-700"
            onClick={() => window.location.reload()}
          >
            Retry
          </button>
        </div>
      );
    }

    if (!Component) {
      // Empty container while loading; the global loader handles the overlay.
      return <div className="min-h-screen" />;
    }

    return <Component {...props} />;
  }

  return { Component: AsyncWrapper as T, preload };
}
