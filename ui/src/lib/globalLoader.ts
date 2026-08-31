// Global full-screen loader engine. Reference-counted so overlapping
// consumers (auth refresh, route chunk loading, user-triggered actions)
// share one continuous overlay instead of stacking separate loaders.
let loaderCount = 0;
let hideTimeout: ReturnType<typeof setTimeout> | null = null;
let listeners: ((visible: boolean) => void)[] = [];

export const globalLoader = {
  show: () => {
    if (hideTimeout) {
      clearTimeout(hideTimeout);
      hideTimeout = null;
    }
    loaderCount++;
    if (loaderCount === 1) {
      listeners.forEach((l) => l(true));
    }
  },
  hide: () => {
    loaderCount = Math.max(0, loaderCount - 1);
    if (loaderCount === 0) {
      // 50ms debounce prevents blinking when handing off between consumers.
      hideTimeout = setTimeout(() => {
        hideTimeout = null;
        listeners.forEach((l) => l(false));
      }, 50);
    }
  },
};

export function subscribeLoader(listener: (visible: boolean) => void): () => void {
  listeners.push(listener);
  return () => {
    listeners = listeners.filter((l) => l !== listener);
  };
}
