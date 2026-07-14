import { useEffect } from 'react';

export function useAntiInspect() {
  useEffect(() => {
    const handleContextMenu = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      // Allow context menu only on inputs, textareas, and contenteditable
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        return;
      }
      e.preventDefault();
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      // F12
      if (e.key === 'F12' || e.keyCode === 123) {
        e.preventDefault();
        return;
      }
      
      if (e.ctrlKey || e.metaKey) {
        // Ctrl+U (View Source)
        if (e.key === 'u' || e.key === 'U' || e.keyCode === 85) {
          e.preventDefault();
          return;
        }
        // Ctrl+Shift+I / J / C (DevTools)
        if (e.shiftKey) {
          const key = e.key.toLowerCase();
          if (key === 'i' || key === 'j' || key === 'c' || e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67) {
            e.preventDefault();
            return;
          }
        }
      }
    };

    document.addEventListener('contextmenu', handleContextMenu);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('contextmenu', handleContextMenu);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);
}
