import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

function buildProxy(target: string) {
  const proxyPaths = ['/v1', '/assets', '/dashboard', '/healthz', '/readyz', '/block'];

  return Object.fromEntries(
    proxyPaths.map((path) => [
      path,
      {
        target,
        changeOrigin: true,
        secure: false,
      },
    ]),
  );
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiOrigin = env.SAFE_ZONE_UI_API_ORIGIN || 'http://127.0.0.1:8080';

  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: buildProxy(apiOrigin),
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
      target: 'es2022',
    },
  };
});
