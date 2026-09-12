import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

function normalizeBasePath(value: string) {
  const trimmed = value.trim();
  if (trimmed === '' || trimmed === '/') {
    return '/';
  }

  return `/${trimmed.replace(/^\/+|\/+$/g, '')}/`;
}

function buildProxy(target: string) {
  const proxyPaths = ['/v1', '/assets', '/dashboard', '/healthz', '/readyz', '/block', '/metrics'];

  return Object.fromEntries(
    proxyPaths.map((path) => [
      path,
      {
        target,
        changeOrigin: true,
        secure: false,
        headers: {
          Origin: target,
        },
      },
    ]),
  );
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiOrigin = env.SAFE_ZONE_UI_API_ORIGIN || 'http://127.0.0.1:8080';
  const basePath = normalizeBasePath(env.SAFE_ZONE_UI_BASE_PATH || '/app/');

  return {
    base: basePath,
    assetsInclude: ['**/*.lottie'],
    plugins: [react()],
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
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
      // Split heavy vendor libraries out of page chunks: recharts dominates
      // TelemetryPage and framer-motion is shared by the shell and most
      // routes. Shared vendor chunks stay cached across route navigations
      // instead of being duplicated per page.
      rolldownOptions: {
        output: {
          advancedChunks: {
            groups: [
              { name: 'vendor-recharts', test: /node_modules\/recharts/ },
              { name: 'vendor-motion', test: /node_modules\/framer-motion/ },
              {
                name: 'vendor-react',
                test: /node_modules\/(react|react-dom|react-router-dom|scheduler|swr)/,
              },
            ],
          },
        },
      },
    },
  };
});
