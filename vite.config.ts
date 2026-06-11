import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const aegisTarget = env.VITE_AEGIS_PROXY_TARGET || 'https://aegis-dev.preprodcxr.co';
  const internalApiKey = env.VITE_AEGIS_INTERNAL_API_KEY || '';

  // Emit one line per proxied request so the dev terminal shows exactly where
  // each browser request is being forwarded to. This makes the proxy behaviour
  // obvious (the browser always sees localhost:5173; Vite is the one talking to
  // aegis-core).
  const log = (direction: '→' | '←', from: string, to: string, status?: number) => {
    const arrow = direction === '→' ? '→' : '←';
    const suffix = status !== undefined ? ` [HTTP ${status}]` : '';
    console.log(`[aegis-proxy] ${arrow} ${from}  ${arrow}  ${to}${suffix}`);
  };

  return {
    plugins: [react()],
    server: {
      proxy: {
        // Public aegis-core endpoints: /api/v1/{country}/public/*, /api/v1/users/me,
        // /api/v1/auth/*, etc. The browser calls localhost:5173/api/...; Vite forwards
        // to {aegisTarget}/api/... keeping the path intact (aegis-core is already rooted
        // at /api/v1).
        '/api': {
          target: aegisTarget,
          changeOrigin: true,
          secure: true,
          configure: (proxy) => {
            proxy.on('proxyReq', (_proxyReq, req) => {
              log('→', req.url ?? '<unknown>', `${aegisTarget}${req.url ?? ''}`);
            });
            proxy.on('proxyRes', (proxyRes, req) => {
              log('←', req.url ?? '<unknown>', `${aegisTarget}${req.url ?? ''}`, proxyRes.statusCode);
            });
          },
        },
        // Internal endpoints (introspection). The browser calls /internal/*; Vite rewrites
        // the path to /api/v1/internal/* and injects X-Internal-API-Key so the secret
        // never reaches the browser bundle.
        '/internal': {
          target: aegisTarget,
          changeOrigin: true,
          secure: true,
          rewrite: (path) => path.replace(/^\/internal/, '/api/v1/internal'),
          configure: (proxy) => {
            proxy.on('proxyReq', (proxyReq, req) => {
              if (internalApiKey) {
                proxyReq.setHeader('X-Internal-API-Key', internalApiKey);
              }
              proxyReq.setHeader('X-Caller-Service', 'aegis-demo-ui');
              // `req.url` is the POST-rewrite URL (Vite applies the rewrite before
              // firing proxyReq). Concatenate as-is so we don't double-prefix.
              log('→', req.url ?? '<unknown>', `${aegisTarget}${req.url ?? ''}`);
            });
            proxy.on('proxyRes', (proxyRes, req) => {
              log('←', req.url ?? '<unknown>', `${aegisTarget}${req.url ?? ''}`, proxyRes.statusCode);
            });
          },
        },
      },
    },
  };
});
