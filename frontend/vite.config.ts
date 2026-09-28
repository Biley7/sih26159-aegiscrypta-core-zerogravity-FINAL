import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The frontend addresses the API with a same-origin relative base URL, so the dev
// server proxies API traffic to the local backend. This keeps a hardcoded host out
// of the bundle and avoids cross-origin preflights during development.
// Override the target with AEGIS_API_TARGET when the backend runs elsewhere.
const API_TARGET = process.env.AEGIS_API_TARGET || 'http://127.0.0.1:8000';

const apiProxy = {
  '/api': { target: API_TARGET, changeOrigin: true },
  '/health': { target: API_TARGET, changeOrigin: true },
  '/docs': { target: API_TARGET, changeOrigin: true },
  '/redoc': { target: API_TARGET, changeOrigin: true },
  '/openapi.json': { target: API_TARGET, changeOrigin: true },
};

export default defineConfig({
  plugins: [react()],
  server: { proxy: apiProxy },
  preview: { proxy: apiProxy },
});
