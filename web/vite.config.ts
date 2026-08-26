import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // uvicorn is run with --port 8010 (see README); the client sends
    // relative /api/* paths (see src/api/client.ts's empty BASE_URL) so
    // this proxy is what makes dev-mode work without CORS at all — CORS
    // middleware in keyring/main.py exists only for the odd case of
    // running the dev server against a differently-hosted API.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8010',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
})
