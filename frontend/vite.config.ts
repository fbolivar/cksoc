import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// En desarrollo, /api se redirige al backend Express (puerto 4000).
// En produccion, Nginx hace ese proxy.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:4000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
