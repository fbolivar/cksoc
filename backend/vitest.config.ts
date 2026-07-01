import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Solo pruebas unitarias (sin BD). Las de integracion viven en test/integration/.
    include: ['test/*.test.ts'],
    setupFiles: ['./test/setup.ts'],
  },
});
