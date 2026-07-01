import { defineConfig } from 'vitest/config';

// Pruebas de integracion contra una BD Postgres real (efimera en CI).
// Requieren DATABASE_URL apuntando a una base desechable.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/integration/**/*.test.ts'],
    setupFiles: ['./test/setup.ts'],
    globalSetup: ['./test/integration/globalSetup.ts'],
    fileParallelism: false, // comparten la misma BD: evita carreras entre archivos
    testTimeout: 20000,
  },
});
