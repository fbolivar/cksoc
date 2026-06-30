/**
 * Setup de pruebas: define variables de entorno minimas para que
 * config/env.ts valide correctamente en CI/local sin un .env real.
 * Se ejecuta ANTES de importar cualquier modulo de la app.
 */
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-0123456789abcdef';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgres://test:test@localhost:5432/test';
