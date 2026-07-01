/**
 * Prepara la BD efimera para las pruebas de integracion: aplica schema.sql
 * (idempotente) sobre la base apuntada por DATABASE_URL. Se ejecuta una vez.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';

export default async function setup(): Promise<void> {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL es obligatorio para las pruebas de integracion');
  }
  const schemaPath = fileURLToPath(new URL('../../src/db/schema.sql', import.meta.url));
  const schema = readFileSync(schemaPath, 'utf8');
  const pool = new Pool({ connectionString });
  try {
    await pool.query(schema);
  } finally {
    await pool.end();
  }
}
