/**
 * Aplica el esquema (schema.sql) a la base de datos.
 * Idempotente: usa CREATE TABLE IF NOT EXISTS y ON CONFLICT DO NOTHING.
 * Uso: npm run migrate
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pool } from '../config/db';

async function main(): Promise<void> {
  const sql = readFileSync(join(__dirname, 'schema.sql'), 'utf-8');
  // eslint-disable-next-line no-console
  console.log('Aplicando esquema a la base de datos...');
  await pool.query(sql);
  console.log('✅ Esquema aplicado correctamente.');
  await pool.end();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('❌ Error aplicando el esquema:', err);
  process.exit(1);
});
