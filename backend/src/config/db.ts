/**
 * Pool de conexiones a PostgreSQL (datos propios de la app).
 */
import { Pool } from 'pg';
import { env } from './env';
import { logger } from './logger';

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

// Error a nivel de pool (p. ej. PostgreSQL se reinicia por una actualizacion y
// mata las conexiones ociosas). El pool se reconecta solo; registramos un
// mensaje COMPACTO en vez del objeto de conexion completo, para no inundar el
// log con cientos de lineas por un evento transitorio.
pool.on('error', (err) => {
  logger.warn({ err: err.message }, 'Error transitorio en el pool de PostgreSQL (se reconecta solo)');
});

/** Helper tipado para queries. */
export async function query<T = unknown>(
  text: string,
  params?: unknown[]
): Promise<T[]> {
  const res = await pool.query(text, params as never[]);
  return res.rows as T[];
}

/** Verifica la conexion (usado por /health). */
export async function pingDb(): Promise<boolean> {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}
