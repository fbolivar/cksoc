/**
 * Logger estructurado (pino). Salida JSON (ideal para PM2/agregadores).
 * - Nivel segun entorno: silent en tests, info en prod, debug en dev.
 * - Redacta cabeceras sensibles (Authorization/Cookie) de los logs HTTP.
 */
import pino from 'pino';
import { env } from './env';

const level = env.NODE_ENV === 'test' ? 'silent' : env.NODE_ENV === 'production' ? 'info' : 'debug';

export const logger = pino({
  level,
  redact: { paths: ['req.headers.authorization', 'req.headers.cookie'], remove: true },
});
