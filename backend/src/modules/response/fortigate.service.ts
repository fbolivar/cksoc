/**
 * Cliente del FortiGate para la respuesta de la app. Usa el endpoint de
 * CUARENTENA (`/api/v2/monitor/user/banned`) — el MISMO mecanismo ya validado
 * por el Active-Response del manager (`fortigate-ban.py`): banear = add_users,
 * desbloquear = clear_users, listar = GET. No toca políticas ni objetos cmdb.
 *
 * Bloquear   = POST /user/banned/add_users  { ip_addresses:[ip], expiry:N }
 * Desbloquear= POST /user/banned/clear_users{ ip_addresses:[ip] }
 * listBlocked= GET  /user/banned            (solo lectura)
 *
 * La validación de lista blanca se hace ANTES, en response.service.ts.
 */
import axios, { type AxiosInstance } from 'axios';
import https from 'node:https';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

let client: AxiosInstance | null = null;

export function isFortigateConfigured(): boolean {
  return Boolean(env.FORTIGATE_HOST && env.FORTIGATE_API_TOKEN);
}

function fg(): AxiosInstance {
  if (client) return client;
  if (!isFortigateConfigured()) {
    throw new HttpError(503, 'FortiGate no configurado (define FORTIGATE_HOST y FORTIGATE_API_TOKEN)');
  }
  client = axios.create({
    baseURL: `https://${env.FORTIGATE_HOST}/api/v2/monitor`,
    headers: { Authorization: `Bearer ${env.FORTIGATE_API_TOKEN}` },
    timeout: 12_000,
    httpsAgent: new https.Agent({ rejectUnauthorized: env.FORTIGATE_TLS_REJECT_UNAUTHORIZED }),
  });
  return client;
}

/** Traduce errores del FortiGate a HttpError legibles (nunca falla en silencio). */
function mapFgError(err: unknown, context: string): never {
  if (err instanceof HttpError) throw err;
  const e = err as { code?: string; response?: { status: number; data?: unknown } };
  if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT' || e.code === 'EHOSTUNREACH' || e.code === 'ENOTFOUND') {
    throw new HttpError(502, `No se pudo conectar al FortiGate (${context}). Verifica FORTIGATE_HOST y la red.`);
  }
  if (e.response?.status === 401 || e.response?.status === 403) {
    throw new HttpError(502, `El FortiGate rechazó la autenticación/permisos (${context}). Revisa el token y sus trusted-hosts.`);
  }
  throw new HttpError(502, `Error en el FortiGate (${context}, HTTP ${e.response?.status ?? '?'})`);
}

interface BannedResult { results?: { ip_address?: string; srcip?: string }[] }

function parseBanned(data: BannedResult): { ip: string; name: string }[] {
  const rows = data?.results ?? [];
  return rows
    .map((r) => String(r.ip_address ?? r.srcip ?? '').trim())
    .filter((ip) => ip.length > 0)
    .map((ip) => ({ ip, name: ip }));
}

/** Lee las IPs en cuarentena (SOLO LECTURA). */
export async function listBlocked(): Promise<{ ip: string; name: string }[]> {
  try {
    const { data } = await fg().get<BannedResult>('/user/banned');
    return parseBanned(data);
  } catch (err) {
    mapFgError(err, 'listar cuarentena');
  }
}

/** Verifica conexión y permisos en SOLO LECTURA (no modifica nada). */
export async function verifyConnection(): Promise<{ group: string; count: number }> {
  try {
    const { data } = await fg().get<BannedResult>('/user/banned');
    return { group: 'quarantine', count: parseBanned(data).length };
  } catch (err) {
    mapFgError(err, 'verificar conexión');
  }
}

/** Añade una IP a la cuarentena del FortiGate (con expiración de seguridad). */
export async function blockIP(ip: string): Promise<void> {
  try {
    await fg().post('/user/banned/add_users', { ip_addresses: [ip], expiry: env.FORTIGATE_BAN_SECONDS });
  } catch (err) {
    mapFgError(err, 'bloquear IP');
  }
}

/** Quita una IP de la cuarentena (revertir manualmente antes de que expire). */
export async function unblockIP(ip: string): Promise<void> {
  try {
    await fg().post('/user/banned/clear_users', { ip_addresses: [ip] });
  } catch (err) {
    mapFgError(err, 'desbloquear IP');
  }
}
