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
let fullClient: AxiosInstance | null = null;

export function isFortigateConfigured(): boolean {
  return Boolean(env.FORTIGATE_HOST && env.FORTIGATE_API_TOKEN);
}

/** Cliente con baseURL en la raíz de la API (para leer /api/v2/monitor y /api/v2/cmdb). */
function fgFull(): AxiosInstance {
  if (fullClient) return fullClient;
  if (!isFortigateConfigured()) throw new HttpError(503, 'FortiGate no configurado (define FORTIGATE_HOST y FORTIGATE_API_TOKEN)');
  fullClient = axios.create({
    baseURL: `https://${env.FORTIGATE_HOST}`,
    headers: { Authorization: `Bearer ${env.FORTIGATE_API_TOKEN}` },
    timeout: 20_000,
    httpsAgent: new https.Agent({ rejectUnauthorized: env.FORTIGATE_TLS_REJECT_UNAUTHORIZED }),
  });
  return fullClient;
}

/** GET genérico a la API del FortiGate (ruta absoluta, p.ej. `/api/v2/cmdb/system/global`).
 *  SOLO LECTURA. axios descomprime gzip automáticamente. Para auditoría de postura. */
export async function fgGet<T = unknown>(path: string): Promise<T> {
  try {
    const { data } = await fgFull().get<T>(path);
    return data;
  } catch (err) {
    mapFgError(err, `GET ${path}`);
  }
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

interface BannedRow { ip_address?: string; srcip?: string; expires?: number; created?: number; source?: string }
interface BannedResult { results?: BannedRow[] }

export interface BannedEntry { ip: string; name: string; expiresAt: number | null; permanent: boolean }

function parseBanned(data: BannedResult): BannedEntry[] {
  const rows = data?.results ?? [];
  return rows
    .map((r) => ({ ip: String(r.ip_address ?? r.srcip ?? '').trim(), expires: r.expires }))
    .filter((r) => r.ip.length > 0)
    // Sin `expires` (ban "Administrative"/expiry=0) = permanente; con `expires` = temporal.
    .map((r) => ({ ip: r.ip, name: r.ip, expiresAt: r.expires ? r.expires * 1000 : null, permanent: !r.expires }));
}

/** Lee las IPs en cuarentena (SOLO LECTURA). */
export async function listBlocked(): Promise<BannedEntry[]> {
  try {
    const { data } = await fg().get<BannedResult>('/user/banned');
    return parseBanned(data);
  } catch (err) {
    mapFgError(err, 'listar cuarentena');
  }
}

export interface FgInterface {
  name: string; alias: string | null; ip: string | null; link: boolean;
  speedMbps: number; txBytes: number; rxBytes: number; txErrors: number; rxErrors: number;
}

/** Lee el estado y contadores de las interfaces (SOLO LECTURA). Para NPM. */
export async function fetchInterfaces(): Promise<FgInterface[]> {
  try {
    const { data } = await fg().get<{ results?: Record<string, {
      name?: string; alias?: string; ip?: string; link?: boolean; speed?: number;
      tx_bytes?: number; rx_bytes?: number; tx_errors?: number; rx_errors?: number;
    }> }>('/system/interface?scope=global');
    const results = data?.results ?? {};
    return Object.entries(results).map(([key, i]) => ({
      name: i.name ?? key,
      alias: i.alias ?? null,
      ip: i.ip ?? null,
      link: Boolean(i.link),
      speedMbps: Number(i.speed ?? 0),
      txBytes: Number(i.tx_bytes ?? 0),
      rxBytes: Number(i.rx_bytes ?? 0),
      txErrors: Number(i.tx_errors ?? 0),
      rxErrors: Number(i.rx_errors ?? 0),
    }));
  } catch (err) {
    mapFgError(err, 'leer interfaces');
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

/**
 * Añade una IP a la cuarentena del FortiGate.
 * `expirySeconds`: duración del ban; 0 = PERMANENTE (ban "Administrative" sin
 * expiración). Si no se indica, usa el default de seguridad (FORTIGATE_BAN_SECONDS).
 */
export async function blockIP(ip: string, expirySeconds?: number): Promise<void> {
  const expiry = expirySeconds === undefined ? env.FORTIGATE_BAN_SECONDS : expirySeconds;
  try {
    await fg().post('/user/banned/add_users', { ip_addresses: [ip], expiry });
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
