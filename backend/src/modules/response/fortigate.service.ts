/**
 * Cliente del FortiGate (API REST cmdb) para gestionar SOLO el address group
 * de bloqueo (FORTIGATE_BLOCKLIST_GROUP). La app no toca nada mas.
 *
 * Bloquear  = crear objeto address "SOC_BL_<ip>" (ip/32) y anadirlo al grupo.
 * Desbloquear = quitar el miembro del grupo y borrar el objeto address.
 * listBlocked = leer los miembros del grupo (solo lectura).
 *
 * Toda validacion de lista blanca se hace en whitelist.ts ANTES de llamar aqui.
 */
import axios, { type AxiosInstance } from 'axios';
import https from 'node:https';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

const ADDR_PREFIX = 'SOC_BL_';
const VDOM = 'root';

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
    baseURL: `https://${env.FORTIGATE_HOST}/api/v2/cmdb`,
    headers: { Authorization: `Bearer ${env.FORTIGATE_API_TOKEN}` },
    params: { vdom: VDOM },
    timeout: 10_000,
    httpsAgent: new https.Agent({ rejectUnauthorized: env.FORTIGATE_TLS_REJECT_UNAUTHORIZED }),
  });
  return client;
}

const addrName = (ip: string) => `${ADDR_PREFIX}${ip}`;

/** Traduce errores del FortiGate a HttpError legibles (nunca falla en silencio). */
function mapFgError(err: unknown, context: string): never {
  if (err instanceof HttpError) throw err;
  const e = err as { code?: string; response?: { status: number; data?: unknown } };
  if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT' || e.code === 'EHOSTUNREACH' || e.code === 'ENOTFOUND') {
    throw new HttpError(502, `No se pudo conectar al FortiGate (${context}). Verifica FORTIGATE_HOST y la red.`);
  }
  if (e.response?.status === 401 || e.response?.status === 403) {
    throw new HttpError(502, `El FortiGate rechazo la autenticacion/permisos (${context}). Revisa el token y su perfil.`);
  }
  throw new HttpError(502, `Error en el FortiGate (${context}, HTTP ${e.response?.status ?? '?'})`);
}

/** Lee los miembros del grupo de bloqueo (SOLO LECTURA). */
export async function listBlocked(): Promise<{ ip: string; name: string }[]> {
  const group = env.FORTIGATE_BLOCKLIST_GROUP;
  try {
    const { data } = await fg().get(`/firewall/addrgrp/${encodeURIComponent(group)}`);
    const members: { name: string }[] = data?.results?.[0]?.member ?? [];
    return members
      .filter((m) => m.name.startsWith(ADDR_PREFIX))
      .map((m) => ({ ip: m.name.slice(ADDR_PREFIX.length), name: m.name }));
  } catch (err) {
    mapFgError(err, 'listar grupo');
  }
}

/** Verifica conexion y permisos en SOLO LECTURA (no modifica nada). */
export async function verifyConnection(): Promise<{ group: string; count: number }> {
  const group = env.FORTIGATE_BLOCKLIST_GROUP;
  try {
    const { data } = await fg().get(`/firewall/addrgrp/${encodeURIComponent(group)}`);
    const members: unknown[] = data?.results?.[0]?.member ?? [];
    return { group, count: members.length };
  } catch (err) {
    mapFgError(err, 'verificar conexion');
  }
}

/**
 * Anade una IP al grupo de bloqueo usando operaciones QUIRURGICAS sobre el
 * miembro individual (endpoints hijo). NO reescribe la lista completa, por lo
 * que NUNCA puede afectar a los demas miembros del grupo.
 * NO valida lista blanca (eso se hace antes, en response.service).
 */
export async function blockIP(ip: string): Promise<void> {
  const group = env.FORTIGATE_BLOCKLIST_GROUP;
  const ignore = (codes: number[]) => (e: unknown) => {
    const s = (e as { response?: { status: number } }).response?.status;
    if (s && codes.includes(s)) return; // duplicado/ya existe -> idempotente
    throw e;
  };
  try {
    // 1) Crear el objeto address /32 (idempotente: 500 = ya existe)
    await fg()
      .post('/firewall/address', {
        name: addrName(ip),
        type: 'ipmask',
        subnet: `${ip} 255.255.255.255`,
        comment: 'Bloqueo SOC PNNC (Wazuh)',
      })
      .catch(ignore([500]));

    // 2) Anadirlo como miembro del grupo (sin tocar los demas miembros)
    await fg()
      .post(`/firewall/addrgrp/${encodeURIComponent(group)}/member`, { name: addrName(ip) })
      .catch(ignore([500])); // 500 = ya es miembro
  } catch (err) {
    mapFgError(err, 'bloquear IP');
  }
}

/**
 * Quita una IP del grupo (revertir) borrando solo SU miembro, y elimina su
 * objeto address. Tampoco toca a los demas miembros.
 */
export async function unblockIP(ip: string): Promise<void> {
  const group = env.FORTIGATE_BLOCKLIST_GROUP;
  try {
    // 1) Quitar el miembro del grupo (404 = no estaba -> ok)
    await fg()
      .delete(`/firewall/addrgrp/${encodeURIComponent(group)}/member/${encodeURIComponent(addrName(ip))}`)
      .catch((e) => {
        const s = (e as { response?: { status: number } }).response?.status;
        if (s !== 404) throw e;
      });
    // 2) Borrar el objeto address (si falla, no es critico)
    await fg()
      .delete(`/firewall/address/${encodeURIComponent(addrName(ip))}`)
      .catch(() => undefined);
  } catch (err) {
    mapFgError(err, 'desbloquear IP');
  }
}
