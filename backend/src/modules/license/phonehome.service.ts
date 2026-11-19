/**
 * Phone-home del lado HexWatch: consulta periódica a CrubolOS (la autoridad de
 * licencias) para saber si la licencia sigue vigente, fue renovada o revocada.
 *
 * Principio NO AFECTAR LA OPERACIÓN:
 *  - Una caída de red / error NUNCA bloquea: se sigue con la licencia local.
 *  - Solo un token `revoked` VÁLIDO y FIRMADO bloquea (y es pegajoso).
 *  - `renewed` adopta solo el código nuevo (HEXW1) → renovar/ajustar remoto.
 *  - Anti-replay: se ignora cualquier token cuyo issuedAt no sea más nuevo que
 *    el último aplicado (no se puede reinyectar un "active" viejo sobre un corte).
 *
 * El token de estado (HEXWS1.<json>.<firma>) se verifica con la MISMA llave
 * pública embebida (license.service PUBLIC_KEY).
 */
import crypto from 'node:crypto';
import cron from 'node-cron';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import {
  PUBLIC_KEY,
  verifyCode,
  activateLicense,
  markRevoked,
  getLastStatusAt,
  recordStatusSeen,
  invalidateLicenseCache,
} from './license.service';

type StatusPayload = {
  v: number;
  typ: string;
  status: 'active' | 'renewed' | 'revoked' | 'unknown';
  licenseId: string;
  code?: string;
  issuedAt: string;
  ttlSeconds: number;
};

function cfg() {
  return {
    url: (process.env.CRUBOLOS_PHONEHOME_URL || '').trim(),
    token: (process.env.CRUBOLOS_PHONEHOME_TOKEN || '').trim(),
    cronExpr: process.env.CRUBOLOS_PHONEHOME_CRON || '0 */6 * * *',
    tz: process.env.CRUBOLOS_PHONEHOME_TZ || process.env.DIGEST_TZ || 'America/Bogota',
  };
}

/** Verifica un token de estado HEXWS1 con la llave pública embebida. */
export function verifyStatusToken(token: string): { ok: boolean; payload?: StatusPayload; reason?: string } {
  try {
    const parts = String(token || '').trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'HEXWS1') return { ok: false, reason: 'Formato de token inválido.' };
    const bytes = Buffer.from(parts[1], 'base64url');
    const sig = Buffer.from(parts[2], 'base64url');
    if (!crypto.verify(null, bytes, PUBLIC_KEY, sig)) return { ok: false, reason: 'Firma de token inválida.' };
    const payload = JSON.parse(bytes.toString('utf8')) as StatusPayload;
    if (payload?.typ !== 'status' || !payload?.status || !payload?.issuedAt) return { ok: false, reason: 'Token incompleto.' };
    return { ok: true, payload };
  } catch {
    return { ok: false, reason: 'No se pudo leer el token.' };
  }
}

/** Una pasada del phone-home. Nunca lanza: cualquier fallo se traga (no bloquea). */
export async function runPhoneHome(): Promise<void> {
  const { url, token } = cfg();
  if (!url || !token) return; // feature apagada
  try {
    const rows = await query<{ license_id: string | null }>('SELECT license_id FROM license WHERE id = 1');
    const licenseId = rows[0]?.license_id;
    if (!licenseId) { logger.info('phone-home: sin licencia local aún; nada que consultar.'); return; }

    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 15_000);
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({ licenseId }),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(to);
    }
    if (!res.ok) { logger.warn({ status: res.status }, 'phone-home: respuesta no OK; se mantiene la licencia local.'); return; }

    const body = (await res.json()) as { token?: string };
    const v = verifyStatusToken(body?.token || '');
    if (!v.ok || !v.payload) { logger.warn({ reason: v.reason }, 'phone-home: token inválido; se ignora.'); return; }
    const p = v.payload;

    // El token debe ser PARA nuestra licencia.
    if (p.licenseId && p.licenseId !== licenseId) { logger.warn('phone-home: token para otra licencia; se ignora.'); return; }

    // Anti-replay: solo aceptar tokens más nuevos que el último aplicado.
    const issuedMs = new Date(p.issuedAt).getTime();
    const last = await getLastStatusAt();
    if (Number.isFinite(issuedMs) && issuedMs <= last) { logger.info('phone-home: token no más nuevo que el último visto; se ignora (anti-replay).'); return; }

    switch (p.status) {
      case 'revoked': {
        await markRevoked();
        logger.warn('phone-home: el proveedor REVOCÓ la licencia → servicio bloqueado.');
        break;
      }
      case 'renewed': {
        if (!p.code) { logger.warn('phone-home: renewed sin código; se ignora.'); break; }
        const vc = verifyCode(p.code);
        if (!vc.ok || !vc.payload) { logger.warn({ reason: vc.reason }, 'phone-home: código renovado inválido; se ignora.'); break; }
        if (new Date(vc.payload.expiresAt).getTime() <= Date.now()) { logger.warn('phone-home: código renovado ya vencido; se ignora.'); break; }
        await activateLicense(p.code, null);
        logger.info({ expiresAt: vc.payload.expiresAt }, 'phone-home: licencia RENOVADA y adoptada automáticamente.');
        break;
      }
      case 'active':
        logger.info('phone-home: licencia vigente (active).');
        break;
      case 'unknown':
      default:
        logger.info('phone-home: estado desconocido en el proveedor; se mantiene la licencia local.');
        break;
    }
    // Solo avanzar la marca anti-replay si el token fue aceptado/aplicado.
    if (Number.isFinite(issuedMs)) await recordStatusSeen(p.issuedAt);
    invalidateLicenseCache();
  } catch (e) {
    logger.warn({ err: e instanceof Error ? e.message : String(e) }, 'phone-home: error (se mantiene la licencia local, sin bloquear).');
  }
}

/** Programa el phone-home (cada 6 h por defecto) + una pasada inicial a los 30 s. */
export function startPhoneHomeScheduler(): void {
  const { url, token, cronExpr, tz } = cfg();
  if (!url || !token) {
    logger.info('phone-home: APAGADO (faltan CRUBOLOS_PHONEHOME_URL / CRUBOLOS_PHONEHOME_TOKEN).');
    return;
  }
  if (!cron.validate(cronExpr)) {
    logger.error({ cronExpr }, 'phone-home: expresión cron inválida; no se programa.');
    return;
  }
  cron.schedule(cronExpr, () => { void runPhoneHome(); }, { timezone: tz });
  setTimeout(() => { void runPhoneHome(); }, 30_000);
  logger.info({ cronExpr, tz, url }, 'phone-home: programado.');
}
