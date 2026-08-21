/**
 * Licenciamiento HexWatch. Los códigos de activación se firman con una llave
 * Ed25519 PRIVADA que solo tiene el proveedor; la app lleva embebida la PÚBLICA
 * y solo puede VERIFICAR (no fabricar). Un código lleva cliente + fechas de
 * emisión/expiración. Sin licencia válida y vigente, el gate bloquea la API.
 *
 * Anti-manipulación de reloj: se guarda el último instante "confiable" visto;
 * si alguien atrasa el reloj del servidor para revivir una licencia vencida, se
 * usa el máximo(now, last_seen) → no se puede des-expirar retrasando la hora.
 */
import crypto from 'node:crypto';
import { query } from '../../config/db';

// Llave PÚBLICA de verificación (la privada NUNCA se despliega).
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0yCxygPqLEYEhy0OJFSVbxp0M6F+4t64u0B7G97A6yA=
-----END PUBLIC KEY-----`;

export interface LicensePayload { v: number; customer: string; licenseId: string; issuedAt: string; expiresAt: string }
export type LicenseState = 'active' | 'expired' | 'none' | 'invalid';
export interface LicenseStatus {
  state: LicenseState;
  message: string;
  customer?: string;
  issuedAt?: string;
  expiresAt?: string;
  daysLeft?: number;
  clockWarning?: boolean;
}

function b64u(s: string): Buffer { return Buffer.from(s, 'base64url'); }

/** Verifica firma + estructura de un código (NO comprueba vigencia). */
export function verifyCode(code: string): { ok: boolean; payload?: LicensePayload; reason?: string } {
  try {
    const parts = String(code || '').trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'HEXW1') return { ok: false, reason: 'Formato de código inválido.' };
    const bytes = b64u(parts[1]);
    const sig = b64u(parts[2]);
    if (!crypto.verify(null, bytes, PUBLIC_KEY, sig)) {
      return { ok: false, reason: 'Firma inválida: el código no fue emitido por el proveedor.' };
    }
    const payload = JSON.parse(bytes.toString('utf8')) as LicensePayload;
    if (!payload?.expiresAt || !payload?.issuedAt || !payload?.customer) return { ok: false, reason: 'Código incompleto.' };
    return { ok: true, payload };
  } catch {
    return { ok: false, reason: 'No se pudo leer el código.' };
  }
}

let cache: { at: number; data: LicenseStatus } | null = null;
const TTL = 30_000;
export function invalidateLicenseCache(): void { cache = null; }

export async function getLicenseStatus(): Promise<LicenseStatus> {
  if (cache && Date.now() - cache.at < TTL) return cache.data;
  const data = await computeStatus();
  cache = { at: Date.now(), data };
  return data;
}

async function computeStatus(): Promise<LicenseStatus> {
  const rows = await query<{ code: string }>('SELECT code FROM license WHERE id = 1');
  if (!rows[0]) return { state: 'none', message: 'No hay licencia activada.' };

  const v = verifyCode(rows[0].code);
  if (!v.ok || !v.payload) return { state: 'invalid', message: v.reason ?? 'Licencia inválida.' };

  // Reloj confiable (anti-rollback).
  const now = Date.now();
  const st = await query<{ ts: string }>("SELECT extract(epoch from last_seen_at) * 1000 AS ts FROM license_state WHERE id = 1");
  const lastSeen = st[0] ? Number(st[0].ts) : 0;
  const trusted = Math.max(now, lastSeen);
  const clockWarning = now < lastSeen - 6 * 3600_000;
  if (trusted > lastSeen) {
    await query(
      `INSERT INTO license_state (id, last_seen_at) VALUES (1, to_timestamp($1))
         ON CONFLICT (id) DO UPDATE SET last_seen_at = to_timestamp($1)`,
      [Math.floor(trusted / 1000)]
    );
  }

  const exp = new Date(v.payload.expiresAt).getTime();
  const daysLeft = Math.max(0, Math.ceil((exp - trusted) / 86400_000));
  const base = { customer: v.payload.customer, issuedAt: v.payload.issuedAt, expiresAt: v.payload.expiresAt, daysLeft, clockWarning };
  if (trusted > exp) {
    return { state: 'expired', message: `Licencia vencida el ${v.payload.expiresAt.slice(0, 10)}.`, ...base };
  }
  return { state: 'active', message: `Licencia activa · ${daysLeft} día(s) restantes.`, ...base };
}

/** Activa un código (solo si firma válida y no vencido). Reinicia la línea de tiempo confiable. */
export async function activateLicense(code: string, userId: string): Promise<LicenseStatus> {
  const v = verifyCode(code);
  if (!v.ok || !v.payload) return { state: 'invalid', message: v.reason ?? 'Código inválido.' };
  if (new Date(v.payload.expiresAt).getTime() <= Date.now()) {
    return { state: 'expired', message: 'El código ya está vencido; solicita uno nuevo al proveedor.', customer: v.payload.customer, expiresAt: v.payload.expiresAt, daysLeft: 0 };
  }
  await query(
    `INSERT INTO license (id, code, customer, license_id, issued_at, expires_at, activated_at, activated_by)
       VALUES (1, $1, $2, $3, $4, $5, now(), $6)
       ON CONFLICT (id) DO UPDATE SET code=$1, customer=$2, license_id=$3, issued_at=$4, expires_at=$5, activated_at=now(), activated_by=$6`,
    [code.trim(), v.payload.customer, v.payload.licenseId, v.payload.issuedAt, v.payload.expiresAt, userId]
  );
  await query(
    `INSERT INTO license_state (id, last_seen_at) VALUES (1, now())
       ON CONFLICT (id) DO UPDATE SET last_seen_at = now()`
  );
  invalidateLicenseCache();
  return getLicenseStatus();
}
