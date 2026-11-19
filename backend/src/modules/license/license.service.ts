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
import { writeFileSync } from 'node:fs';
import { query } from '../../config/db';

// Llave PÚBLICA de verificación (la privada NUNCA se despliega). Exportada para
// que el cliente de phone-home verifique los tokens de estado con la MISMA llave.
export const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGd6q1HYle58O+j0GA7yTHxea+mEst8okX5QeNWtM/Zc=
-----END PUBLIC KEY-----`;

export interface LicensePayload { v: number; customer: string; licenseId: string; issuedAt: string; expiresAt: string }
export type LicenseState = 'active' | 'grace' | 'expired' | 'none' | 'invalid' | 'revoked';
export type LicenseUrgency = 'none' | 'info' | 'warn' | 'urgent';
export interface LicenseStatus {
  state: LicenseState;
  message: string;
  customer?: string;
  issuedAt?: string;
  expiresAt?: string;
  daysLeft?: number;
  clockWarning?: boolean;
  renewalWarning?: boolean; // activa pero por vencer (daysLeft <= 30)
  urgency?: LicenseUrgency; // escala del aviso según días restantes
  graceDaysLeft?: number; // días de gracia restantes tras el vencimiento (state='grace')
  snoozedUntil?: string; // si está en el futuro, el frontend oculta el banner de gracia (aviso pospuesto)
}

// Umbral de aviso proactivo: renovar antes de que el gate bloquee todo el SOC.
const RENEWAL_WARN_DAYS = 30;
// Periodo de gracia: tras vencer, el SOC sigue operando N días (con banner rojo)
// para no quedar ciego por un trámite; al agotarse, el gate bloquea (402).
const GRACE_DAYS = 7;
const GRACE_MS = GRACE_DAYS * 86400_000;
function renewalUrgency(daysLeft: number): LicenseUrgency {
  if (daysLeft > RENEWAL_WARN_DAYS) return 'none';
  if (daysLeft <= 7) return 'urgent';
  if (daysLeft <= 14) return 'warn';
  return 'info';
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
  try { writeFileSync('/opt/hexwatch-ops/.lic-notify', (data.state === 'active' || data.state === 'grace') ? '1' : '0'); } catch { /* bandera opcional */ }
  return data;
}

async function computeStatus(): Promise<LicenseStatus> {
  const rows = await query<{ code: string }>('SELECT code FROM license WHERE id = 1');
  if (!rows[0]) return { state: 'none', message: 'No hay licencia activada.' };

  const v = verifyCode(rows[0].code);
  if (!v.ok || !v.payload) return { state: 'invalid', message: v.reason ?? 'Licencia inválida.' };

  // Reloj confiable (anti-rollback) + revocación remota.
  const now = Date.now();
  const st = await query<{ ts: string; rev: string | null }>(
    "SELECT extract(epoch from last_seen_at) * 1000 AS ts, extract(epoch from revoked_at) * 1000 AS rev FROM license_state WHERE id = 1"
  );
  // Revocación remota (phone-home): el proveedor cortó el servicio. Bloquea y es pegajoso.
  if (st[0] && st[0].rev) {
    return {
      state: 'revoked',
      message: `Licencia revocada por el proveedor${v.payload.customer ? ` (${v.payload.customer})` : ''}. El servicio quedó bloqueado; contacta a Crubol para reactivar.`,
      customer: v.payload.customer,
      issuedAt: v.payload.issuedAt,
      expiresAt: v.payload.expiresAt,
      daysLeft: 0,
    };
  }
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
  const snz = await query<{ until: Date | string | null }>("SELECT snoozed_until AS until FROM license_state WHERE id = 1");
  const snoozedUntil = snz[0] && snz[0].until ? new Date(snz[0].until as unknown as string).toISOString() : undefined;
  if (trusted > exp) {
    // Vencida: si aún está dentro del periodo de gracia, el SOC sigue operando.
    if (trusted <= exp + GRACE_MS) {
      const graceDaysLeft = Math.max(0, Math.ceil((exp + GRACE_MS - trusted) / 86400_000));
      return {
        state: 'grace',
        message: `Licencia VENCIDA el ${v.payload.expiresAt.slice(0, 10)}. Periodo de gracia: ${graceDaysLeft} día(s) para renovar antes del corte del servicio.`,
        renewalWarning: true,
        urgency: 'urgent',
        graceDaysLeft,
        snoozedUntil,
        ...base,
      };
    }
    return { state: 'expired', message: `Licencia vencida el ${v.payload.expiresAt.slice(0, 10)}. El servicio quedó bloqueado; carga un código nuevo.`, ...base };
  }
  const urgency = renewalUrgency(daysLeft);
  const renewalWarning = urgency !== 'none';
  const message = renewalWarning
    ? `Licencia por vencer: ${daysLeft} día(s) restantes. Renueva antes del ${v.payload.expiresAt.slice(0, 10)} para no interrumpir el servicio.`
    : `Licencia activa · ${daysLeft} día(s) restantes.`;
  return { state: 'active', message, renewalWarning, urgency, ...base };
}

/** Activa un código (solo si firma válida y no vencido). Reinicia la línea de tiempo confiable y limpia cualquier revocación previa. */
export async function activateLicense(code: string, userId: string | null): Promise<LicenseStatus> {
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
    `INSERT INTO license_state (id, last_seen_at, revoked_at) VALUES (1, now(), NULL)
       ON CONFLICT (id) DO UPDATE SET last_seen_at = now(), revoked_at = NULL`
  );
  invalidateLicenseCache();
  return getLicenseStatus();
}

/** Marca la licencia como REVOCADA remotamente (phone-home). Bloquea y es pegajoso hasta una nueva activación. */
export async function markRevoked(): Promise<void> {
  await query(
    `INSERT INTO license_state (id, revoked_at) VALUES (1, now())
       ON CONFLICT (id) DO UPDATE SET revoked_at = now()`
  );
  invalidateLicenseCache();
}

/** Último issuedAt de token de estado visto (anti-replay del phone-home), en ms. */
export async function getLastStatusAt(): Promise<number> {
  const r = await query<{ ts: string | null }>("SELECT extract(epoch from last_status_at) * 1000 AS ts FROM license_state WHERE id = 1");
  return r[0]?.ts ? Number(r[0].ts) : 0;
}

/** Registra (monotónico) el issuedAt del último token de estado aplicado. */
export async function recordStatusSeen(issuedAtIso: string): Promise<void> {
  const t = Math.floor(new Date(issuedAtIso).getTime() / 1000);
  if (!Number.isFinite(t)) return;
  await query(
    `INSERT INTO license_state (id, last_status_at) VALUES (1, to_timestamp($1))
       ON CONFLICT (id) DO UPDATE SET last_status_at = GREATEST(license_state.last_status_at, to_timestamp($1))`,
    [t]
  );
}
