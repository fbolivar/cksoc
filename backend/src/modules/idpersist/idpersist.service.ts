/**
 * Persistencia de Identidad (M365) — detecta mecanismos que un atacante usa para
 * PERSISTIR tras robar una cuenta, a partir de la auditoría O365 ya ingerida en el
 * indexer de Wazuh (data.office365.*). Complementa ITDR (viaje imposible / MFA-fatigue):
 *   - Cambio de MFA / security-info (registro de un método propio del atacante)
 *   - Delegación de buzón (FullAccess) a otra cuenta
 *   - Cambios de Acceso Condicional (debilitar MFA)
 *   - Reset de tokens de sesión (StsRefreshTokenValidFrom)
 * Solo lectura; sin permisos nuevos (reutiliza lo que el puller O365 ya trae).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

const INDEX = env.WAZUH_ALERTS_INDEX;
const RANGE: Record<string, string> = { '7d': 'now-7d', '30d': 'now-30d', '90d': 'now-90d' };
const gte = (r: string): string => RANGE[r] ?? 'now-30d';

interface Office365 {
  Operation?: string; UserId?: string; ObjectId?: string; ClientIP?: string; ActorIpAddress?: string; CreationTime?: string;
  ModifiedProperties?: { Name?: string; OldValue?: string; NewValue?: string }[];
  Parameters?: { Name?: string; Value?: string }[];
}
interface Hit { _source: { data?: { office365?: Office365 } } }

const SYS = /NT SERVICE|ServicePrincipal_|MSExchange|BackgroundTask|Microsoft\.Exchange|Substrate|Sync_|HealthMailbox|Administrator@/i;
const MFA_PROP = /StrongAuthentication|PhoneAppDetail|security info|AlternativeSecurityId|SearchableDeviceKey|OTP|\bMFA\b/i;

export type Sev = 'critica' | 'alta' | 'media' | 'baja';
export interface IdpFinding { tipo: string; tipoLabel: string; user: string; actor: string; ip: string | null; detalle: string; ts: string; sev: Sev }
export interface IdpOverview { generatedAt: string; range: string; kpis: { mfa: number; delegacion: number; caPolicy: number; tokenReset: number }; hallazgos: IdpFinding[] }

async function search(ops: string[], days: string, size = 500): Promise<Office365[]> {
  const body = {
    size,
    query: { bool: { filter: [{ terms: { 'data.office365.Operation': ops } }, { range: { '@timestamp': { gte: gte(days) } } }] } },
    sort: [{ '@timestamp': { order: 'desc' } }],
    _source: ['data.office365'],
  };
  const { data } = await getIndexerClient().post<{ hits: { hits: Hit[] } }>(`/${INDEX}/_search`, body);
  return (data.hits?.hits ?? []).map((h) => h._source.data?.office365 ?? {}).filter((o) => o.Operation);
}
const param = (o: Office365, name: string): string | null => o.Parameters?.find((p) => p.Name === name)?.Value ?? null;

export async function getOverview(days = '30d'): Promise<IdpOverview> {
  const hallazgos: IdpFinding[] = [];

  // A) Cambio de MFA / security-info (dentro de "Update user.")
  try {
    const upd = await search(['Update user.'], days, 800);
    for (const o of upd) {
      if (SYS.test(o.UserId ?? '')) continue; // excluir churn de ServicePrincipals/servicios (no es un atacante)
      const props = (o.ModifiedProperties ?? []).filter((p) => MFA_PROP.test(p.Name ?? ''));
      if (!props.length) continue;
      hallazgos.push({ tipo: 'mfa_change', tipoLabel: 'Cambio de MFA / security-info', user: o.ObjectId ?? '?', actor: o.UserId ?? '?', ip: o.ClientIP ?? o.ActorIpAddress ?? null, detalle: `Modificó: ${props.map((p) => p.Name).join(', ')}`, ts: o.CreationTime ?? '', sev: 'alta' });
    }
  } catch (e) { logger.warn({ err: (e as Error).message }, 'idp: mfa'); }

  // B) Delegación de buzón (FullAccess) usuario->usuario
  try {
    const perm = await search(['Add-MailboxPermission'], days, 400);
    for (const o of perm) {
      if (SYS.test(o.UserId ?? '')) continue;
      const target = param(o, 'Identity'); const grantee = param(o, 'User'); const rights = param(o, 'AccessRights');
      if (/DiscoverySearchMailbox|SystemMailbox|HealthMailbox/i.test(target ?? '')) continue;
      if ((rights ?? '').toLowerCase() !== 'fullaccess') continue;
      if (/\b(nt authority|self)\b/i.test(grantee ?? '')) continue;
      hallazgos.push({ tipo: 'mailbox_delegation', tipoLabel: 'Delegación de buzón (FullAccess)', user: target ?? '?', actor: o.UserId ?? '?', ip: o.ClientIP ?? null, detalle: `${grantee ?? '?'} obtuvo FullAccess sobre ${target ?? '?'}`, ts: o.CreationTime ?? '', sev: 'alta' });
    }
  } catch (e) { logger.warn({ err: (e as Error).message }, 'idp: deleg'); }

  // C) Cambios de Acceso Condicional (posible debilitamiento de MFA)
  try {
    const ca = await search(['Set-ConditionalAccessPolicy', 'New-ConditionalAccessPolicy', 'Remove-ConditionalAccessPolicy'], days, 200);
    for (const o of ca) {
      if (SYS.test(o.UserId ?? '')) continue;
      hallazgos.push({ tipo: 'ca_change', tipoLabel: 'Cambio de Acceso Condicional', user: o.ObjectId ?? '(política)', actor: o.UserId ?? '?', ip: o.ClientIP ?? null, detalle: o.Operation ?? '', ts: o.CreationTime ?? '', sev: 'media' });
    }
  } catch (e) { logger.warn({ err: (e as Error).message }, 'idp: ca'); }

  // D) Reset de tokens de sesión
  try {
    const tok = await search(['Update StsRefreshTokenValidFrom Timestamp.'], days, 200);
    for (const o of tok) {
      if (SYS.test(o.UserId ?? '')) continue;
      hallazgos.push({ tipo: 'token_reset', tipoLabel: 'Reset de tokens de sesión', user: o.ObjectId ?? '?', actor: o.UserId ?? '?', ip: o.ClientIP ?? null, detalle: 'Se invalidaron los tokens de sesión del usuario (sign-out forzado)', ts: o.CreationTime ?? '', sev: 'baja' });
    }
  } catch (e) { logger.warn({ err: (e as Error).message }, 'idp: token'); }

  const rank = { critica: 0, alta: 1, media: 2, baja: 3 } as const;
  hallazgos.sort((a, b) => rank[a.sev] - rank[b.sev] || b.ts.localeCompare(a.ts));
  return {
    generatedAt: new Date().toISOString(), range: days,
    kpis: {
      mfa: hallazgos.filter((h) => h.tipo === 'mfa_change').length,
      delegacion: hallazgos.filter((h) => h.tipo === 'mailbox_delegation').length,
      caPolicy: hallazgos.filter((h) => h.tipo === 'ca_change').length,
      tokenReset: hallazgos.filter((h) => h.tipo === 'token_reset').length,
    },
    hallazgos: hallazgos.slice(0, 150),
  };
}

// ─── dedup + alertas (solo mfa_change + mailbox_delegation) ───
export async function ensureSchema(): Promise<void> {
  await query('CREATE TABLE IF NOT EXISTS idp_seen (k TEXT PRIMARY KEY, tipo TEXT, usr TEXT, first_seen TIMESTAMPTZ NOT NULL DEFAULT now())', []);
}
export async function findNew(): Promise<IdpFinding[]> {
  await ensureSchema();
  const ov = await getOverview('30d');
  const watch = ov.hallazgos.filter((h) => h.tipo === 'mfa_change' || h.tipo === 'mailbox_delegation');
  const fresh: IdpFinding[] = [];
  for (const h of watch) {
    const k = `${h.tipo}|${h.user}|${h.ts}`.toLowerCase();
    const rows = await query('SELECT 1 FROM idp_seen WHERE k=$1', [k]);
    if (!rows.length) { await query('INSERT INTO idp_seen(k,tipo,usr) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [k, h.tipo, h.user]); fresh.push(h); }
  }
  return fresh;
}
export async function seedBaseline(): Promise<boolean> {
  await ensureSchema();
  const rows = await query<{ n: number }>('SELECT count(*)::int AS n FROM idp_seen', []);
  if ((rows[0]?.n ?? 0) > 0) return false;
  await findNew();
  logger.info('🧬 Persistencia de identidad: baseline sembrado');
  return true;
}
