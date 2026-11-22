/**
 * Monitor de Consentimientos OAuth (M365) — inventario vivo de aplicaciones de
 * terceros con consentimiento en el tenant y su RIESGO (permisos delegados/de
 * aplicación, alcance org vs usuario, editor verificado). Detecta el ataque de
 * "consent phishing" / grants ilícitos que un atacante usa para persistir leyendo
 * correo o datos sin contraseña.
 * Fuente: Microsoft Graph (servicePrincipals + oauth2PermissionGrants +
 * appRoleAssignments) con la app client-credentials existente. Solo lectura.
 */
import axios, { type AxiosResponse } from 'axios';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { env } from '../../config/env';

export function isGraphConfigured(): boolean { return Boolean(env.GRAPH_TENANT_ID && env.GRAPH_CLIENT_ID && env.GRAPH_CLIENT_SECRET); }
const MS_TENANT = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; // tenant de Microsoft (apps de 1ª parte)

let tok: { token: string; exp: number } | null = null;
async function graphToken(): Promise<string> {
  if (tok && Date.now() < tok.exp) return tok.token;
  const body = new URLSearchParams({ client_id: env.GRAPH_CLIENT_ID!, client_secret: env.GRAPH_CLIENT_SECRET!, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' });
  const { data } = await axios.post<{ access_token: string; expires_in: number }>(
    `https://login.microsoftonline.com/${env.GRAPH_TENANT_ID}/oauth2/v2.0/token`, body.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 12_000 });
  tok = { token: data.access_token, exp: Date.now() + (data.expires_in - 60) * 1000 };
  return data.access_token;
}
const G = axios.create({ baseURL: 'https://graph.microsoft.com/v1.0', timeout: 25_000 });
async function gAll<T>(path: string, token: string): Promise<T[]> {
  const out: T[] = [];
  let url: string | null = path;
  while (url) {
    const resp: AxiosResponse<{ value?: T[]; '@odata.nextLink'?: string }> = await G.get(url, { headers: { Authorization: `Bearer ${token}` } });
    out.push(...(resp.data.value ?? []));
    const n: string | undefined = resp.data['@odata.nextLink'];
    url = n ? n.replace('https://graph.microsoft.com/v1.0', '') : null;
  }
  return out;
}

interface SP { id: string; appId: string; displayName: string; appOwnerOrganizationId?: string; verifiedPublisher?: { displayName?: string } | null; servicePrincipalType?: string }
interface Grant { clientId: string; consentType: string; principalId: string | null; resourceId: string; scope: string }

const SENSITIVE = /(mail\.(read|readwrite|send)|mailboxsettings|full_access_as_user|files\.(read|readwrite)\.all|sites\.(read|readwrite|fullcontrol|manage)|directory\.(read|readwrite)\.all|user\.(read|readwrite)\.all|group\.(read|readwrite)|member\.read\.hidden|calendars\.readwrite|chat)/i;
const MAIL = /(mail\.|mailbox|full_access_as_user|imap|pop|smtp)/i;

export type Risk = 'critica' | 'alta' | 'media' | 'baja';
export interface OAuthApp {
  appId: string; spId: string; name: string; publisher: string | null; verified: boolean; firstParty: boolean;
  consent: 'organizacion' | 'usuario'; usuarios: number; scopes: string[]; appRoles: string[]; mailAccess: boolean;
  risk: Risk; score: number; reasons: string[];
}
export interface OAuthOverview {
  generatedAt: string; configured: boolean;
  kpis: { total: number; terceros: number; riesgosas: number; sinEditor: number; orgConsent: number; conCorreo: number };
  apps: OAuthApp[];
}

async function appRoleNames(clientId: string, token: string, cache: Map<string, Map<string, string>>): Promise<string[]> {
  const asg = await gAll<{ appRoleId: string; resourceId: string }>(`/servicePrincipals/${clientId}/appRoleAssignments?$top=100`, token).catch(() => []);
  const names: string[] = [];
  for (const a of asg) {
    let m = cache.get(a.resourceId);
    if (!m) {
      try {
        const { data } = await G.get<{ appRoles?: { id: string; value: string }[] }>(`/servicePrincipals/${a.resourceId}?$select=appRoles,displayName`, { headers: { Authorization: `Bearer ${token}` } });
        m = new Map((data.appRoles ?? []).map((r) => [r.id, r.value]));
      } catch { m = new Map(); }
      cache.set(a.resourceId, m);
    }
    names.push(m.get(a.appRoleId) ?? a.appRoleId);
  }
  return names;
}

export async function getOverview(): Promise<OAuthOverview> {
  if (!isGraphConfigured()) return { generatedAt: new Date().toISOString(), configured: false, kpis: { total: 0, terceros: 0, riesgosas: 0, sinEditor: 0, orgConsent: 0, conCorreo: 0 }, apps: [] };
  const token = await graphToken();
  const [grants, sps] = await Promise.all([
    gAll<Grant>('/oauth2PermissionGrants?$top=100', token),
    gAll<SP>('/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,verifiedPublisher,servicePrincipalType&$top=200', token),
  ]);
  const spById = new Map(sps.map((s) => [s.id, s]));
  const byClient = new Map<string, Grant[]>();
  for (const g of grants) { const a = byClient.get(g.clientId); if (a) a.push(g); else byClient.set(g.clientId, [g]); }

  const roleCache = new Map<string, Map<string, string>>();
  const apps: OAuthApp[] = [];
  for (const [clientId, gs] of byClient) {
    const sp = spById.get(clientId);
    const firstParty = !sp?.appOwnerOrganizationId || sp.appOwnerOrganizationId === MS_TENANT || sp.appOwnerOrganizationId === env.GRAPH_TENANT_ID;
    const scopes = [...new Set(gs.flatMap((g) => (g.scope ?? '').split(/\s+/).filter(Boolean)))];
    const consentOrg = gs.some((g) => g.consentType === 'AllPrincipals');
    const usuarios = gs.filter((g) => g.consentType === 'Principal').length;
    const roles = firstParty ? [] : await appRoleNames(clientId, token, roleCache);
    const allScopes = scopes.join(' ');
    const verified = !!sp?.verifiedPublisher?.displayName;

    let score = 0; const reasons: string[] = [];
    if (roles.length) { score += 50; reasons.push(`Permisos de aplicación (app-only): ${roles.slice(0, 5).join(', ')}`); }
    if (SENSITIVE.test(allScopes)) { score += 25; reasons.push('Permisos delegados sensibles (correo/archivos/directorio)'); }
    if (consentOrg) { score += 15; reasons.push('Consentido para TODA la organización'); }
    if (!verified && !firstParty) { score += 12; reasons.push('Editor no verificado'); }
    if (/offline_access/i.test(allScopes)) { score += 5; reasons.push('offline_access (persistencia)'); }
    if (!firstParty) score += 5;
    const risk: Risk = score >= 50 ? 'critica' : score >= 30 ? 'alta' : score >= 15 ? 'media' : 'baja';
    const mailAccess = MAIL.test(allScopes) || roles.some((r) => MAIL.test(r));

    apps.push({
      appId: sp?.appId ?? clientId, spId: clientId, name: sp?.displayName ?? '(app desconocida)',
      publisher: sp?.verifiedPublisher?.displayName ?? null, verified, firstParty,
      consent: consentOrg ? 'organizacion' : 'usuario', usuarios, scopes, appRoles: roles, mailAccess, risk, score, reasons,
    });
  }
  const rank = { critica: 0, alta: 1, media: 2, baja: 3 } as const;
  apps.sort((a, b) => rank[a.risk] - rank[b.risk] || b.score - a.score);

  return {
    generatedAt: new Date().toISOString(), configured: true,
    kpis: {
      total: apps.length,
      terceros: apps.filter((a) => !a.firstParty).length,
      riesgosas: apps.filter((a) => a.risk === 'critica' || a.risk === 'alta').length,
      sinEditor: apps.filter((a) => !a.verified && !a.firstParty).length,
      orgConsent: apps.filter((a) => a.consent === 'organizacion').length,
      conCorreo: apps.filter((a) => a.mailAccess).length,
    },
    apps,
  };
}

// ─── dedup + alertas de apps riesgosas NUEVAS ───
export async function ensureSchema(): Promise<void> {
  await query('CREATE TABLE IF NOT EXISTS oauth_apps_seen (app_id TEXT PRIMARY KEY, name TEXT, risk TEXT, first_seen TIMESTAMPTZ NOT NULL DEFAULT now())', []);
}
export async function findNewRisky(): Promise<OAuthApp[]> {
  await ensureSchema();
  const ov = await getOverview();
  const risky = ov.apps.filter((a) => (a.risk === 'critica' || a.risk === 'alta') && !a.firstParty);
  const fresh: OAuthApp[] = [];
  for (const a of risky) {
    const rows = await query('SELECT 1 FROM oauth_apps_seen WHERE app_id=$1', [a.appId]);
    if (!rows.length) { await query('INSERT INTO oauth_apps_seen(app_id,name,risk) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [a.appId, a.name, a.risk]); fresh.push(a); }
  }
  return fresh;
}
export async function seedBaseline(): Promise<boolean> {
  await ensureSchema();
  const rows = await query<{ n: number }>('SELECT count(*)::int AS n FROM oauth_apps_seen', []);
  if ((rows[0]?.n ?? 0) > 0) return false;
  await findNewRisky();
  logger.info('🔑 OAuth apps: baseline sembrado');
  return true;
}
