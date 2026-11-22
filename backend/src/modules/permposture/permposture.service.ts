/**
 * Postura de Permisos / Compartición (M365) — "Permission Manager lite": visibilidad
 * del acceso externo al tenant (invitados/guests vía Graph) y de la compartición
 * externa/anónima (auditoría O365 del indexer). Solo lectura, con recomendaciones.
 */
import axios, { type AxiosResponse } from 'axios';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { logger } from '../../config/logger';

export function isGraphConfigured(): boolean { return Boolean(env.GRAPH_TENANT_ID && env.GRAPH_CLIENT_ID && env.GRAPH_CLIENT_SECRET); }
const INDEX = env.WAZUH_ALERTS_INDEX;
const RANGE: Record<string, string> = { '7d': 'now-7d', '30d': 'now-30d', '90d': 'now-90d' };
const gte = (r: string): string => RANGE[r] ?? 'now-30d';
const FREEMAIL = /@(gmail|hotmail|outlook|live|yahoo|proton|protonmail|icloud|aol)\./i;

let tok: { token: string; exp: number } | null = null;
async function graphToken(): Promise<string> {
  if (tok && Date.now() < tok.exp) return tok.token;
  const b = new URLSearchParams({ client_id: env.GRAPH_CLIENT_ID!, client_secret: env.GRAPH_CLIENT_SECRET!, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' });
  const { data } = await axios.post<{ access_token: string; expires_in: number }>(`https://login.microsoftonline.com/${env.GRAPH_TENANT_ID}/oauth2/v2.0/token`, b.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 12_000 });
  tok = { token: data.access_token, exp: Date.now() + (data.expires_in - 60) * 1000 };
  return data.access_token;
}
const G = axios.create({ baseURL: 'https://graph.microsoft.com/v1.0', timeout: 20_000 });

export interface Guest { name: string; mail: string; domain: string; created: string | null; enabled: boolean; freeMail: boolean; stale: boolean }
export interface SiteShare { site: string; count: number }
export interface PermPosture {
  generatedAt: string; configured: boolean; range: string;
  kpis: { invitados: number; deshabilitados: number; dominios: number; correoGratis: number; enlacesAnonimos: number; invitExternas: number };
  invitados: Guest[]; dominios: { dominio: string; invitados: number }[];
  topSitiosAnonimos: SiteShare[]; recomendaciones: string[];
}

async function guests(token: string): Promise<Guest[]> {
  const out: Guest[] = [];
  let url: string | null = "/users?$filter=userType eq 'Guest'&$select=displayName,mail,userPrincipalName,createdDateTime,accountEnabled&$top=999";
  const now = Date.now();
  while (url) {
    const resp: AxiosResponse<{ value?: { displayName?: string; mail?: string; userPrincipalName?: string; createdDateTime?: string; accountEnabled?: boolean }[]; '@odata.nextLink'?: string }> =
      await G.get(url, { headers: { Authorization: `Bearer ${token}` } });
    for (const u of resp.data.value ?? []) {
      const mail = (u.mail || u.userPrincipalName || '').replace(/#EXT#.*/i, '');
      const domain = mail.includes('@') ? mail.split('@')[1].toLowerCase() : '?';
      const created = u.createdDateTime ?? null;
      const stale = created ? (now - Date.parse(created)) > 180 * 86400000 : false;
      out.push({ name: u.displayName ?? '(invitado)', mail, domain, created, enabled: u.accountEnabled !== false, freeMail: FREEMAIL.test(mail), stale });
    }
    const n: string | undefined = resp.data['@odata.nextLink'];
    url = n ? n.replace('https://graph.microsoft.com/v1.0', '') : null;
  }
  return out;
}

async function sharingActivity(days: string): Promise<{ anon: number; invit: number; sites: SiteShare[] }> {
  try {
    const body = {
      size: 0,
      query: { bool: { filter: [{ exists: { field: 'data.office365.Operation' } }, { range: { '@timestamp': { gte: gte(days) } } }] } },
      aggs: {
        anon: { filter: { terms: { 'data.office365.Operation': ['AnonymousLinkCreated', 'AnonymousLinkUpdated'] } }, aggs: { sites: { terms: { field: 'data.office365.SiteUrl', size: 10 } } } },
        invit: { filter: { terms: { 'data.office365.Operation': ['SharingInvitationCreated', 'AddedToSecureLink'] } } },
      },
    };
    const resp: AxiosResponse<{ aggregations?: { anon?: { doc_count: number; sites?: { buckets: { key: string; doc_count: number }[] } }; invit?: { doc_count: number } } }> =
      await getIndexerClient().post(`/${INDEX}/_search`, body);
    const a = resp.data.aggregations;
    return {
      anon: a?.anon?.doc_count ?? 0,
      invit: a?.invit?.doc_count ?? 0,
      sites: (a?.anon?.sites?.buckets ?? []).map((b) => ({ site: b.key, count: b.doc_count })),
    };
  } catch (e) { logger.warn({ err: (e as Error).message }, 'permposture: sharing'); return { anon: 0, invit: 0, sites: [] }; }
}

export async function getPosture(days = '30d'): Promise<PermPosture> {
  if (!isGraphConfigured()) return { generatedAt: new Date().toISOString(), configured: false, range: days, kpis: { invitados: 0, deshabilitados: 0, dominios: 0, correoGratis: 0, enlacesAnonimos: 0, invitExternas: 0 }, invitados: [], dominios: [], topSitiosAnonimos: [], recomendaciones: [] };
  const token = await graphToken();
  const [gs, sh] = await Promise.all([guests(token).catch(() => [] as Guest[]), sharingActivity(days)]);

  const domMap = new Map<string, number>();
  for (const g of gs) domMap.set(g.domain, (domMap.get(g.domain) ?? 0) + 1);
  const dominios = [...domMap.entries()].map(([dominio, invitados]) => ({ dominio, invitados })).sort((a, b) => b.invitados - a.invitados);

  const disabled = gs.filter((g) => !g.enabled).length;
  const free = gs.filter((g) => g.freeMail).length;
  const stale = gs.filter((g) => g.stale && g.enabled).length;

  const rec: string[] = [];
  if (disabled) rec.push(`${disabled} invitado(s) deshabilitado(s) sin eliminar — conviene removerlos del directorio.`);
  if (free) rec.push(`${free} invitado(s) desde correos gratuitos (gmail/hotmail…) — verificar que sean legítimos.`);
  if (stale) rec.push(`${stale} invitado(s) activos con más de 180 días — revisar si siguen necesitando acceso.`);
  if (sh.anon) rec.push(`${sh.anon} enlace(s) anónimo(s) creados en el rango — revisar que no expongan datos sensibles.`);
  if (!rec.length) rec.push('Sin hallazgos de riesgo en el acceso externo. 👍');

  gs.sort((a, b) => Number(a.enabled) - Number(b.enabled) || (b.created ?? '').localeCompare(a.created ?? ''));
  return {
    generatedAt: new Date().toISOString(), configured: true, range: days,
    kpis: { invitados: gs.length, deshabilitados: disabled, dominios: dominios.length, correoGratis: free, enlacesAnonimos: sh.anon, invitExternas: sh.invit },
    invitados: gs, dominios, topSitiosAnonimos: sh.sites, recomendaciones: rec,
  };
}
