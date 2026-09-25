/**
 * Dashboard de Office 365: agrega los eventos de la Management Activity API que
 * Wazuh ingesta (data.office365.*) para dar visibilidad tipo "módulo O365" de
 * Wazuh: top usuarios, IPs cliente (con país), operaciones, workloads, reglas,
 * sign-ins de Azure AD (éxito/fallo, origen, dispositivo) y actividad de
 * archivos (OneDrive/SharePoint — señal de exfiltración).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { query } from '../../config/db';

const RANGE: Record<string, string> = { '12h': 'now-12h', '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
const O365_FILTER = { bool: { should: [{ match: { 'rule.groups': 'office365' } }, { exists: { field: 'data.office365' } }], minimum_should_match: 1 } };

export interface NamedCount { key: string; count: number; country?: string; system?: boolean }

/** Identidad de sistema/anónima de Microsoft (SharePoint/OneDrive), no una persona real. */
function isSystemUser(u?: string): boolean {
  if (!u) return false;
  return /^urn:spo:/i.test(u) || /^urn:/i.test(u) || u.toLowerCase() === 'app@sharepoint';
}
export interface RuleCount { desc: string; count: number; level: number }
export interface TimePoint { ts: number; count: number }

// --- Panel "Riesgos M365": indicadores de amenaza específicos del tenant ---
export interface O365RiskDetail { label: string; count: number }
export interface O365Risk {
  key: string;
  label: string;
  severity: 'critica' | 'alta' | 'media';
  hint: string;          // por qué importa (lenguaje llano)
  count: number;         // eventos/afectados
  detail: O365RiskDetail[]; // top usuarios / países / operaciones
  active: boolean;       // true = hay indicio; false = sano
}
export interface O365Risks { clean: boolean; items: O365Risk[] }

// País donde opera el cliente: un login desde OTRO país es sospechoso.
const HOME_COUNTRY_ISO = 'CO';
const FORWARD_OPS = ['New-InboxRule', 'Set-InboxRule', 'Set-Mailbox', 'New-TransportRule', 'Set-TransportRule'];
const EXT_SHARE_OPS = ['AnonymousLinkCreated', 'AnonymousLinkUsed', 'SharingInvitationCreated', 'SecureLinkCreated', 'AddedToSecureLink', 'CompanyLinkCreated'];
const ADMIN_OPS = ['Add member to role.', 'Remove member from role.', 'Consent to application.', 'Add-MailboxPermission', 'Add service principal.', 'New-ManagementRoleAssignment', 'Add delegated permission grant.', 'Add app role assignment to service principal.', 'Set-AdminAuditLogConfig'];
const FAIL_SPIKE = 10;      // fallos de login por usuario en la ventana
const MASS_DOWNLOAD = 200;  // descargas por usuario en la ventana

export interface O365Overview {
  risks: O365Risks;
  range: string;
  total: number;
  users: number;
  clientIps: number;
  signIns: number;
  signInsFailed: number;
  downloads: number;
  timeline: TimePoint[];
  topUsers: NamedCount[];
  topClientIps: NamedCount[];
  topOperations: NamedCount[];
  workloads: NamedCount[];
  topRules: RuleCount[];
  signInUsers: NamedCount[];
  signInIps: NamedCount[];
  fileTopUsers: NamedCount[];
  generatedAt: string;
}

interface TermB { key: string; doc_count: number; tu?: { buckets: TermB[] } }
interface RuleB extends TermB { lvl: { value: number | null } }

function withGeo(buckets: TermB[]): NamedCount[] {
  return buckets.map((b) => {
    const g = isPublicIP(b.key) ? geolocate(b.key) : null;
    // Una IP es "infra Microsoft" si su único usuario es una identidad de sistema (urn:...).
    const topUser = b.tu?.buckets?.[0]?.key;
    const system = isSystemUser(topUser);
    return { key: b.key, count: b.doc_count, country: g?.country || (isPublicIP(b.key) ? '' : 'interna'), system };
  });
}

async function search(body: object): Promise<{ hits: { total: { value: number } | number }; aggregations?: Record<string, { buckets?: TermB[]; value?: number }> }> {
  const { data } = await getIndexerClient().post(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
  return data as { hits: { total: { value: number } | number }; aggregations?: Record<string, { buckets?: TermB[]; value?: number }> };
}

const RANGE_INTERVAL: Record<string, string> = { '12h': '1h', '24h': '1h', '7d': '1d', '30d': '1d' };

/**
 * Panel "Riesgos M365": corre una sola agregación sobre los eventos O365 de la
 * ventana y evalúa indicadores de amenaza concretos del tenant. Cuando todos
 * dan 0 el tenant está sano; los que se activen quedan de primeros.
 */
async function computeRisks(base: object[]): Promise<O365Risks> {
  const r = await search({
    size: 0,
    query: { bool: { filter: base } },
    aggs: {
      // Reglas de reenvío de correo (buzón comprometido reenviando a un externo)
      forward: { filter: { terms: { 'data.office365.Operation': FORWARD_OPS } },
        aggs: { by: { terms: { field: 'data.office365.UserId', size: 8 } } } },
      // Compartir a externos / enlaces anónimos (fuga de datos)
      extShare: { filter: { terms: { 'data.office365.Operation': EXT_SHARE_OPS } },
        aggs: { by: { terms: { field: 'data.office365.UserId', size: 8 } } } },
      // Acciones administrativas sensibles (roles, consentimientos de apps)
      admin: { filter: { terms: { 'data.office365.Operation': ADMIN_OPS } },
        aggs: { by: { terms: { field: 'data.office365.Operation', size: 8 } } } },
      // Fallos de login por usuario (fuerza bruta / password spray)
      fails: { filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } },
        aggs: { by: { terms: { field: 'data.office365.UserId', size: 20, min_doc_count: FAIL_SPIKE } } } },
      // Descargas masivas por usuario (exfiltración desde OneDrive/SharePoint)
      dl: { filter: { terms: { 'data.office365.Operation': ['FileDownloaded', 'FileSyncDownloadedFull'] } },
        aggs: { by: { terms: { field: 'data.office365.UserId', size: 20, min_doc_count: MASS_DOWNLOAD } } } },
      // Logins exitosos por IP (para clasificar por país y detectar orígenes foráneos)
      logins: { filter: { term: { 'data.office365.Operation': 'UserLoggedIn' } },
        aggs: { ip: { terms: { field: 'data.office365.ClientIP', size: 300 } } } },
    },
  });
  type Sub = { doc_count?: number; by?: { buckets: TermB[] }; ip?: { buckets: TermB[] } };
  const ag = (r.aggregations ?? {}) as Record<string, Sub>;
  const items: O365Risk[] = [];

  const push = (key: string, label: string, severity: O365Risk['severity'], hint: string, count: number, detail: O365RiskDetail[]) => {
    items.push({ key, label, severity, hint, count, detail, active: count > 0 });
  };

  const fwdB = ag.forward?.by?.buckets ?? [];
  push('forwarding', 'Reglas de reenvío de correo', 'critica',
    'Un buzón comprometido suele crear una regla que reenvía la correspondencia a un buzón externo del atacante.',
    ag.forward?.doc_count ?? 0, fwdB.map((b) => ({ label: b.key, count: b.doc_count })));

  // Logins foráneos: agrupa IPs de login por país; cualquier país != CO es sospechoso.
  const byCountry: Record<string, number> = {};
  for (const b of ag.logins?.ip?.buckets ?? []) {
    if (!isPublicIP(b.key)) continue;
    const g = geolocate(b.key);
    const iso = g?.isoCode || '';
    if (iso && iso !== HOME_COUNTRY_ISO) {
      const name = g?.country || iso;
      byCountry[name] = (byCountry[name] || 0) + b.doc_count;
    }
  }
  const foreign = Object.entries(byCountry).sort((a, b) => b[1] - a[1]);
  const foreignTotal = foreign.reduce((s, [, v]) => s + v, 0);
  push('foreign_login', 'Inicios de sesión desde el exterior', 'alta',
    `La operación es en Colombia; un inicio de sesión exitoso desde otro país sugiere una cuenta comprometida.`,
    foreignTotal, foreign.map(([k, v]) => ({ label: k, count: v })));

  const failB = ag.fails?.by?.buckets ?? [];
  push('login_failed_spike', 'Ráfaga de fallos de inicio de sesión', 'alta',
    `Un usuario con ${FAIL_SPIKE}+ fallos en la ventana indica fuerza bruta o password spray contra esa cuenta.`,
    failB.length, failB.map((b) => ({ label: b.key, count: b.doc_count })));

  const dlB = ag.dl?.by?.buckets ?? [];
  push('mass_download', 'Descargas masivas de archivos', 'alta',
    `Un usuario que descarga ${MASS_DOWNLOAD}+ archivos en la ventana puede estar exfiltrando información.`,
    dlB.length, dlB.map((b) => ({ label: b.key, count: b.doc_count })));

  const shB = ag.extShare?.by?.buckets ?? [];
  push('external_share', 'Compartir con externos / enlaces anónimos', 'media',
    'Enlaces anónimos o invitaciones a externos exponen documentos fuera de la organización.',
    ag.extShare?.doc_count ?? 0, shB.map((b) => ({ label: b.key, count: b.doc_count })));

  const adB = ag.admin?.by?.buckets ?? [];
  push('admin_action', 'Acciones administrativas sensibles', 'media',
    'Cambios de rol, permisos de buzón o consentimientos de aplicaciones que un atacante usa para persistir.',
    ag.admin?.doc_count ?? 0, adB.map((b) => ({ label: b.key, count: b.doc_count })));

  // Activos primero (por severidad), luego los sanos.
  const sevRank: Record<O365Risk['severity'], number> = { critica: 0, alta: 1, media: 2 };
  items.sort((a, b) => Number(b.active) - Number(a.active) || sevRank[a.severity] - sevRank[b.severity] || b.count - a.count);
  return { clean: items.every((i) => !i.active), items };
}

export async function getO365Overview(rangeIn: string): Promise<O365Overview> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const gte = RANGE[range];
  const base = [{ range: { '@timestamp': { gte } } }, O365_FILTER];

  // 1) Agregación principal
  const main = await getIndexerClient().post<{
    hits: { total: { value: number } | number };
    aggregations: {
      users: { buckets: TermB[] }; ips: { buckets: (TermB & { tu?: { buckets: TermB[] } })[] }; ops: { buckets: TermB[] };
      workloads: { buckets: TermB[] }; rules: { buckets: RuleB[] };
      timeline: { buckets: { key: number; doc_count: number }[] };
      cUsers: { value: number }; cIps: { value: number };
      signin: { doc_count: number }; signinFail: { doc_count: number }; downloads: { doc_count: number };
    };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: base } },
    aggs: {
      users: { terms: { field: 'data.office365.UserId', size: 15 } },
      ips: { terms: { field: 'data.office365.ClientIP', size: 20 }, aggs: { tu: { terms: { field: 'data.office365.UserId', size: 2 } } } },
      ops: { terms: { field: 'data.office365.Operation', size: 15 } },
      workloads: { terms: { field: 'data.office365.Workload', size: 12 } },
      rules: { terms: { field: 'rule.description', size: 12 }, aggs: { lvl: { max: { field: 'rule.level' } } } },
      timeline: { date_histogram: { field: '@timestamp', fixed_interval: RANGE_INTERVAL[range], min_doc_count: 0, extended_bounds: { min: gte, max: 'now' } } },
      cUsers: { cardinality: { field: 'data.office365.UserId' } },
      cIps: { cardinality: { field: 'data.office365.ClientIP' } },
      signin: { filter: { term: { 'data.office365.Operation': 'UserLoggedIn' } } },
      signinFail: { filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } } },
      downloads: { filter: { term: { 'data.office365.Operation': 'FileDownloaded' } } },
    },
  });
  const a = main.data.aggregations;
  const total = typeof main.data.hits.total === 'number' ? main.data.hits.total : main.data.hits.total.value;

  // 2) Sign-ins: origen (ActorIpAddress) y usuarios
  const si = await search({
    size: 0,
    query: { bool: { filter: [...base, { terms: { 'data.office365.Operation': ['UserLoggedIn', 'UserLoginFailed'] } }] } },
    aggs: {
      ipsrc: { terms: { field: 'data.office365.ActorIpAddress', size: 10 } },
      suser: { terms: { field: 'data.office365.UserId', size: 10 } },
    },
  });

  // 3) Actividad de archivos: top usuarios que descargan/modifican (señal de exfil)
  const fa = await search({
    size: 0,
    query: { bool: { filter: [...base, { terms: { 'data.office365.Operation': ['FileDownloaded', 'FileModified', 'FileModifiedExtended', 'FileUploaded', 'FileSyncDownloadedFull'] } }] } },
    aggs: { dusers: { terms: { field: 'data.office365.UserId', size: 10 } } },
  });

  // 4) Panel de riesgos M365 (indicadores de amenaza del tenant)
  const risks = await computeRisks(base);

  return {
    risks,
    range,
    total,
    users: a.cUsers.value,
    clientIps: a.cIps.value,
    signIns: a.signin.doc_count,
    signInsFailed: a.signinFail.doc_count,
    downloads: a.downloads.doc_count,
    timeline: a.timeline.buckets.map((b) => ({ ts: b.key, count: b.doc_count })),
    topUsers: a.users.buckets.map((b) => ({ key: b.key, count: b.doc_count })),
    topClientIps: withGeo(a.ips.buckets),
    topOperations: a.ops.buckets.map((b) => ({ key: b.key, count: b.doc_count })),
    workloads: a.workloads.buckets.map((b) => ({ key: b.key, count: b.doc_count })),
    topRules: a.rules.buckets.map((b) => ({ desc: b.key, count: b.doc_count, level: Math.round(b.lvl.value ?? 0) })),
    signInUsers: (si.aggregations?.suser?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    signInIps: withGeo(si.aggregations?.ipsrc?.buckets ?? []),
    fileTopUsers: (fa.aggregations?.dusers?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    generatedAt: new Date().toISOString(),
  };
}


// --- Correlación: credenciales EXPUESTAS (HIBP/credexp) que están BAJO ATAQUE en O365 ---
// Une el módulo de exposición de credenciales con los logins de Office 365.
// Cuenta filtrada + fallos = credential stuffing activo. Si hubo login EXITOSO desde el
// EXTERIOR (fuera del país de operación) => CRÍTICO (posible compromiso).
export interface ExposedUnderAttack {
  email: string;
  breaches: number;
  breachNames: string[];
  failedLogins: number;
  successfulLogins: number;
  foreignSuccessIps: string[];
  lastFail: string | null;
  riesgo: 'critico' | 'alto' | 'medio';
}

export async function getExposedUnderAttack(rangeIn = '7d'): Promise<ExposedUnderAttack[]> {
  const gte = RANGE[rangeIn] ?? 'now-7d';
  const exposed = await query<{ email: string; num_brechas: number; brechas: string[] }>(
    `SELECT (alias || '@' || domain) AS email, num_brechas, brechas
       FROM credexp_accounts WHERE estado <> 'dismissed'`
  ).catch(() => [] as { email: string; num_brechas: number; brechas: string[] }[]);
  if (!exposed.length) return [];
  const expMap = new Map(exposed.map((e) => [e.email.toLowerCase(), e]));
  const client = getIndexerClient();
  const { data: fd } = await client.post<{ aggregations: { u: { buckets: { key: string; doc_count: number; last: { value_as_string?: string } }[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    { size: 0, query: { bool: { filter: [{ term: { 'data.office365.Operation': 'UserLoginFailed' } }, { range: { timestamp: { gte } } }] } },
      aggs: { u: { terms: { field: 'data.office365.UserId', size: 300 }, aggs: { last: { max: { field: 'timestamp' } } } } } });
  const failMap = new Map((fd.aggregations?.u?.buckets ?? []).map((b) => [String(b.key).toLowerCase(), b]));
  const okResp = await client.post<{ aggregations: { u: { buckets: { key: string; doc_count: number; ips: { buckets: { key: string }[] } }[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    { size: 0, query: { bool: { filter: [{ term: { 'data.office365.Operation': 'UserLoggedIn' } }, { range: { timestamp: { gte } } }] } },
      aggs: { u: { terms: { field: 'data.office365.UserId', size: 300 }, aggs: { ips: { terms: { field: 'data.office365.ActorIpAddress', size: 15 } } } } } }).catch(() => ({ data: { aggregations: { u: { buckets: [] } } } }));
  const okMap = new Map((okResp.data.aggregations?.u?.buckets ?? []).map((b) => [String(b.key).toLowerCase(), { count: b.doc_count, ips: (b.ips?.buckets ?? []).map((x) => x.key) }]));
  const out: ExposedUnderAttack[] = [];
  for (const [email, exp] of expMap) {
    const f = failMap.get(email);
    if (!f || !f.doc_count) continue;
    const ok = okMap.get(email);
    const foreignIps = (ok?.ips ?? []).filter((ip) => { const g = geolocate(ip); return isPublicIP(ip) && g && g.isoCode !== HOME_COUNTRY_ISO; });
    const riesgo: ExposedUnderAttack['riesgo'] = foreignIps.length ? 'critico' : (f.doc_count >= 100 || (exp.num_brechas ?? 0) >= 5) ? 'alto' : 'medio';
    out.push({
      email, breaches: exp.num_brechas ?? 0, breachNames: Array.isArray(exp.brechas) ? exp.brechas : [],
      failedLogins: f.doc_count, successfulLogins: ok?.count ?? 0, foreignSuccessIps: foreignIps,
      lastFail: f.last?.value_as_string ?? null, riesgo,
    });
  }
  const rank = { critico: 3, alto: 2, medio: 1 };
  out.sort((a, b) => (rank[b.riesgo] - rank[a.riesgo]) || (b.failedLogins - a.failedLogins));
  return out;
}
