/**
 * Vigilancia extendida para los informes: reúne análisis + evidencia de las 8 áreas
 * (credenciales expuestas, Office 365, mapa de ataques, XDR, superficie externa/ASM,
 * riesgo digital/DRP, postura de correo y cumplimiento normativo).
 * Cada área está aislada en try/catch: si una falla, el resto del informe sale igual.
 */
import { query } from '../../config/db';
import { env } from '../../config/env';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { getCompliance } from '../compliance/compliance.service';
import { getPosture } from '../email-posture/email-posture.service';
import { getGroups } from '../xdr/xdr.service';
import { getAttackGeo } from '../attacks/attacks.service';

export interface CredItem { cuenta: string; brechas: number; nombres: string }
export interface AsmItem { sev: string; objetivo: string; detalle: string }
export interface DrpItem { sev: string; dominio: string; mx: boolean; detalle: string }
export interface PosturaDom { domain: string; score: number; grade: string; spf: string; dkim: string; dmarc: string; mx: string }
export interface FwItem { marco: string; total: number; controles: number }
export interface AtaqueItem { pais: string; count: number; ip: string; clasif: string }
export interface XdrItem { alertas: number; reglas: number; maxLevel: number; entidades: number; tipos: string; topRegla: string }
export interface O365Stats { logins: number; fallidos: number; mfaFail: number; usuarios: number; ipsPublicas: number; sharingAnon: number }

export interface Vigilancia {
  cred: { total: number; items: CredItem[] };
  asm: { total: number; criticos: number; items: AsmItem[] };
  drp: { total: number; conMx: number; items: DrpItem[] };
  postura: PosturaDom[];
  cumplimiento: FwItem[];
  ataques: AtaqueItem[];
  xdr: { total: number; items: XdrItem[] };
  o365: O365Stats;
}

const FW_LABEL: Record<string, string> = {
  nist_800_53: 'NIST 800-53', gdpr: 'GDPR', tsc: 'SOC 2 (TSC)', pci_dss: 'PCI DSS', hipaa: 'HIPAA',
  nist: 'NIST 800-53', pci: 'PCI DSS',
};
const MFA_ERRORS = ['500121', '500071', '500571', '50076', '50074'];

async function esCount(body: unknown): Promise<number> {
  try {
    const { data } = await getIndexerClient().post<{ count: number }>(`/${env.WAZUH_ALERTS_INDEX}/_count`, body);
    return data.count ?? 0;
  } catch { return 0; }
}
async function esAgg(body: unknown): Promise<any> {
  try {
    const { data } = await getIndexerClient().post<any>(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
    return data;
  } catch { return { aggregations: {} }; }
}

export async function collectVigilancia(hours = 720): Promise<Vigilancia> {
  const gte = `now-${hours}h`;

  // ── 1. Credenciales expuestas ──
  let cred = { total: 0, items: [] as CredItem[] };
  try {
    const rows = await query<{ cuenta: string; num_brechas: number; nombres: string[] }>(
      `SELECT alias || '@' || domain AS cuenta, num_brechas,
              (SELECT array_agg(x) FROM (SELECT jsonb_array_elements_text(brechas) AS x LIMIT 6) s) AS nombres
         FROM credexp_accounts WHERE estado <> 'dismissed' ORDER BY num_brechas DESC NULLS LAST LIMIT 12`);
    const totalRow = await query<{ n: number }>(`SELECT count(*)::int AS n FROM credexp_accounts WHERE estado <> 'dismissed'`);
    cred = {
      total: totalRow[0]?.n ?? rows.length,
      items: rows.map((r) => ({ cuenta: r.cuenta, brechas: r.num_brechas ?? 0, nombres: (r.nombres || []).join(', ') })),
    };
  } catch { /* credexp opcional */ }

  // ── 2. Office 365 ──
  let o365: O365Stats = { logins: 0, fallidos: 0, mfaFail: 0, usuarios: 0, ipsPublicas: 0, sharingAnon: 0 };
  try {
    const f = (op: string, extra: unknown[] = []) => ({ query: { bool: { filter: [{ term: { 'data.office365.Operation': op } }, { range: { '@timestamp': { gte } } }, ...extra] } } });
    o365.logins = await esCount(f('UserLoggedIn'));
    o365.fallidos = await esCount(f('UserLoginFailed'));
    o365.mfaFail = await esCount(f('UserLoginFailed', [{ terms: { 'data.office365.ErrorNumber': MFA_ERRORS } }]));
    o365.sharingAnon = await esCount({ query: { bool: { filter: [{ terms: { 'data.office365.Operation': ['AnonymousLinkCreated', 'AnonymousLinkUsed'] } }, { range: { '@timestamp': { gte } } }] } } });
    const agg = await esAgg({ size: 0, query: { bool: { filter: [{ term: { 'data.office365.Operation': 'UserLoggedIn' } }, { range: { '@timestamp': { gte } } }] } }, aggs: { u: { cardinality: { field: 'data.office365.UserId' } }, ip: { cardinality: { field: 'data.office365.ClientIP' } } } });
    o365.usuarios = agg.aggregations?.u?.value ?? 0;
    o365.ipsPublicas = agg.aggregations?.ip?.value ?? 0;
  } catch { /* o365 opcional */ }

  // ── 3. Mapa de ataques ──
  let ataques: AtaqueItem[] = [];
  try {
    const origenes = await getAttackGeo(60).catch(() => [] as any[]);
    ataques = (origenes as any[]).filter((o) => o && o.threat)
      .sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 8)
      .map((o) => ({ pais: o.country || '—', count: o.count || 0, ip: (o.ips && o.ips[0]) || '—', clasif: o.clasificacion || 'desconocido' }));
  } catch { /* attacks opcional */ }

  // ── 4. XDR (correlación cross-dominio) ──
  let xdr = { total: 0, items: [] as XdrItem[] };
  try {
    const grupos = await getGroups('7d', 10).catch(() => [] as any[]);
    const g = grupos as any[];
    xdr = {
      total: g.length,
      items: g.sort((a, b) => (b.maxLevel || 0) - (a.maxLevel || 0) || (b.alertas || 0) - (a.alertas || 0)).slice(0, 6)
        .map((x) => ({ alertas: x.alertas || 0, reglas: x.reglas || 0, maxLevel: x.maxLevel || 0, entidades: (x.entidades || []).length, tipos: (x.tipos || []).join(', '), topRegla: (x.topReglas && x.topReglas[0]?.desc) || '' })),
    };
  } catch { /* xdr opcional */ }

  // ── 5. Superficie externa (ASM) ──
  let asm = { total: 0, criticos: 0, items: [] as AsmItem[] };
  try {
    const rows = await query<{ severidad: string; tipo: string; host: string; ip: string; puerto: number; domain: string; detalle: string }>(
      `SELECT severidad, tipo, coalesce(host,'') AS host, coalesce(ip,'') AS ip, coalesce(puerto,0) AS puerto, coalesce(domain,'') AS domain, coalesce(detalle,'') AS detalle
         FROM asm_findings WHERE estado='open' ORDER BY CASE severidad WHEN 'critica' THEN 1 WHEN 'alta' THEN 2 WHEN 'media' THEN 3 ELSE 4 END LIMIT 10`);
    const c = await query<{ n: number; crit: number }>(`SELECT count(*)::int AS n, count(*) FILTER (WHERE severidad IN ('critica','alta'))::int AS crit FROM asm_findings WHERE estado='open'`);
    asm = {
      total: c[0]?.n ?? rows.length, criticos: c[0]?.crit ?? 0,
      items: rows.map((r) => ({ sev: r.severidad, objetivo: `${r.host || r.domain || r.ip}${r.puerto ? ':' + r.puerto : ''}`, detalle: r.detalle || r.tipo })),
    };
  } catch { /* asm opcional */ }

  // ── 6. Riesgo digital (DRP) ──
  let drp = { total: 0, conMx: 0, items: [] as DrpItem[] };
  try {
    const rows = await query<{ severidad: string; dominio: string; mx: boolean; detalle: string }>(
      `SELECT severidad, coalesce(dominio,'') AS dominio, (meta->>'mx')='true' AS mx, coalesce(detalle,'') AS detalle
         FROM drp_findings WHERE estado='open' ORDER BY (meta->>'mx')='true' DESC, CASE severidad WHEN 'critica' THEN 1 WHEN 'alta' THEN 2 WHEN 'media' THEN 3 ELSE 4 END LIMIT 12`);
    const c = await query<{ n: number; mx: number }>(`SELECT count(*)::int AS n, count(*) FILTER (WHERE (meta->>'mx')='true')::int AS mx FROM drp_findings WHERE estado='open'`);
    drp = {
      total: c[0]?.n ?? rows.length, conMx: c[0]?.mx ?? 0,
      items: rows.map((r) => ({ sev: r.severidad, dominio: r.dominio, mx: r.mx, detalle: r.detalle })),
    };
  } catch { /* drp opcional */ }

  // ── 7. Postura de correo ──
  let postura: PosturaDom[] = [];
  try {
    const doms = await getPosture().catch(() => [] as any[]);
    postura = (doms as any[]).map((d) => {
      const get = (k: string) => (d.checks || []).find((c: any) => c.key === k)?.grade || '—';
      return { domain: d.domain, score: d.score ?? 0, grade: d.grade || '—', spf: get('spf'), dkim: get('dkim'), dmarc: get('dmarc'), mx: get('mx') };
    });
  } catch { /* postura opcional */ }

  // ── 8. Cumplimiento normativo ──
  let cumplimiento: FwItem[] = [];
  try {
    const comp = await getCompliance(hours).catch(() => ({ frameworks: {} as Record<string, any> }));
    cumplimiento = Object.entries(comp.frameworks || {}).map(([k, v]) => ({
      marco: FW_LABEL[k] || k.toUpperCase(), total: (v as any).total ?? 0, controles: (v as any).controlesCubiertos ?? 0,
    })).sort((a, b) => b.controles - a.controles);
  } catch { /* compliance opcional */ }

  return { cred, asm, drp, postura, cumplimiento, ataques, xdr, o365 };
}
