/**
 * Risk-Based Alerting (RBA) — puntaje de riesgo ACUMULADO por entidad (host y
 * usuario), estilo Splunk RBA / "investigation priority" de Sentinel. En vez de
 * mirar alertas sueltas, suma señales ponderadas por entidad y prioriza el triage:
 * "¿a qué host/usuario le pongo el ojo primero y por qué?".
 *
 * Señales por HOST: alertas críticas/altas (log), severidad máxima, vulns
 *   críticas/altas, agente desconectado. (Misma base que el Threat Radar.)
 * Señales por USUARIO: fallos de autenticación, amplitud (varios hosts/orígenes),
 *   posible fuerza bruta exitosa, y anomalías UEBA abiertas.
 *
 * Reutiliza fuentes ya existentes: collectLogins (UEBA), listAnomalies (UEBA),
 * getVulnerabilities, getAssetList y el índice de alertas.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { getAssetList } from '../assets/assets.service';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { collectLogins, listAnomalies, type AnomalyRow } from '../ueba/ueba.service';

export type RiskBand = 'critico' | 'alto' | 'medio' | 'bajo';

export interface RiskContribution { source: string; label: string; points: number }
export interface EntityRisk {
  entity: string;
  type: 'host' | 'user';
  score: number;             // 0-100 acumulado
  band: RiskBand;
  contributions: RiskContribution[];
  alerts: number;            // alertas relacionadas en la ventana
  critAlerts: number;
  extra?: Record<string, string | number>;
}
export interface EntityRiskReport {
  range: string;
  hosts: EntityRisk[];
  users: EntityRisk[];
  generatedAt: string;
}

const RANGE_HOURS: Record<string, number> = { '24h': 24, '7d': 168, '30d': 720 };

function bandOf(score: number): RiskBand {
  if (score >= 70) return 'critico';
  if (score >= 45) return 'alto';
  if (score >= 25) return 'medio';
  return 'bajo';
}

const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));
const log2 = (n: number) => Math.log2(1 + Math.max(0, n));

/** Puntos por severidad de una anomalía UEBA (tolera es/en y usa score como respaldo). */
function anomalyPoints(a: AnomalyRow): number {
  const s = String(a.severity ?? '').toLowerCase();
  if (s.includes('crit')) return 22;
  if (s.includes('alt') || s === 'high') return 14;
  if (s.includes('med')) return 8;
  if (s.includes('baj') || s === 'low') return 3;
  const sc = Number(a.score) || 0;                 // respaldo por score 0-100
  return clamp(Math.round(sc / 5), 3, 22);
}

interface AgAgg { key: string; doc_count: number; max: { value: number | null }; crit: { doc_count: number }; high: { doc_count: number } }

/** Riesgo por HOST: alertas (por agente) + vulnerabilidades + estado del agente. */
async function computeHostRisk(hours: number): Promise<EntityRisk[]> {
  const [agentsR, vulnR] = await Promise.allSettled([getAssetList(), getVulnerabilities()]);
  const agents = agentsR.status === 'fulfilled' ? agentsR.value : [];

  const vmap = new Map<string, { critical: number; high: number }>();
  if (vulnR.status === 'fulfilled') for (const a of vulnR.value.porAgente) vmap.set(a.agent, { critical: a.critical, high: a.high });

  const amap = new Map<string, { count: number; crit: number; high: number; max: number }>();
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{ aggregations?: { ag: { buckets: AgAgg[] } } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte: `now-${hours}h` } } }, { exists: { field: 'agent.name' } }] } },
        aggs: {
          ag: {
            terms: { field: 'agent.name', size: 500 },
            aggs: {
              max: { max: { field: 'rule.level' } },
              crit: { filter: { range: { 'rule.level': { gte: 12 } } } },
              high: { filter: { range: { 'rule.level': { gte: 8, lt: 12 } } } },
            },
          },
        },
      }
    );
    for (const b of data.aggregations?.ag?.buckets ?? []) amap.set(b.key, { count: b.doc_count, crit: b.crit.doc_count, high: b.high.doc_count, max: Math.round(b.max.value ?? 0) });
  } catch { /* degradado a vulns/estado */ }

  const out: EntityRisk[] = agents.map((a) => {
    const v = vmap.get(a.name) ?? { critical: 0, high: 0 };
    const al = amap.get(a.name) ?? { count: 0, crit: 0, high: 0, max: 0 };
    const disconnected = a.status !== 'active';
    const c: RiskContribution[] = [];
    const pCrit = clamp(Math.round(log2(al.crit) * 8), 0, 35);
    const pHigh = clamp(Math.round(log2(al.high) * 3), 0, 18);
    const pSev = clamp(Math.round((al.max / 16) * 8), 0, 8);
    const pVc = clamp(Math.round(v.critical * 1.3), 0, 20);
    const pVh = clamp(Math.round(v.high * 0.3), 0, 8);
    const pBlind = disconnected ? 8 : 0;
    if (pCrit) c.push({ source: 'alertas', label: `${al.crit} alertas críticas`, points: pCrit });
    if (pHigh) c.push({ source: 'alertas', label: `${al.high} alertas altas`, points: pHigh });
    if (pSev) c.push({ source: 'alertas', label: `severidad máx. ${al.max}`, points: pSev });
    if (pVc) c.push({ source: 'vulns', label: `${v.critical} vulnerabilidades críticas`, points: pVc });
    if (pVh) c.push({ source: 'vulns', label: `${v.high} vulnerabilidades altas`, points: pVh });
    if (pBlind) c.push({ source: 'estado', label: 'agente desconectado', points: pBlind });
    const score = clamp(c.reduce((s, x) => s + x.points, 0), disconnected ? 8 : 0, 100);
    return {
      entity: a.name, type: 'host' as const, score, band: bandOf(score),
      contributions: c.sort((x, y) => y.points - x.points),
      alerts: al.count, critAlerts: al.crit,
      extra: { os: a.os, ip: a.ip, status: a.status },
    };
  });
  return out.filter((e) => e.score > 0).sort((a, b) => b.score - a.score);
}

/** Riesgo por USUARIO: fallos de auth + amplitud + fuerza bruta + anomalías UEBA. */
async function computeUserRisk(hours: number): Promise<EntityRisk[]> {
  const days = clamp(Math.ceil(hours / 24), 1, 90);
  const [loginsR, anomsR] = await Promise.allSettled([collectLogins(hours), listAnomalies({ status: 'open', days })]);
  const logins = loginsR.status === 'fulfilled' ? loginsR.value : [];
  const anoms = anomsR.status === 'fulfilled' ? anomsR.value : [];

  interface Acc { fails: number; ok: number; hosts: Set<string>; ips: Set<string>; anoms: AnomalyRow[] }
  const map = new Map<string, Acc>();
  const get = (u: string): Acc => {
    let a = map.get(u);
    if (!a) { a = { fails: 0, ok: 0, hosts: new Set(), ips: new Set(), anoms: [] }; map.set(u, a); }
    return a;
  };
  for (const l of logins) {
    const a = get(l.user);
    if (l.outcome === 'fail') a.fails++; else a.ok++;
    if (l.host) a.hosts.add(l.host);
    if (l.srcip) a.ips.add(l.srcip);
  }
  for (const an of anoms) {
    if (!an.entity) continue;
    // UEBA es centrado en usuario; adjunta la anomalía a su entidad (usuario).
    get(an.entity).anoms.push(an);
  }

  const out: EntityRisk[] = [];
  for (const [user, a] of map) {
    const c: RiskContribution[] = [];
    const pFail = clamp(Math.round(log2(a.fails) * 6), 0, 30);
    const pBreadth = a.hosts.size > 1 ? clamp((a.hosts.size - 1) * 3, 0, 10) : 0;
    const pForeign = a.ips.size > 0 ? clamp(a.ips.size * 4, 0, 10) : 0;
    const pBrute = a.fails >= 5 && a.ok >= 1 ? 12 : 0;
    const pAnom = clamp(a.anoms.reduce((s, x) => s + anomalyPoints(x), 0), 0, 45);
    if (pFail) c.push({ source: 'auth', label: `${a.fails} fallos de autenticación`, points: pFail });
    if (pBrute) c.push({ source: 'auth', label: 'posible fuerza bruta exitosa', points: pBrute });
    if (pBreadth) c.push({ source: 'auth', label: `actividad en ${a.hosts.size} hosts`, points: pBreadth });
    if (pForeign) c.push({ source: 'auth', label: `${a.ips.size} orígenes externos`, points: pForeign });
    if (pAnom) c.push({ source: 'ueba', label: `${a.anoms.length} anomalía(s) UEBA`, points: pAnom });
    const score = clamp(c.reduce((s, x) => s + x.points, 0), 0, 100);
    if (score <= 0) continue;
    out.push({
      entity: user, type: 'user', score, band: bandOf(score),
      contributions: c.sort((x, y) => y.points - x.points),
      alerts: a.fails + a.ok, critAlerts: a.anoms.filter((x) => String(x.severity).toLowerCase().includes('crit')).length,
      extra: { fallos: a.fails, exitos: a.ok, hosts: a.hosts.size },
    });
  }
  return out.sort((a, b) => b.score - a.score);
}

export async function getEntityRisk(rangeIn: string): Promise<EntityRiskReport> {
  const range = RANGE_HOURS[rangeIn] ? rangeIn : '24h';
  const hours = RANGE_HOURS[range];
  const [hosts, users] = await Promise.all([computeHostRisk(hours), computeUserRisk(hours)]);
  return { range, hosts: hosts.slice(0, 100), users: users.slice(0, 100), generatedAt: new Date().toISOString() };
}

/** Top-N combinado (host+usuario) para el widget de "prioridad de triage" del Command Center. */
export async function getTriagePriority(limit = 6): Promise<EntityRisk[]> {
  const { hosts, users } = await getEntityRisk('24h');
  return [...hosts, ...users].sort((a, b) => b.score - a.score).slice(0, limit);
}
