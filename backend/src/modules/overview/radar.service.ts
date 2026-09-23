/**
 * Radar de activos: un punto por AGENTE real, con un score de riesgo compuesto
 * (vulnerabilidades críticas/altas + alertas recientes por severidad + estado
 * del agente). Alimenta el "Threat Radar" del Command Center para que cada punto
 * sea un activo interpretable (cerca del centro = más riesgo).
 */
import { getAssetList } from '../assets/assets.service';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { isFortigateConfigured } from '../response/fortigate.service';
import { env } from '../../config/env';

export type AssetCategory = 'ep' | 'srv' | 'net';
export type RiskBand = 'critico' | 'alto' | 'medio' | 'monitoreado' | 'sano';

export interface RadarAsset {
  name: string;
  category: AssetCategory;
  risk: number;          // 0-100
  band: RiskBand;
  criticalVulns: number;
  highVulns: number;
  alerts24h: number;
  critAlerts: number;
  maxLevel: number;
  status: string;        // active | disconnected | never_connected | ...
  os: string;
  ip: string;
}

export interface AssetRadar { total: number; assets: RadarAsset[]; generatedAt: string }

function categorize(name: string, os: string): AssetCategory {
  const n = (name || '').toLowerCase();
  const o = (os || '').toLowerCase();
  if (/(^|[^a-z])(fw|forti|firewall|switch|router|gw|gateway|nsx|pfsense)([^a-z]|$)/.test(n)) return 'net';
  if (/(srv|server|winsrv|prin-|soc|pmx|proxmox|wazuh|velocirap|\bdc\d|\bad\d)/.test(n) || o.includes('server')) return 'srv';
  return 'ep';
}

function bandOf(risk: number, disconnected: boolean): RiskBand {
  if (risk >= 70) return 'critico';
  if (risk >= 45) return 'alto';
  if (risk >= 25) return 'medio';
  if (risk >= 10 || disconnected) return 'monitoreado';
  return 'sano';
}

interface AgAgg { key: string; doc_count: number; max: { value: number | null }; crit: { doc_count: number }; high: { doc_count: number } }

/**
 * SonicWall como activo de RED en el radar. No es un agente Wazuh (manda syslog),
 * así que se construye aparte: riesgo desde sus eventos reales del SIEM (grupo
 * `fortigate`) y estado por heartbeat (¿emitió syslog hace poco?). Si el firewall
 * no está configurado o el indexer no responde, devuelve null (no se inventa).
 */
async function getFortigateAsset(): Promise<RadarAsset | null> {
  if (!isFortigateConfigured()) return null;
  const host = (process.env.SONICWALL_API_URL || '').replace(/^https?:\/\//, '').split('/')[0].split(':')[0] || '192.168.20.1';
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{
      hits: { total: { value: number } | number };
      aggregations?: { last: { value: number | null }; mx: { value: number | null }; crit: { doc_count: number }; high: { doc_count: number } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      track_total_hits: true,
      query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }, { match: { 'rule.groups': 'sonicwall' } }] } },
      aggs: {
        last: { max: { field: '@timestamp' } },
        mx: { max: { field: 'rule.level' } },
        crit: { filter: { range: { 'rule.level': { gte: 12 } } } },
        high: { filter: { range: { 'rule.level': { gte: 8, lt: 12 } } } },
      },
    });
    const t = data.hits.total;
    const count = typeof t === 'number' ? t : t.value;
    const ag = data.aggregations;
    const crit = ag?.crit.doc_count ?? 0;
    const high = ag?.high.doc_count ?? 0;
    const max = Math.round(ag?.mx.value ?? 0);
    const lastMs = ag?.last.value ?? 0;
    // Heartbeat: activo si emitió syslog en los últimos 20 min.
    const disconnected = !(lastMs > 0 && Date.now() - lastMs < 20 * 60_000);
    // Sin vulnerabilidades (no hay escaneo del FW); el riesgo sale de su actividad.
    const alertScore = Math.min(30, Math.log2(1 + crit) * 6 + Math.log2(1 + high) * 2);
    const sevScore = Math.min(8, (max / 16) * 8);
    const blind = disconnected ? 12 : 0;
    let risk = Math.round(alertScore + sevScore + blind);
    risk = Math.max(disconnected ? 12 : 2, Math.min(100, risk));
    return {
      name: 'FW-SonicWall', category: 'net', risk, band: bandOf(risk, disconnected),
      criticalVulns: 0, highVulns: 0, alerts24h: count, critAlerts: crit, maxLevel: max,
      status: disconnected ? 'disconnected' : 'active', os: 'SonicOS · firewall perimetral', ip: host,
    };
  } catch {
    return null; // sin datos del indexer: no se dibuja un punto inventado
  }
}

export async function getAssetRadar(): Promise<AssetRadar> {
  const [agentsR, vulnR] = await Promise.allSettled([getAssetList(), getVulnerabilities()]);
  const agents = agentsR.status === 'fulfilled' ? agentsR.value : [];

  // Vulns por agente.
  const vmap = new Map<string, { critical: number; high: number }>();
  if (vulnR.status === 'fulfilled') for (const a of vulnR.value.porAgente) vmap.set(a.agent, { critical: a.critical, high: a.high });

  // Alertas por agente en 24h (conteo + máximo nivel + críticas/altas).
  const amap = new Map<string, { count: number; crit: number; high: number; max: number }>();
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{ aggregations?: { ag: { buckets: AgAgg[] } } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }, { exists: { field: 'agent.name' } }], must_not: [{ terms: { 'rule.groups': ['vulnerability-detector', 'sca'] } }] } },
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
  } catch { /* sin alertas: se degrada a solo vulns/estado */ }

  // SonicWall (activo de red) en paralelo — no es un agente Wazuh.
  const fortiP = getFortigateAsset();

  const assets: RadarAsset[] = agents.map((a) => {
    const v = vmap.get(a.name) ?? { critical: 0, high: 0 };
    const al = amap.get(a.name) ?? { count: 0, crit: 0, high: 0, max: 0 };
    const disconnected = a.status !== 'active';
    // Score compuesto y ACOTADO por factor (para que discrimine y no se sature):
    //  exposición (vulns) + actividad de alertas alto/crítico en escala LOG (el
    //  volumen crudo es ruidoso) + severidad máxima + castigo por punto ciego.
    const vulnScore = Math.min(50, v.critical * 1.3 + v.high * 0.3);
    const alertScore = Math.min(30, Math.log2(1 + al.crit) * 6 + Math.log2(1 + al.high) * 2);
    const sevScore = Math.min(8, (al.max / 16) * 8);
    const blind = disconnected ? 12 : 0;
    let risk = Math.round(vulnScore + alertScore + sevScore + blind);
    risk = Math.max(disconnected ? 12 : 2, Math.min(100, risk));
    return {
      name: a.name, category: categorize(a.name, a.os), risk, band: bandOf(risk, disconnected),
      criticalVulns: v.critical, highVulns: v.high, alerts24h: al.count, critAlerts: al.crit, maxLevel: al.max,
      status: a.status, os: a.os, ip: a.ip,
    };
  });

  // Añade el SonicWall (si está) y ordena/recorta el conjunto completo.
  const forti = await fortiP;
  const all = (forti ? [...assets, forti] : assets).sort((x, y) => y.risk - x.risk).slice(0, 300);

  return { total: agents.length + (forti ? 1 : 0), assets: all, generatedAt: new Date().toISOString() };
}
