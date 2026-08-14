/**
 * Radar de activos: un punto por AGENTE real, con un score de riesgo compuesto
 * (vulnerabilidades críticas/altas + alertas recientes por severidad + estado
 * del agente). Alimenta el "Threat Radar" del Command Center para que cada punto
 * sea un activo interpretable (cerca del centro = más riesgo).
 */
import { getAssetList } from '../assets/assets.service';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { getIndexerClient } from '../wazuh/wazuh.client';
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
        query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }, { exists: { field: 'agent.name' } }] } },
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
  }).sort((x, y) => y.risk - x.risk).slice(0, 300);

  return { total: agents.length, assets, generatedAt: new Date().toISOString() };
}
