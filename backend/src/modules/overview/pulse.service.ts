/**
 * Datos "en vivo" del Command Center que faltaban por conectar:
 *  - tendencia real de alertas por banda (crítica/alta/media) en el rango dado,
 *  - "pulso" del ticker: tasa de ingesta real, disco del Indexer, CVEs en KEV,
 *    estado del SIEM y variación de alertas vs el día anterior.
 * Nada de datos de ejemplo.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { cachedHealth, getOverallHealth } from '../health/siem-health.service';
import { env } from '../../config/env';

// ---- Tendencia de seguridad ----
const RANGE_CFG: Record<string, { gte: string; interval: string }> = {
  '24h': { gte: 'now-24h', interval: '1h' },
  '7d': { gte: 'now-7d', interval: '1d' },
  '30d': { gte: 'now-30d', interval: '1d' },
  '90d': { gte: 'now-90d', interval: '3d' },
};

interface HistBucket { key: number; crit: { doc_count: number }; alta: { doc_count: number }; media: { doc_count: number } }

export interface AlertTrend { range: string; critica: number[]; alta: number[]; media: number[] }

export async function getAlertTrend(rangeIn: string): Promise<AlertTrend> {
  const range = RANGE_CFG[rangeIn] ? rangeIn : '7d';
  const { gte, interval } = RANGE_CFG[range];
  const client = getIndexerClient();
  const { data } = await client.post<{ aggregations?: { t: { buckets: HistBucket[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte } } }] } },
      aggs: {
        t: {
          date_histogram: { field: '@timestamp', fixed_interval: interval, min_doc_count: 0, extended_bounds: { min: gte, max: 'now' } },
          aggs: {
            crit: { filter: { range: { 'rule.level': { gte: 12 } } } },
            alta: { filter: { range: { 'rule.level': { gte: 8, lt: 12 } } } },
            media: { filter: { range: { 'rule.level': { gte: 5, lt: 8 } } } },
          },
        },
      },
    }
  );
  const buckets = data.aggregations?.t?.buckets ?? [];
  return {
    range,
    critica: buckets.map((b) => b.crit.doc_count),
    alta: buckets.map((b) => b.alta.doc_count),
    media: buckets.map((b) => b.media.doc_count),
  };
}

// ---- Pulso del ticker ----
export interface Pulse {
  sistema: 'OPERATIVO' | 'EN GESTIÓN' | 'ATENCIÓN';
  ingestaMin: number;      // alertas/min (última hora)
  discoPct: number | null; // % de disco usado del Indexer
  kevEnv: number;          // CVEs del entorno en CISA KEV
  alertas24h: number;
  deltaPct: number;        // variación vs 24h previas
}

async function countAlerts(gte: string, lt?: string): Promise<number> {
  try {
    const client = getIndexerClient();
    const range: Record<string, string> = { gte };
    if (lt) range.lt = lt;
    const { data } = await client.post<{ count: number }>(`/${env.WAZUH_ALERTS_INDEX}/_count`, { query: { bool: { filter: [{ range: { '@timestamp': range } }] } } });
    return data.count ?? 0;
  } catch { return 0; }
}

export async function getPulse(): Promise<Pulse> {
  const [c24, cPrev, c60m, health, vulns] = await Promise.all([
    countAlerts('now-24h'),
    countAlerts('now-48h', 'now-24h'),
    countAlerts('now-60m'),
    (async () => cachedHealth() ?? await getOverallHealth().catch(() => null))(),
    getVulnerabilities().catch(() => null),
  ]);

  const sistema: Pulse['sistema'] = health?.semaforo === 'rojo' ? 'ATENCIÓN' : health?.semaforo === 'amarillo' ? 'EN GESTIÓN' : 'OPERATIVO';
  let discoPct: number | null = null;
  const disco = health?.componentes.find((c) => c.id === 'disco');
  if (disco) { const m = disco.resumen.match(/(\d+)%/); if (m) discoPct = Number(m[1]); }

  const deltaPct = cPrev > 0 ? Math.round(((c24 - cPrev) / cPrev) * 100) : 0;

  return {
    sistema,
    ingestaMin: Math.round(c60m / 60),
    discoPct,
    kevEnv: vulns?.resumen.kev ?? 0,
    alertas24h: c24,
    deltaPct,
  };
}
