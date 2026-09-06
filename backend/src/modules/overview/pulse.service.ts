/**
 * Datos "en vivo" del Command Center que faltaban por conectar:
 *  - tendencia real de alertas por banda (crítica/alta/media) en el rango dado,
 *  - "pulso" del ticker: tasa de ingesta real, disco del Indexer, CVEs en KEV,
 *    estado del SIEM y variación de alertas vs el día anterior.
 *
 * Regla de oro: nunca fabricar 0 por un timeout. El Command Center dispara
 * muchas consultas pesadas al Indexer a la vez; si una se cae, devolvemos
 * "desconocido" (null) y servimos la última foto buena, jamás calma falsa.
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
    },
    { timeout: 20_000 }
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
  ingestaMin: number | null;   // alertas/min (última hora); null = desconocido
  discoPct: number | null;     // % de disco usado del Indexer
  kevEnv: number | null;       // CVEs del entorno en CISA KEV
  alertas24h: number | null;
  deltaPct: number | null;     // variación vs 24h previas
  degradado?: boolean;         // true si se sirvió la última foto buena
}

// Single-flight: consultas idénticas simultáneas comparten una sola promesa, así
// la ráfaga del Command Center no multiplica la carga sobre el Indexer.
const inflight = new Map<string, Promise<number | null>>();

async function countAlerts(gte: string, lt?: string): Promise<number | null> {
  const key = `${gte}|${lt ?? ''}`;
  const existing = inflight.get(key);
  if (existing) return existing;
  const p = (async (): Promise<number | null> => {
    const range: Record<string, string> = { gte };
    if (lt) range.lt = lt;
    const body = { query: { bool: { filter: [{ range: { '@timestamp': range } }] } } };
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const { data } = await getIndexerClient().post<{ count: number }>(
          `/${env.WAZUH_ALERTS_INDEX}/_count`, body, { timeout: 20_000 }
        );
        return data.count ?? 0;
      } catch {
        if (attempt === 0) await new Promise((r) => setTimeout(r, 350));
      }
    }
    return null;
  })().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

// Última foto buena + cache: evita re-consultar en cada refresco y, ante un fallo
// transitorio, permite servir la última verdad conocida en vez de ceros. El TTL
// vive por encima del intervalo del warmup (25s) para que el precalentado en
// segundo plano —a baja concurrencia— sea quien reconstruye, no la ráfaga del
// dashboard; `force` deja que el warmup renueve pese a la cache vigente.
let lastGood: Pulse | null = null;
let pulseCache: { at: number; data: Pulse } | null = null;
const PULSE_TTL = 30_000;

export async function getPulse(opts?: { force?: boolean }): Promise<Pulse> {
  if (!opts?.force && pulseCache && Date.now() - pulseCache.at < PULSE_TTL) return pulseCache.data;

  const [c24, cPrev, c60m, health, vulns] = await Promise.all([
    countAlerts('now-24h'),
    countAlerts('now-48h', 'now-24h'),
    countAlerts('now-60m'),
    (async () => cachedHealth() ?? await getOverallHealth().catch(() => null))(),
    getVulnerabilities().catch(() => null),
  ]);

  let discoPct: number | null = null;
  const disco = health?.componentes.find((c) => c.id === 'disco');
  if (disco) { const m = disco.resumen.match(/(\d+)%/); if (m) discoPct = Number(m[1]); }

  const deltaPct = c24 != null && cPrev != null && cPrev > 0 ? Math.round(((c24 - cPrev) / cPrev) * 100) : null;

  // Degradado si no pudimos leer la ingesta/volumen o el estado del SIEM: en ese
  // caso servimos la última foto buena (real, algo vieja) antes que calma falsa.
  const degradado = c24 === null || c60m === null || health == null;
  if (degradado && lastGood) {
    const data = { ...lastGood, degradado: true };
    pulseCache = { at: Date.now(), data };
    return data;
  }

  const sistema: Pulse['sistema'] = health?.semaforo === 'rojo' ? 'ATENCIÓN' : health?.semaforo === 'amarillo' ? 'EN GESTIÓN' : 'OPERATIVO';
  const data: Pulse = {
    sistema,
    ingestaMin: c60m != null ? Math.round(c60m / 60) : null,
    discoPct,
    kevEnv: vulns?.resumen.kev ?? null,
    alertas24h: c24,
    deltaPct,
    degradado: degradado || undefined,
  };
  if (!degradado) lastGood = data;
  pulseCache = { at: Date.now(), data };
  return data;
}
