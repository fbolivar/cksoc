/**
 * Servicio de lectura de Wazuh Indexer.
 * Consultas de SOLO LECTURA sobre el indice wazuh-alerts-*.
 *   - countAlerts / countBySeverity (Fase 1)
 *   - getSummary / getTimeline / getTopAgents / getMitre (Fase 2)
 */
import { getIndexerClient } from './wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

/** Convierte un rango tipo "24h", "7d", "1h" a la sintaxis de fecha de OpenSearch. */
function rangeToGte(range: string): string {
  const match = /^(\d+)([hdm])$/.exec(range);
  if (!match) {
    throw new HttpError(400, 'Rango invalido. Usa formato como 24h, 7d o 30m');
  }
  return `now-${match[1]}${match[2]}`;
}

/** Filtro base de tiempo reutilizado por todas las agregaciones. */
function timeQuery(range: string) {
  return { range: { timestamp: { gte: rangeToGte(range), lte: 'now' } } };
}

/**
 * Categoriza un nivel de regla Wazuh (0-15) en una banda de severidad.
 * Mapa configurable; documentado para el equipo SOC.
 */
export function severityBand(level: number): 'baja' | 'media' | 'alta' | 'critica' {
  if (level >= 12) return 'critica';
  if (level >= 8) return 'alta';
  if (level >= 5) return 'media';
  return 'baja';
}

// ------------------------- Fase 1 -------------------------

export async function countAlerts(range: string): Promise<number> {
  const client = getIndexerClient();
  try {
    const { data } = await client.post<{ count: number }>(
      `/${env.WAZUH_ALERTS_INDEX}/_count`,
      { query: timeQuery(range) }
    );
    return data.count;
  } catch (err) {
    return mapIndexerError(err);
  }
}

export async function countBySeverity(
  range: string
): Promise<{ level: string; count: number }[]> {
  const buckets = await termsAgg(range, 'rule.level', 20, { _key: 'asc' });
  return buckets.map((b) => ({ level: String(b.key), count: b.doc_count }));
}

// ------------------------- Fase 2 -------------------------

export interface AlertsSummary {
  total: number;
  byLevel: { level: number; count: number }[];
  byBand: { baja: number; media: number; alta: number; critica: number };
}

/** Total + distribucion por nivel y por banda de severidad. */
export async function getSummary(range: string): Promise<AlertsSummary> {
  const client = getIndexerClient();
  const body = {
    size: 0,
    track_total_hits: true,
    query: timeQuery(range),
    aggs: { by_level: { terms: { field: 'rule.level', size: 20, order: { _key: 'asc' } } } },
  };
  try {
    const { data } = await client.post<{
      hits: { total: { value: number } };
      aggregations: { by_level: { buckets: { key: number; doc_count: number }[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);

    const byLevel = data.aggregations.by_level.buckets.map((b) => ({
      level: b.key,
      count: b.doc_count,
    }));
    const byBand = { baja: 0, media: 0, alta: 0, critica: 0 };
    for (const { level, count } of byLevel) byBand[severityBand(level)] += count;

    return { total: data.hits.total.value, byLevel, byBand };
  } catch (err) {
    return mapIndexerError(err);
  }
}

/** Serie temporal de alertas (date_histogram). */
export async function getTimeline(
  range: string,
  interval: string
): Promise<{ ts: string; count: number }[]> {
  const client = getIndexerClient();
  const body = {
    size: 0,
    query: timeQuery(range),
    aggs: {
      over_time: {
        date_histogram: {
          field: 'timestamp',
          fixed_interval: interval,
          min_doc_count: 0,
        },
      },
    },
  };
  try {
    const { data } = await client.post<{
      aggregations: {
        over_time: { buckets: { key_as_string: string; doc_count: number }[] };
      };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
    return data.aggregations.over_time.buckets.map((b) => ({
      ts: b.key_as_string,
      count: b.doc_count,
    }));
  } catch (err) {
    return mapIndexerError(err);
  }
}

/** Top agentes por numero de alertas. */
export async function getTopAgents(
  range: string,
  size: number
): Promise<{ agent: string; count: number }[]> {
  const buckets = await termsAgg(range, 'agent.name', size);
  return buckets.map((b) => ({ agent: String(b.key), count: b.doc_count }));
}

/** Top tecnicas MITRE ATT&CK. */
export async function getMitre(
  range: string,
  size: number
): Promise<{ technique: string; count: number }[]> {
  const buckets = await termsAgg(range, 'rule.mitre.technique', size);
  return buckets.map((b) => ({ technique: String(b.key), count: b.doc_count }));
}

/**
 * Cuenta alertas que cumplen una condicion (para el motor de notificaciones).
 * Filtra por ventana de tiempo, nivel minimo y, opcionalmente, grupos de regla.
 */
export async function countMatching(opts: {
  windowMinutes: number;
  minLevel: number;
  ruleGroups?: string[];
}): Promise<number> {
  const client = getIndexerClient();
  const filters: unknown[] = [
    { range: { timestamp: { gte: `now-${opts.windowMinutes}m`, lte: 'now' } } },
    { range: { 'rule.level': { gte: opts.minLevel } } },
  ];
  if (opts.ruleGroups && opts.ruleGroups.length > 0) {
    filters.push({ terms: { 'rule.groups': opts.ruleGroups } });
  }
  try {
    const { data } = await client.post<{ count: number }>(
      `/${env.WAZUH_ALERTS_INDEX}/_count`,
      { query: { bool: { filter: filters } } }
    );
    return data.count;
  } catch (err) {
    return mapIndexerError(err);
  }
}

// ------------------------- helpers -------------------------

/** Agregacion terms generica sobre el indice de alertas. */
async function termsAgg(
  range: string,
  field: string,
  size: number,
  order?: Record<string, 'asc' | 'desc'>
): Promise<{ key: string | number; doc_count: number }[]> {
  const client = getIndexerClient();
  const body = {
    size: 0,
    query: timeQuery(range),
    aggs: { result: { terms: { field, size, ...(order ? { order } : {}) } } },
  };
  try {
    const { data } = await client.post<{
      aggregations: { result: { buckets: { key: string | number; doc_count: number }[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
    return data.aggregations.result.buckets;
  } catch (err) {
    return mapIndexerError(err);
  }
}

/** Traduce errores del Indexer a HttpError legibles. */
function mapIndexerError(err: unknown): never {
  if (err instanceof HttpError) throw err;
  const e = err as { code?: string; response?: { status: number } };
  if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT' || e.code === 'EHOSTUNREACH') {
    throw new HttpError(
      502,
      'No se pudo conectar al Wazuh Indexer (.5:9200). Verifica conectividad de red y que el puerto este expuesto.'
    );
  }
  if (e.response?.status === 401) {
    throw new HttpError(502, 'Credenciales de Wazuh Indexer invalidas');
  }
  if (e.response?.status === 404) {
    throw new HttpError(502, 'Indice de alertas no encontrado en el Indexer');
  }
  throw new HttpError(502, 'Error consultando el Wazuh Indexer');
}
