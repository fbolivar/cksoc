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

// ------------------------- Explorador de alertas -------------------------

export interface AlertHit {
  id: string;
  index: string;
  timestamp: string;
  ruleId: string;
  level: number;
  band: 'baja' | 'media' | 'alta' | 'critica';
  description: string;
  agent: string;
  srcip: string | null;
  mitre: string[];
  groups: string[];
}

export interface AlertSearchParams {
  range: string;
  band?: string;
  agent?: string;
  srcip?: string;
  ruleId?: string;
  q?: string;
  mitre?: string;
  page: number;
  size: number;
}

const MAX_WINDOW = 10000; // limite de deep paging de OpenSearch

function bandRange(band: string): Record<string, number> | null {
  switch (band) {
    case 'critica': return { gte: 12 };
    case 'alta': return { gte: 8, lte: 11 };
    case 'media': return { gte: 5, lte: 7 };
    case 'baja': return { lte: 4 };
    default: return null;
  }
}

/** Busqueda paginada de alertas individuales con filtros. */
export async function searchAlerts(
  p: AlertSearchParams
): Promise<{ total: number; capped: boolean; items: AlertHit[] }> {
  const client = getIndexerClient();
  const filter: unknown[] = [timeQuery(p.range)];
  const bandR = p.band ? bandRange(p.band) : null;
  if (bandR) filter.push({ range: { 'rule.level': bandR } });
  if (p.agent) filter.push({ term: { 'agent.name': p.agent } });
  if (p.ruleId) filter.push({ term: { 'rule.id': p.ruleId } });
  if (p.mitre) filter.push({ term: { 'rule.mitre.id': p.mitre } });
  if (p.srcip) {
    filter.push({
      bool: { should: [{ term: { 'data.srcip': p.srcip } }, { term: { 'data.remip': p.srcip } }], minimum_should_match: 1 },
    });
  }
  const must = p.q ? [{ match: { 'rule.description': { query: p.q, operator: 'and' } } }] : [];

  const from = Math.min(p.page * p.size, Math.max(0, MAX_WINDOW - p.size));
  try {
    const { data } = await client.post<{
      hits: { total: { value: number; relation: string }; hits: { _id: string; _index: string; _source: Record<string, unknown> }[] };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      track_total_hits: MAX_WINDOW,
      from,
      size: p.size,
      sort: [{ timestamp: { order: 'desc' } }],
      _source: ['timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.groups', 'rule.mitre.id', 'agent.name', 'data.srcip', 'data.remip'],
      query: { bool: { filter, ...(must.length ? { must } : {}) } },
    });
    return {
      total: data.hits.total.value,
      capped: data.hits.total.relation === 'gte',
      items: data.hits.hits.map(flattenHit),
    };
  } catch (err) {
    return mapIndexerError(err);
  }
}

function flattenHit(h: { _id: string; _index: string; _source: Record<string, unknown> }): AlertHit {
  const s = h._source;
  const rule = (s.rule ?? {}) as Record<string, unknown>;
  const agent = (s.agent ?? {}) as Record<string, unknown>;
  const dataF = (s.data ?? {}) as Record<string, unknown>;
  const mitre = ((rule.mitre ?? {}) as Record<string, unknown>).id;
  const level = Number(rule.level ?? 0);
  return {
    id: h._id,
    index: h._index,
    timestamp: (s.timestamp as string) ?? '',
    ruleId: String(rule.id ?? ''),
    level,
    band: severityBand(level),
    description: (rule.description as string) ?? '',
    agent: (agent.name as string) ?? '',
    srcip: ((dataF.srcip ?? dataF.remip) as string) ?? null,
    mitre: Array.isArray(mitre) ? (mitre as string[]) : mitre ? [String(mitre)] : [],
    groups: Array.isArray(rule.groups) ? (rule.groups as string[]) : [],
  };
}

/** Documento completo de una alerta por _id (para el panel de detalle). */
export async function getAlertDetail(index: string, id: string): Promise<Record<string, unknown>> {
  if (!/^wazuh-alerts-[\w.\-*]+$/.test(index)) {
    throw new HttpError(400, 'Índice no permitido');
  }
  const client = getIndexerClient();
  try {
    const { data } = await client.get<{ _source: Record<string, unknown> }>(
      `/${encodeURIComponent(index)}/_doc/${encodeURIComponent(id)}`
    );
    return data._source ?? {};
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
