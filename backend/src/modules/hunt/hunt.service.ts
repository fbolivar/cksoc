/**
 * Threat Hunting: busqueda ad-hoc sobre el indice de alertas de Wazuh, con
 * filtros por campo, texto libre y rango de tiempo, mas agregaciones (top
 * reglas, agentes, IPs de origen y tecnicas MITRE) para guiar la caceria.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';

export interface HuntParams {
  range?: string; // '24h' | '7d' | '30d' | ...
  from?: string;
  to?: string;
  q?: string; // texto libre sobre rule.description
  agent?: string;
  ruleId?: string;
  minLevel?: number;
  srcip?: string;
  mitre?: string;
  size?: number;
  page?: number;
}

export interface HuntHit {
  id: string;
  timestamp: string;
  ruleId: string;
  level: number;
  description: string;
  agent: string;
  srcip: string | null;
  mitre: string[];
}

export interface Bucket { key: string; count: number; label?: string }

export interface HuntResult {
  total: number;
  capped: boolean;
  items: HuntHit[];
  aggs: { rules: Bucket[]; agents: Bucket[]; srcips: Bucket[]; mitre: Bucket[] };
}

const MAX_WINDOW = 10000;

function timeFilter(p: HuntParams): unknown {
  if (p.from || p.to) {
    const r: Record<string, string> = {};
    if (p.from) r.gte = p.from;
    if (p.to) r.lte = p.to;
    return { range: { timestamp: r } };
  }
  const range = /^\d+[hdmw]$/.test(p.range ?? '') ? p.range : '24h';
  return { range: { timestamp: { gte: `now-${range}` } } };
}

export async function hunt(p: HuntParams): Promise<HuntResult> {
  const client = getIndexerClient();
  const filter: unknown[] = [timeFilter(p)];
  if (p.agent) filter.push({ term: { 'agent.name': p.agent } });
  if (p.ruleId) filter.push({ term: { 'rule.id': p.ruleId } });
  if (p.mitre) filter.push({ term: { 'rule.mitre.id': p.mitre } });
  if (typeof p.minLevel === 'number' && p.minLevel > 0) filter.push({ range: { 'rule.level': { gte: p.minLevel } } });
  if (p.srcip) {
    filter.push({
      bool: { should: [{ term: { 'data.srcip': p.srcip } }, { term: { 'data.remip': p.srcip } }], minimum_should_match: 1 },
    });
  }
  const must = p.q ? [{ match: { 'rule.description': { query: p.q, operator: 'and' } } }] : [];

  const size = Math.min(Math.max(p.size ?? 50, 1), 200);
  const page = Math.max(p.page ?? 0, 0);
  const from = Math.min(page * size, Math.max(0, MAX_WINDOW - size));

  const { data } = await client.post<{
    hits: { total: { value: number; relation: string }; hits: { _id: string; _source: Record<string, unknown> }[] };
    aggregations: Record<string, { buckets: { key: string | number; doc_count: number }[] }>;
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    track_total_hits: MAX_WINDOW,
    from,
    size,
    sort: [{ timestamp: { order: 'desc' } }],
    _source: ['timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.mitre.id', 'agent.name', 'data.srcip', 'data.remip'],
    query: { bool: { filter, ...(must.length ? { must } : {}) } },
    aggs: {
      rules: { terms: { field: 'rule.id', size: 10 } },
      agents: { terms: { field: 'agent.name', size: 10 } },
      srcips: { terms: { field: 'data.srcip', size: 10 } },
      mitre: { terms: { field: 'rule.mitre.id', size: 10 } },
    },
  });

  const items: HuntHit[] = data.hits.hits.map((h) => {
    const s = h._source;
    const rule = (s.rule ?? {}) as Record<string, unknown>;
    const agent = (s.agent ?? {}) as Record<string, unknown>;
    const dataF = (s.data ?? {}) as Record<string, unknown>;
    const mitre = ((rule.mitre ?? {}) as Record<string, unknown>).id;
    return {
      id: h._id,
      timestamp: (s.timestamp as string) ?? '',
      ruleId: String(rule.id ?? ''),
      level: Number(rule.level ?? 0),
      description: (rule.description as string) ?? '',
      agent: (agent.name as string) ?? '',
      srcip: ((dataF.srcip ?? dataF.remip) as string) ?? null,
      mitre: Array.isArray(mitre) ? (mitre as string[]) : mitre ? [String(mitre)] : [],
    };
  });

  // Etiqueta de reglas: descripcion tomada de los hits visibles.
  const ruleDesc = new Map<string, string>();
  for (const it of items) if (it.ruleId && !ruleDesc.has(it.ruleId)) ruleDesc.set(it.ruleId, it.description);

  const buckets = (name: string, withLabel = false): Bucket[] =>
    (data.aggregations?.[name]?.buckets ?? []).map((b) => ({
      key: String(b.key),
      count: b.doc_count,
      ...(withLabel ? { label: ruleDesc.get(String(b.key)) } : {}),
    }));

  return {
    total: data.hits.total.value,
    capped: data.hits.total.relation === 'gte',
    items,
    aggs: {
      rules: buckets('rules', true),
      agents: buckets('agents'),
      srcips: buckets('srcips'),
      mitre: buckets('mitre'),
    },
  };
}
