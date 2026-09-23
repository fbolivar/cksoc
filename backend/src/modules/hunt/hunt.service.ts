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
  signalOnly?: boolean; // lente "señal de caza": excluye la telemetría benigna de alto volumen
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
  signalOnly: boolean;
  items: HuntHit[];
  aggs: { rules: Bucket[]; agents: Bucket[]; srcips: Bucket[]; mitre: Bucket[] };
}

const MAX_WINDOW = 10000; // límite de la ventana from+size de OpenSearch (paginación)

// Lente "señal de caza": telemetría benigna de alto volumen que ahoga la caza.
// (medido en vivo: estas 5 reglas = ~1.0M de 1.24M eventos/7d). El texto libre y
// los filtros por técnica siguen abiertos; el toggle "ver todo" las trae de vuelta.
const NOISE_RULE_IDS = ['81633', '80792', '550', '752', '91578', '100205', '100207', '100700', '5501'];
//  81633 Forti "App passed" · 80792 audit systemd · 550 FIM checksum · 752 registry value · 91578 O365 MailItemsAccessed
const NOISE_GROUPS = ['sca', 'vulnerability-detector'];

/** Convierte texto libre en wildcards case-insensitive sobre rule.description (que es keyword). */
function textClauses(q: string): unknown[] {
  return q.trim().toLowerCase().split(/\s+/).filter(Boolean)
    .map((tok) => ({ wildcard: { 'rule.description': { value: `*${tok}*`, case_insensitive: true } } }));
}

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
  // Texto libre → wildcard case-insensitive (rule.description es keyword; `match` no matchea parcial).
  const must = p.q ? textClauses(p.q) : [];

  // Lente señal: quita la telemetría benigna de alto volumen (sin cegar la búsqueda cruda).
  const mustNot: unknown[] = p.signalOnly
    ? [{ terms: { 'rule.id': NOISE_RULE_IDS } }, { terms: { 'rule.groups': NOISE_GROUPS } }]
    : [];

  const size = Math.min(Math.max(p.size ?? 50, 1), 200);
  const page = Math.max(p.page ?? 0, 0);
  const from = Math.min(page * size, Math.max(0, MAX_WINDOW - size));

  const { data } = await client.post<{
    hits: { total: { value: number; relation: string }; hits: { _id: string; _source: Record<string, unknown> }[] };
    aggregations: Record<string, { buckets: { key: string | number; doc_count: number }[] }>;
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    track_total_hits: true, // total exacto (antes se capaba en 10.000 y el conteo mentía)
    from,
    size,
    sort: [{ timestamp: { order: 'desc' } }],
    _source: ['timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.mitre.id', 'agent.name', 'data.srcip', 'data.remip'],
    query: { bool: { filter, ...(must.length ? { must } : {}), ...(mustNot.length ? { must_not: mustNot } : {}) } },
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
    // Con track_total_hits:true el total es exacto; "capped" avisa que solo se pueden
    // paginar los primeros MAX_WINDOW resultados (límite de OpenSearch), no que el conteo sea parcial.
    capped: data.hits.total.value > MAX_WINDOW,
    signalOnly: Boolean(p.signalOnly),
    items,
    aggs: {
      rules: buckets('rules', true),
      agents: buckets('agents'),
      srcips: buckets('srcips'),
      mitre: buckets('mitre'),
    },
  };
}
