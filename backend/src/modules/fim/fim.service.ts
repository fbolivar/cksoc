/**
 * File Integrity Monitoring (FIM): cambios en archivos y claves de registro
 * detectados por syscheck (added / modified / deleted), con el usuario que los
 * realizo cuando esta disponible.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

export type FimEvent = 'added' | 'modified' | 'deleted';

export interface FimChange {
  path: string;
  event: FimEvent | string;
  mode: string;
  user: string;
  agent: string;
  level: number;
  sha256: string;
  timestamp: string;
}

export interface FimData {
  resumen: { total: number; added: number; modified: number; deleted: number; agentes: number };
  porAgente: { agent: string; count: number }[];
  topPaths: { path: string; count: number }[];
  recientes: FimChange[];
}

const cache = new Map<number, { at: number; data: FimData }>();
const TTL = 30_000;

export async function getFim(hours: number): Promise<FimData> {
  const cached = cache.get(hours);
  if (cached && Date.now() - cached.at < TTL) return cached.data;

  const client = getIndexerClient();
  const body = {
    size: 60,
    track_total_hits: true,
    sort: [{ timestamp: { order: 'desc' as const } }],
    _source: [
      'syscheck.path', 'syscheck.event', 'syscheck.mode', 'syscheck.uname_after',
      'syscheck.sha256_after', 'agent.name', 'rule.level', 'timestamp',
    ],
    query: {
      bool: {
        filter: [
          { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
          { exists: { field: 'syscheck.path' } },
        ],
      },
    },
    aggs: {
      ev: { terms: { field: 'syscheck.event', size: 6 } },
      ag: { terms: { field: 'agent.name', size: 12 } },
      path: { terms: { field: 'syscheck.path', size: 12 } },
      agentes: { cardinality: { field: 'agent.name' } },
    },
  };

  let data: {
    hits: { total: { value: number }; hits: { _source: Record<string, unknown> }[] };
    aggregations: {
      ev: { buckets: { key: string; doc_count: number }[] };
      ag: { buckets: { key: string; doc_count: number }[] };
      path: { buckets: { key: string; doc_count: number }[] };
      agentes: { value: number };
    };
  };
  try {
    const res = await client.post(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
    data = res.data;
  } catch (err) {
    const e = err as { code?: string };
    if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') {
      throw new HttpError(502, 'No se pudo conectar al Wazuh Indexer');
    }
    throw new HttpError(502, 'Error consultando File Integrity Monitoring');
  }

  const a = data.aggregations;
  const evCount = (e: string) => a.ev.buckets.find((b) => b.key === e)?.doc_count ?? 0;

  const result: FimData = {
    resumen: {
      total: data.hits.total.value,
      added: evCount('added'),
      modified: evCount('modified'),
      deleted: evCount('deleted'),
      agentes: a.agentes.value,
    },
    porAgente: a.ag.buckets.map((b) => ({ agent: b.key, count: b.doc_count })),
    topPaths: a.path.buckets.map((b) => ({ path: b.key, count: b.doc_count })),
    recientes: data.hits.hits.map((h) => flatten(h._source)),
  };

  cache.set(hours, { at: Date.now(), data: result });
  return result;
}

function flatten(src: Record<string, unknown>): FimChange {
  const sc = (src.syscheck ?? {}) as Record<string, unknown>;
  const agent = (src.agent ?? {}) as Record<string, unknown>;
  const rule = (src.rule ?? {}) as Record<string, unknown>;
  return {
    path: (sc.path as string) ?? '',
    event: (sc.event as string) ?? '',
    mode: (sc.mode as string) ?? '',
    user: (sc.uname_after as string) ?? '',
    agent: (agent.name as string) ?? '',
    level: (rule.level as number) ?? 0,
    sha256: (sc.sha256_after as string) ?? '',
    timestamp: (src.timestamp as string) ?? '',
  };
}
