/**
 * MITRE ATT&CK: agrega las alertas mapeadas a tacticas y tecnicas de ATT&CK
 * (rule.mitre.*) para construir una matriz tipo Navigator y un top por severidad.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  count: number;
  maxLevel: number;
}

export interface MitreData {
  total: number;
  tecnicasDistintas: number;
  tactics: { tactic: string; count: number }[];
  techniques: MitreTechnique[];
}

const cache = new Map<number, { at: number; data: MitreData }>();
const TTL = 30_000;

export async function getMitre(hours: number): Promise<MitreData> {
  const cached = cache.get(hours);
  if (cached && Date.now() - cached.at < TTL) return cached.data;

  const client = getIndexerClient();
  const body = {
    size: 0,
    track_total_hits: true,
    query: {
      bool: {
        filter: [
          { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
          { exists: { field: 'rule.mitre.id' } },
        ],
      },
    },
    aggs: {
      tactics: { terms: { field: 'rule.mitre.tactic', size: 20 } },
      distintas: { cardinality: { field: 'rule.mitre.id' } },
      techniques: {
        terms: { field: 'rule.mitre.id', size: 80, order: { _count: 'desc' as const } },
        aggs: {
          info: { top_hits: { size: 1, _source: ['rule.mitre.technique', 'rule.mitre.tactic'] } },
          lvl: { max: { field: 'rule.level' } },
        },
      },
    },
  };

  let data: {
    hits: { total: { value: number } };
    aggregations: {
      tactics: { buckets: { key: string; doc_count: number }[] };
      distintas: { value: number };
      techniques: {
        buckets: {
          key: string;
          doc_count: number;
          lvl: { value: number | null };
          info: { hits: { hits: { _source: { rule: { mitre: { technique?: string[]; tactic?: string[] } } } }[] } };
        }[];
      };
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
    throw new HttpError(502, 'Error consultando MITRE ATT&CK');
  }

  const a = data.aggregations;
  const result: MitreData = {
    total: data.hits.total.value,
    tecnicasDistintas: a.distintas.value,
    tactics: a.tactics.buckets.map((b) => ({ tactic: b.key, count: b.doc_count })),
    techniques: a.techniques.buckets.map((b) => {
      const mitre = b.info.hits.hits[0]?._source?.rule?.mitre ?? {};
      const name = (mitre.technique ?? []).filter(Boolean).join(' / ') || b.key;
      return {
        id: b.key,
        name,
        tactics: mitre.tactic ?? [],
        count: b.doc_count,
        maxLevel: Math.round(b.lvl.value ?? 0),
      };
    }),
  };

  cache.set(hours, { at: Date.now(), data: result });
  return result;
}
