/**
 * MITRE ATT&CK: agrega las alertas mapeadas a tacticas y tecnicas de ATT&CK
 * (rule.mitre.*) para construir una matriz tipo Navigator y un top por severidad.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { wazuhApiGet } from '../wazuh/wazuh.api.client';
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

// ---------------------------------------------------------------------
// Cobertura de detección: técnicas detectadas (observadas en alertas) vs. el
// total del marco ATT&CK, por táctica. Revela puntos ciegos.
// ---------------------------------------------------------------------

export interface TacticCoverage {
  tactic: string;
  total: number;      // técnicas del marco en esa táctica
  detected: number;   // técnicas distintas detectadas en alertas
  coverage: number;   // %
  alerts: number;     // volumen de alertas de la táctica
}
export interface CoverageData {
  days: number;
  tacticsTotal: number;
  tacticsCovered: number;
  tacticsBlind: number;
  techniquesDetected: number;
  tactics: TacticCoverage[];
}

const normKey = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

// El marco (tácticas + total de técnicas por táctica) cambia rara vez: cache larga.
let frameworkCache: { at: number; byTactic: Map<string, { name: string; total: number }> } | null = null;
const FW_TTL = 6 * 60 * 60 * 1000; // 6h

async function getFramework(): Promise<Map<string, { name: string; total: number }>> {
  if (frameworkCache && Date.now() - frameworkCache.at < FW_TTL) return frameworkCache.byTactic;
  const tac = await wazuhApiGet<{ affected_items: { id: string; name: string }[] }>('/mitre/tactics', { limit: 200 });
  const uuidToName = new Map(tac.affected_items.map((t) => [t.id, t.name]));
  const tech = await wazuhApiGet<{ affected_items: { external_id: string; tactics: string[] }[] }>('/mitre/techniques', { limit: 2000, select: 'external_id,tactics' });
  const byTactic = new Map<string, { name: string; total: number }>();
  for (const [, name] of uuidToName) byTactic.set(normKey(name), { name, total: 0 });
  for (const t of tech.affected_items) {
    for (const uuid of t.tactics ?? []) {
      const name = uuidToName.get(uuid);
      if (!name) continue;
      const entry = byTactic.get(normKey(name));
      if (entry) entry.total += 1;
    }
  }
  frameworkCache = { at: Date.now(), byTactic };
  return byTactic;
}

export async function getCoverage(days: number): Promise<CoverageData> {
  const framework = await getFramework();

  // Técnicas detectadas por táctica (observadas en alertas del rango).
  const client = getIndexerClient();
  const { data } = await client.post<{
    aggregations?: { tac: { buckets: { key: string; doc_count: number; tech: { buckets: { key: string }[] } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { timestamp: { gte: `now-${days}d`, lte: 'now' } } }, { exists: { field: 'rule.mitre.tactic' } }] } },
    aggs: { tac: { terms: { field: 'rule.mitre.tactic', size: 30 }, aggs: { tech: { terms: { field: 'rule.mitre.id', size: 300 } } } } },
  });

  const detectedByTactic = new Map<string, { alerts: number; techs: Set<string> }>();
  for (const b of data.aggregations?.tac?.buckets ?? []) {
    detectedByTactic.set(normKey(b.key), { alerts: b.doc_count, techs: new Set(b.tech.buckets.map((x) => x.key)) });
  }

  const tactics: TacticCoverage[] = [];
  const allDetected = new Set<string>();
  for (const [key, fw] of framework) {
    const det = detectedByTactic.get(key);
    const detected = det ? det.techs.size : 0;
    det?.techs.forEach((t) => allDetected.add(t));
    tactics.push({
      tactic: fw.name,
      total: fw.total,
      detected,
      coverage: fw.total > 0 ? Math.round((detected / fw.total) * 100) : 0,
      alerts: det?.alerts ?? 0,
    });
  }
  tactics.sort((a, b) => a.coverage - b.coverage || b.total - a.total);

  return {
    days,
    tacticsTotal: tactics.length,
    tacticsCovered: tactics.filter((t) => t.detected > 0).length,
    tacticsBlind: tactics.filter((t) => t.detected === 0).length,
    techniquesDetected: allDetected.size,
    tactics,
  };
}
