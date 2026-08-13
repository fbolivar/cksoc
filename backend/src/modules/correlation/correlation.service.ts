/**
 * Correlación multi-fuente: agrupa las alertas por IP de origen y detecta cuando
 * la misma IP la ven varias fuentes (FortiGate IPS + Wazuh) o varios hosts, para
 * presentar UN caso en vez de N alertas sueltas. Enriquecido con IOCs.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { isPublicIP } from '../geo/geoip.service';
import { query } from '../../config/db';
import { env } from '../../config/env';

export interface Correlation {
  srcip: string;
  external: boolean;
  count: number;
  maxLevel: number;
  band: 'baja' | 'media' | 'alta' | 'critica';
  distinctRules: number;
  agents: string[];
  fortiCount: number;
  wazuhCount: number;
  crossSource: boolean;
  firstSeen: string;
  lastSeen: string;
  sampleRule: string;
  mitre: string[];
  iocSource: string | null;
  score: number;
}

function band(level: number): Correlation['band'] {
  if (level >= 12) return 'critica';
  if (level >= 8) return 'alta';
  if (level >= 5) return 'media';
  return 'baja';
}

interface Bucket {
  key: string;
  doc_count: number;
  maxlevel: { value: number | null };
  rulescard: { value: number };
  agents: { buckets: { key: string }[] };
  forti: { doc_count: number };
  firstseen: { value_as_string?: string };
  lastseen: { value_as_string?: string };
  sample: { hits: { hits: { _source: { rule?: { description?: string } } }[] } };
  mitre: { buckets: { key: string }[] };
}

export async function getCorrelations(range: string): Promise<Correlation[]> {
  const gte = /^\d+[hd]$/.test(range) ? `now-${range}` : 'now-24h';
  const client = getIndexerClient();
  const { data } = await client.post<{ aggregations?: { ips: { buckets: Bucket[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { exists: { field: 'data.srcip' } }] } },
      aggs: {
        ips: {
          terms: { field: 'data.srcip', size: 400, order: { maxlevel: 'desc' } },
          aggs: {
            maxlevel: { max: { field: 'rule.level' } },
            rulescard: { cardinality: { field: 'rule.id' } },
            agents: { terms: { field: 'agent.name', size: 6 } },
            forti: { filter: { term: { 'decoder.name': 'fortigate-firewall-v5' } } },
            firstseen: { min: { field: '@timestamp' } },
            lastseen: { max: { field: '@timestamp' } },
            sample: { top_hits: { size: 1, sort: [{ 'rule.level': { order: 'desc' } }], _source: ['rule.description'] } },
            mitre: { terms: { field: 'rule.mitre.id', size: 4 } },
          },
        },
      },
    }
  );

  const buckets = data.aggregations?.ips?.buckets ?? [];

  // IOCs de IP para enriquecer.
  const iocRows = await query<{ value: string; source: string }>(
    "SELECT value, source FROM iocs WHERE ioc_type = 'ip' AND enabled = TRUE"
  ).catch(() => [] as { value: string; source: string }[]);
  const iocMap = new Map(iocRows.map((r) => [r.value, r.source]));

  const out: Correlation[] = [];
  for (const b of buckets) {
    // Ignora IPv6 link-local/multicast/loopback: nunca son un origen accionable.
    if (/^(fe80|ff0|::1|fec0)/i.test(b.key)) continue;
    const count = b.doc_count;
    const maxLevel = Math.round(b.maxlevel.value ?? 0);
    const fortiCount = b.forti.doc_count;
    const wazuhCount = count - fortiCount;
    const distinctRules = b.rulescard.value;
    const agents = b.agents.buckets.map((x) => x.key);
    const crossSource = fortiCount > 0 && wazuhCount > 0;
    const iocSource = iocMap.get(b.key) ?? null;

    // Filtro de relevancia: descarta ruido (poca actividad y baja severidad).
    if (count < 3 && maxLevel < 8 && !iocSource) continue;

    const score =
      maxLevel * 8 +
      distinctRules * 3 +
      agents.length * 4 +
      (crossSource ? 25 : 0) +
      (iocSource ? 40 : 0) +
      Math.min(20, Math.round(Math.log2(count + 1) * 3));

    out.push({
      srcip: b.key,
      external: isPublicIP(b.key),
      count,
      maxLevel,
      band: band(maxLevel),
      distinctRules,
      agents,
      fortiCount,
      wazuhCount,
      crossSource,
      firstSeen: b.firstseen.value_as_string ?? '',
      lastSeen: b.lastseen.value_as_string ?? '',
      sampleRule: b.sample.hits.hits[0]?._source?.rule?.description ?? '',
      mitre: b.mitre.buckets.map((x) => x.key),
      iocSource,
      score,
    });
  }

  out.sort((a, b) => b.score - a.score);
  return out.slice(0, 60);
}
