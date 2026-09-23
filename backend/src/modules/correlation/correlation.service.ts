/**
 * Correlación multi-fuente: agrupa las alertas por IP de origen y detecta cuando
 * la misma IP la ven varias fuentes (SonicWall IPS + Wazuh) o varios hosts, para
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

// FP de exfiltración benigna (regla 100600 sobre tráfico interno/DVR/HexDesk): se
// excluye de la correlación para que no infle las IPs internas. Mismo patrón que NDR/MITRE.
const BENIGN_100600 = {
  bool: {
    filter: [{ term: { 'rule.id': '100600' } }],
    minimum_should_match: 1,
    should: [
      { prefix: { 'data.dstip': '192.168.' } },
      { prefix: { 'data.dstip': '10.' } },
      { match_phrase: { 'data.srcip': '192.168.0.31' } },
      { terms: { 'data.dstip': ['40.160.225.24', '209.250.254.15'] } },
    ],
  },
};

export async function getCorrelations(range: string, externalOnly = true): Promise<Correlation[]> {
  const gte = /^\d+[hd]$/.test(range) ? `now-${range}` : 'now-24h';
  const client = getIndexerClient();
  const { data } = await client.post<{ aggregations?: { ips: { buckets: Bucket[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: { bool: {
        filter: [{ range: { '@timestamp': { gte } } }, { exists: { field: 'data.srcip' } }],
        must_not: [BENIGN_100600],
      } },
      aggs: {
        ips: {
          terms: { field: 'data.srcip', size: 400, order: { maxlevel: 'desc' } },
          aggs: {
            maxlevel: { max: { field: 'rule.level' } },
            rulescard: { cardinality: { field: 'rule.id' } },
            agents: { terms: { field: 'agent.name', size: 6 } },
            forti: { filter: { terms: { 'decoder.name': ['fortigate-firewall-v5', 'sonicwall'] } } },
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
    // "Solo externas": una IP INTERNA correlacionando su propio tráfico no es un
    // ataque; el valor real está en las IPs EXTERNAS (atacantes) vistas por varias
    // fuentes. En modo externo se omiten las privadas.
    const external = isPublicIP(b.key);
    if (externalOnly && !external) continue;
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

    // Reponderado: prioriza EXTERNO, cross-source e IOC (señales de ataque real)
    // por encima del volumen crudo, que antes hacía ganar a las IPs internas ruidosas.
    const score =
      maxLevel * 7 +
      distinctRules * 3 +
      agents.length * 5 +
      (crossSource ? 30 : 0) +
      (iocSource ? 50 : 0) +
      (external ? 20 : 0) +
      Math.min(15, Math.round(Math.log2(count + 1) * 3));

    out.push({
      srcip: b.key,
      external,
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
