/**
 * Deteccion de Vulnerabilidades (Wazuh Vulnerability Detector).
 * Lee el indice de estado wazuh-states-vulnerabilities-* (CVEs vigentes por
 * agente y paquete) y construye resumen + top CVE + por agente + por paquete.
 */
import { getStatesClient } from '../wazuh/wazuh.client';
import { HttpError } from '../auth/auth.service';

const INDEX = 'wazuh-states-vulnerabilities-*';
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const;
export type Severity = (typeof SEVERITIES)[number] | '-';

export interface VulnItem {
  cve: string;
  severity: Severity;
  score: number | null;
  packageName: string;
  packageVersion: string;
  agent: string;
  os: string;
  description: string;
  detectedAt: string | null;
  publishedAt: string | null;
  reference: string | null;
}

export interface VulnData {
  resumen: { total: number; critical: number; high: number; medium: number; low: number; agentes: number; cves: number };
  porSeveridad: { severity: Severity; count: number }[];
  topCve: { cve: string; count: number; severity: Severity; score: number | null; description: string }[];
  porAgente: { agent: string; total: number; critical: number; high: number }[];
  topPaquetes: { paquete: string; count: number }[];
  items: VulnItem[];
}

interface Bucket {
  key: string;
  doc_count: number;
}

let cache: { at: number; data: VulnData } | null = null;
const TTL = 60_000;

export async function getVulnerabilities(): Promise<VulnData> {
  if (cache && Date.now() - cache.at < TTL) return cache.data;
  const client = getStatesClient();

  const body = {
    size: 100,
    sort: [{ 'vulnerability.score.base': { order: 'desc', missing: '_last' } }],
    _source: [
      'vulnerability.id', 'vulnerability.severity', 'vulnerability.score.base', 'vulnerability.description',
      'vulnerability.detected_at', 'vulnerability.published_at', 'vulnerability.reference',
      'package.name', 'package.version', 'agent.name', 'host.os.full',
    ],
    aggs: {
      sev: { terms: { field: 'vulnerability.severity', size: 8 } },
      cves: { cardinality: { field: 'vulnerability.id' } },
      agentes: { cardinality: { field: 'agent.name' } },
      cve: {
        terms: { field: 'vulnerability.id', size: 12, order: { _count: 'desc' } },
        aggs: {
          info: {
            top_hits: {
              size: 1,
              _source: ['vulnerability.severity', 'vulnerability.score.base', 'vulnerability.description'],
            },
          },
        },
      },
      porAgente: {
        terms: { field: 'agent.name', size: 12 },
        aggs: {
          critical: { filter: { term: { 'vulnerability.severity': 'Critical' } } },
          high: { filter: { term: { 'vulnerability.severity': 'High' } } },
        },
      },
      paquetes: { terms: { field: 'package.name', size: 10 } },
    },
  };

  let data: {
    hits: { total: { value: number }; hits: { _source: Record<string, unknown> }[] };
    aggregations: {
      sev: { buckets: Bucket[] };
      cves: { value: number };
      agentes: { value: number };
      cve: { buckets: (Bucket & { info: { hits: { hits: { _source: Record<string, unknown> }[] } } })[] };
      porAgente: { buckets: (Bucket & { critical: { doc_count: number }; high: { doc_count: number } })[] };
      paquetes: { buckets: Bucket[] };
    };
  };
  try {
    const res = await client.post(`/${INDEX}/_search`, body);
    data = res.data;
  } catch (err) {
    const e = err as { response?: { status?: number } };
    if (e.response?.status === 404 || e.response?.status === 403) {
      // Indice aun no creado (modulo sin reportar todavia): devolver vacio limpio.
      return emptyData();
    }
    throw new HttpError(502, 'No se pudo consultar el índice de vulnerabilidades');
  }

  const a = data.aggregations;
  const sevCount = (s: string) => a.sev.buckets.find((b) => b.key === s)?.doc_count ?? 0;

  const result: VulnData = {
    resumen: {
      total: data.hits.total.value,
      critical: sevCount('Critical'),
      high: sevCount('High'),
      medium: sevCount('Medium'),
      low: sevCount('Low'),
      agentes: a.agentes.value,
      cves: a.cves.value,
    },
    porSeveridad: a.sev.buckets.map((b) => ({ severity: b.key as Severity, count: b.doc_count })),
    topCve: a.cve.buckets.map((b) => {
      const src = (b.info.hits.hits[0]?._source ?? {}) as Record<string, unknown>;
      const vuln = (src.vulnerability ?? {}) as Record<string, unknown>;
      const score = (vuln.score ?? {}) as Record<string, unknown>;
      return {
        cve: b.key,
        count: b.doc_count,
        severity: (vuln.severity as Severity) ?? '-',
        score: (score.base as number) ?? null,
        description: (vuln.description as string) ?? '',
      };
    }),
    porAgente: a.porAgente.buckets.map((b) => ({
      agent: b.key,
      total: b.doc_count,
      critical: b.critical.doc_count,
      high: b.high.doc_count,
    })),
    topPaquetes: a.paquetes.buckets.map((b) => ({ paquete: b.key, count: b.doc_count })),
    items: data.hits.hits.map((h) => flatten(h._source)),
  };

  cache = { at: Date.now(), data: result };
  return result;
}

function flatten(src: Record<string, unknown>): VulnItem {
  const vuln = (src.vulnerability ?? {}) as Record<string, unknown>;
  const score = (vuln.score ?? {}) as Record<string, unknown>;
  const pkg = (src.package ?? {}) as Record<string, unknown>;
  const agent = (src.agent ?? {}) as Record<string, unknown>;
  const host = (src.host ?? {}) as Record<string, unknown>;
  const os = (host.os ?? {}) as Record<string, unknown>;
  return {
    cve: (vuln.id as string) ?? '',
    severity: (vuln.severity as Severity) ?? '-',
    score: (score.base as number) ?? null,
    packageName: (pkg.name as string) ?? '',
    packageVersion: (pkg.version as string) ?? '',
    agent: (agent.name as string) ?? '',
    os: (os.full as string) ?? '',
    description: (vuln.description as string) ?? '',
    detectedAt: (vuln.detected_at as string) ?? null,
    publishedAt: (vuln.published_at as string) ?? null,
    reference: (vuln.reference as string) ?? null,
  };
}

function emptyData(): VulnData {
  return {
    resumen: { total: 0, critical: 0, high: 0, medium: 0, low: 0, agentes: 0, cves: 0 },
    porSeveridad: [],
    topCve: [],
    porAgente: [],
    topPaquetes: [],
    items: [],
  };
}
