/**
 * Deteccion de Vulnerabilidades (Wazuh Vulnerability Detector).
 * Lee el indice de estado wazuh-states-vulnerabilities-* (CVEs vigentes por
 * agente y paquete) y construye resumen + top CVE + por agente + por paquete.
 */
import { getStatesClient } from '../wazuh/wazuh.client';
import { HttpError } from '../auth/auth.service';
import { getIntelMap, type CveIntel } from './cveintel.service';

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
  inKev: boolean;
  epss: number | null;
  priority: number;
}

/** CVE priorizada: la peor instancia por CVE, agregando instancias/agentes. */
export interface PrioritizedCve {
  cve: string;
  severity: Severity;
  score: number | null;
  inKev: boolean;
  kevDue: string | null;
  epss: number | null;
  epssPct: number | null;
  priority: number;
  instancias: number;
  agentes: number;
  description: string;
}

export interface VulnData {
  resumen: { total: number; critical: number; high: number; medium: number; low: number; agentes: number; cves: number; kev: number; exploitable: number };
  porSeveridad: { severity: Severity; count: number }[];
  topCve: { cve: string; count: number; severity: Severity; score: number | null; description: string; inKev: boolean; epss: number | null; priority: number }[];
  porAgente: { agent: string; total: number; critical: number; high: number }[];
  topPaquetes: { paquete: string; count: number }[];
  priorizadas: PrioritizedCve[];
  items: VulnItem[];
}

/** CVSS efectivo (usa el score si existe; si no, mapea por severidad). */
function cvssBase(sev: Severity, score: number | null): number {
  if (score != null) return score;
  return sev === 'Critical' ? 9 : sev === 'High' ? 7 : sev === 'Medium' ? 5 : sev === 'Low' ? 2 : 0;
}

/** Prioridad por riesgo real: CVSS + gran empujón si está en KEV + EPSS. */
export function priorityOf(sev: Severity, score: number | null, intel?: CveIntel): number {
  return Math.round(cvssBase(sev, score) * 6 + (intel?.inKev ? 45 : 0) + (intel?.epss ?? 0) * 40);
}

interface Bucket {
  key: string;
  doc_count: number;
}

let cache: { at: number; data: VulnData } | null = null;
const TTL = 60_000;

/** Invalida la caché (p. ej. tras refrescar la inteligencia de CVEs). */
export function invalidateCache(): void {
  cache = null;
}

export async function getVulnerabilities(): Promise<VulnData> {
  if (cache && Date.now() - cache.at < TTL) return cache.data;
  const client = getStatesClient();

  const body = {
    size: 100,
    // Sin esto, hits.total.value topa en 10.000 y el "total" del resumen queda
    // artificialmente truncado. Los conteos por severidad vienen de aggs (ya
    // exactos); esto corrige solo el gran total.
    track_total_hits: true,
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
      // TODOS los CVEs del entorno (liviano: sin top_hits) para priorizar sin el
      // sesgo del corte por CVSS. Aquí sí entran los KEV/EPSS de CVSS moderado.
      allcve: {
        terms: { field: 'vulnerability.id', size: 4000 },
        aggs: {
          sev: { terms: { field: 'vulnerability.severity', size: 1 } },
          sco: { max: { field: 'vulnerability.score.base' } },
          ag: { cardinality: { field: 'agent.name' } },
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
      allcve: { buckets: (Bucket & { sev: { buckets: Bucket[] }; sco: { value: number | null }; ag: { value: number } })[] };
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
      kev: 0,
      exploitable: 0,
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
        inKev: false,
        epss: null as number | null,
        priority: 0,
      };
    }),
    porAgente: a.porAgente.buckets.map((b) => ({
      agent: b.key,
      total: b.doc_count,
      critical: b.critical.doc_count,
      high: b.high.doc_count,
    })),
    topPaquetes: a.paquetes.buckets.map((b) => ({ paquete: b.key, count: b.doc_count })),
    priorizadas: [],
    items: data.hits.hits.map((h) => flatten(h._source)),
  };

  // Fuente de priorización: TODOS los CVEs (no solo el top-100 por CVSS).
  const prioSource = a.allcve.buckets.map((b) => ({
    cve: b.key,
    severity: (b.sev.buckets[0]?.key ?? '-') as Severity,
    score: b.sco.value ?? null,
    instancias: b.doc_count,
    agentes: b.ag.value,
  }));

  await enrichWithIntel(result, prioSource);

  cache = { at: Date.now(), data: result };
  return result;
}

/**
 * Enriquece items y topCve con KEV/EPSS, calcula la prioridad y arma la lista
 * "priorizadas" (peor instancia por CVE). Si la intel aún no está cargada, todo
 * queda con inKev=false/epss=null y la prioridad se basa solo en CVSS.
 */
interface PrioSource { cve: string; severity: Severity; score: number | null; instancias: number; agentes: number }

async function enrichWithIntel(result: VulnData, prioSource: PrioSource[]): Promise<void> {
  const cves = [...new Set([...prioSource.map((p) => p.cve), ...result.items.map((i) => i.cve), ...result.topCve.map((c) => c.cve)].filter(Boolean))];
  if (!cves.length) return;
  const intel = await getIntelMap(cves);

  for (const it of result.items) {
    const info = intel.get(it.cve.toUpperCase());
    it.inKev = info?.inKev ?? false;
    it.epss = info?.epss ?? null;
    it.priority = priorityOf(it.severity, it.score, info);
  }
  for (const c of result.topCve) {
    const info = intel.get(c.cve.toUpperCase());
    c.inKev = info?.inKev ?? false;
    c.epss = info?.epss ?? null;
    c.priority = priorityOf(c.severity, c.score, info);
  }
  // "Top CVE": ordenar por prioridad (no por conteo) y sacar los que no tienen datos
  // (severidad/CVSS nulos y sin intel) — dejaban prioridad negativa en el tope.
  result.topCve = result.topCve
    .filter((c) => c.inKev || c.epss != null || (c.score != null && c.severity !== '-'))
    .sort((x, y) => y.priority - x.priority);

  // Priorización REAL: sobre TODOS los CVEs del entorno (prioSource), no el top-100 por CVSS.
  const descMap = new Map<string, string>();
  for (const it of result.items) if (it.description && !descMap.has(it.cve)) descMap.set(it.cve, it.description);
  for (const c of result.topCve) if (c.description && !descMap.has(c.cve)) descMap.set(c.cve, c.description);

  const prio: PrioritizedCve[] = prioSource.map((p) => {
    const info = intel.get(p.cve.toUpperCase());
    return {
      cve: p.cve, severity: p.severity, score: p.score,
      inKev: info?.inKev ?? false, kevDue: info?.kevDue ?? null,
      epss: info?.epss ?? null, epssPct: info?.epssPct ?? null,
      priority: priorityOf(p.severity, p.score, info),
      instancias: p.instancias, agentes: p.agentes,
      description: descMap.get(p.cve) ?? '',
    };
  });
  prio.sort((x, y) => y.priority - x.priority);
  result.priorizadas = prio.slice(0, 30);

  // Contadores honestos sobre TODO el entorno (no solo el top 30).
  result.resumen.kev = prio.filter((p) => p.inKev).length;
  result.resumen.exploitable = prio.filter((p) => p.inKev || (p.epss ?? 0) >= 0.5).length;

  // Descripciones faltantes para el top 30 (una consulta pequeña).
  await fillDescriptions(result.priorizadas);
}

/** Rellena la descripción de los CVEs priorizados que no la traían (1 consulta acotada). */
async function fillDescriptions(list: PrioritizedCve[]): Promise<void> {
  const missing = list.filter((p) => !p.description).map((p) => p.cve);
  if (!missing.length) return;
  try {
    const { data } = await getStatesClient().post<{
      aggregations: { c: { buckets: { key: string; d: { hits: { hits: { _source: Record<string, unknown> }[] } } }[] } };
    }>(`/${INDEX}/_search`, {
      size: 0,
      query: { terms: { 'vulnerability.id': missing } },
      aggs: { c: { terms: { field: 'vulnerability.id', size: missing.length }, aggs: { d: { top_hits: { size: 1, _source: ['vulnerability.description'] } } } } },
    });
    const dmap = new Map<string, string>();
    for (const b of data.aggregations.c.buckets) {
      const v = (b.d.hits.hits[0]?._source?.vulnerability ?? {}) as Record<string, unknown>;
      if (v.description) dmap.set(b.key, v.description as string);
    }
    for (const p of list) if (!p.description) p.description = dmap.get(p.cve) ?? '';
  } catch { /* descripción es cosmética; si falla, se deja vacía */ }
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
    inKev: false,
    epss: null,
    priority: 0,
  };
}

function emptyData(): VulnData {
  return {
    resumen: { total: 0, critical: 0, high: 0, medium: 0, low: 0, agentes: 0, cves: 0, kev: 0, exploitable: 0 },
    porSeveridad: [],
    topCve: [],
    porAgente: [],
    topPaquetes: [],
    priorizadas: [],
    items: [],
  };
}
