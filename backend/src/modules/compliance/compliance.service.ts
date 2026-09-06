/**
 * Cumplimiento normativo: agrega las alertas mapeadas a controles de los marcos
 * NIST 800-53, GDPR, TSC (SOC 2), PCI DSS e HIPAA (rule.<marco>).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

const FIELDS: Record<string, string> = {
  nist: 'rule.nist_800_53',
  gdpr: 'rule.gdpr',
  tsc: 'rule.tsc',
  pci: 'rule.pci_dss',
  hipaa: 'rule.hipaa',
};

export interface FrameworkResult {
  total: number;              // alertas de SEGURIDAD (sin ruido) mapeadas al marco
  controlesCubiertos: number; // controles distintos con monitoreo (cobertura)
  controles: { id: string; count: number; level: number }[];
}
export type ComplianceData = { hours: number; frameworks: Record<string, FrameworkResult> };

// Ruido benigno de alto volumen que ahoga los mapeos de cumplimiento (el mismo
// que en los demás módulos). Sin esto, "revisión de logs/auditoría" (AU.6, PCI
// 10.6.1, HIPAA 164.312.b) suma ~900k de tráfico benigno y el conteo miente.
const COMPLIANCE_NOISE = [
  { terms: { 'rule.id': ['81633', '80792', '550', '752', '91578'] } }, // Forti app-passed, audit systemd, FIM checksum, registry, O365 MailItemsAccessed
  { terms: { 'rule.groups': ['sca', 'vulnerability-detector'] } },
  // 100600 benigno (exfil interna/DVR): egress a RFC1918. El externo real se conserva.
  { bool: { filter: [{ term: { 'rule.id': '100600' } }, { bool: { should: [{ prefix: { 'data.dstip': '192.168.' } }, { prefix: { 'data.dstip': '10.' } }, { prefix: { 'data.dstip': '172.' } }], minimum_should_match: 1 } }] } },
];

const cache = new Map<number, { at: number; data: ComplianceData }>();
const TTL = 60_000;

export async function getCompliance(hours: number): Promise<ComplianceData> {
  const cached = cache.get(hours);
  if (cached && Date.now() - cached.at < TTL) return cached.data;

  const client = getIndexerClient();
  const aggs: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(FIELDS)) {
    aggs[`${key}_total`] = { filter: { exists: { field } } };
    aggs[`${key}_cov`] = { cardinality: { field } };
    aggs[`${key}_ctrl`] = {
      terms: { field, size: 40, order: { _count: 'desc' } },
      aggs: { lvl: { max: { field: 'rule.level' } } },
    };
  }

  let data: { aggregations: Record<string, { doc_count?: number; value?: number; buckets?: { key: string; doc_count: number; lvl?: { value: number | null } }[] }> };
  try {
    const res = await client.post(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      // Excluye el ruido benigno: los conteos reflejan eventos de seguridad reales por control.
      query: { bool: { filter: [{ range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } }], must_not: COMPLIANCE_NOISE } },
      aggs,
    });
    data = res.data;
  } catch (err) {
    const e = err as { code?: string };
    if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') {
      throw new HttpError(502, 'No se pudo conectar al Wazuh Indexer');
    }
    throw new HttpError(502, 'Error consultando cumplimiento');
  }

  const frameworks: Record<string, FrameworkResult> = {};
  for (const key of Object.keys(FIELDS)) {
    const controles = (data.aggregations[`${key}_ctrl`]?.buckets ?? []).map((b) => ({
      id: b.key, count: b.doc_count, level: Math.round(b.lvl?.value ?? 0),
    }));
    // Orden por severidad (nivel máx) y luego por conteo — no por volumen de logs.
    controles.sort((a, b) => b.level - a.level || b.count - a.count);
    frameworks[key] = {
      total: data.aggregations[`${key}_total`]?.doc_count ?? 0,
      controlesCubiertos: data.aggregations[`${key}_cov`]?.value ?? 0,
      controles,
    };
  }

  const result: ComplianceData = { hours, frameworks };
  cache.set(hours, { at: Date.now(), data: result });
  return result;
}
