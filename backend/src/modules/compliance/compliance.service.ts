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
  total: number;
  controles: { id: string; count: number }[];
}
export type ComplianceData = { hours: number; frameworks: Record<string, FrameworkResult> };

const cache = new Map<number, { at: number; data: ComplianceData }>();
const TTL = 60_000;

export async function getCompliance(hours: number): Promise<ComplianceData> {
  const cached = cache.get(hours);
  if (cached && Date.now() - cached.at < TTL) return cached.data;

  const client = getIndexerClient();
  const aggs: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(FIELDS)) {
    aggs[`${key}_total`] = { filter: { exists: { field } } };
    aggs[`${key}_ctrl`] = { terms: { field, size: 40, order: { _count: 'desc' } } };
  }

  let data: { aggregations: Record<string, { doc_count?: number; buckets?: { key: string; doc_count: number }[] }> };
  try {
    const res = await client.post(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
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
    frameworks[key] = {
      total: data.aggregations[`${key}_total`]?.doc_count ?? 0,
      controles: (data.aggregations[`${key}_ctrl`]?.buckets ?? []).map((b) => ({ id: b.key, count: b.doc_count })),
    };
  }

  const result: ComplianceData = { hours, frameworks };
  cache.set(hours, { at: Date.now(), data: result });
  return result;
}
