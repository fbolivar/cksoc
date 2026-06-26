/**
 * Configuration Assessment (SCA): postura de hardening (CIS) por agente.
 * Combina el estado actual de las politicas (Wazuh API /sca/{agent}) con el
 * detalle de los checks fallidos mas comunes (alertas data.sca.*).
 */
import { wazuhApiGet } from '../wazuh/wazuh.api.client';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';

export interface ScaPolicy {
  agentId: string;
  agent: string;
  os: string;
  policyId: string;
  policy: string;
  score: number;
  pass: number;
  fail: number;
  total: number;
  endScan: string | null;
}

export interface FailedCheck {
  title: string;
  count: number;
  remediation: string;
  rationale: string;
}

export interface ScaData {
  resumen: { agentesEvaluados: number; scorePromedio: number; totalChecks: number; pass: number; fail: number };
  agentes: ScaPolicy[];
  topFallidos: FailedCheck[];
}

interface AgentRow { id: string; name: string; os?: { platform?: string } }
interface PolicyRow {
  policy_id: string; name: string; pass: number; fail: number; total_checks: number; score: number; end_scan?: string;
}

let cache: { at: number; data: ScaData } | null = null;
const TTL = 5 * 60_000;

export async function getSca(): Promise<ScaData> {
  if (cache && Date.now() - cache.at < TTL) return cache.data;

  // 1. Agentes activos
  const agentsResp = await wazuhApiGet<{ affected_items: AgentRow[] }>('/agents', {
    select: 'id,name,os.platform', status: 'active', limit: 100,
  });
  const agents = agentsResp.affected_items.filter((a) => a.id !== '000');

  // 2. Politicas SCA por agente (en paralelo, tolerante a fallos)
  const policies: ScaPolicy[] = [];
  await Promise.all(
    agents.map(async (a) => {
      try {
        const sca = await wazuhApiGet<{ affected_items: PolicyRow[] }>(`/sca/${a.id}`);
        for (const p of sca.affected_items ?? []) {
          policies.push({
            agentId: a.id,
            agent: a.name,
            os: a.os?.platform ?? '',
            policyId: p.policy_id,
            policy: p.name,
            score: p.score ?? 0,
            pass: p.pass ?? 0,
            fail: p.fail ?? 0,
            total: p.total_checks ?? 0,
            endScan: p.end_scan ?? null,
          });
        }
      } catch {
        /* agente sin SCA todavia */
      }
    })
  );
  policies.sort((a, b) => a.score - b.score); // peor postura primero

  // 3. Checks fallidos mas comunes (alertas)
  const topFallidos = await topFailedChecks();

  const pass = policies.reduce((s, p) => s + p.pass, 0);
  const fail = policies.reduce((s, p) => s + p.fail, 0);
  const totalChecks = policies.reduce((s, p) => s + p.total, 0);
  const scorePromedio = policies.length
    ? Math.round(policies.reduce((s, p) => s + p.score, 0) / policies.length)
    : 0;

  const result: ScaData = {
    resumen: { agentesEvaluados: policies.length, scorePromedio, totalChecks, pass, fail },
    agentes: policies,
    topFallidos,
  };
  cache = { at: Date.now(), data: result };
  return result;
}

async function topFailedChecks(): Promise<FailedCheck[]> {
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{
      aggregations: {
        chk: {
          buckets: { key: string; doc_count: number; info: { hits: { hits: { _source: Record<string, unknown> }[] } } }[];
        };
      };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: {
        bool: {
          filter: [
            { range: { timestamp: { gte: 'now-30d' } } },
            { term: { 'data.sca.check.result': 'failed' } },
          ],
        },
      },
      aggs: {
        chk: {
          terms: { field: 'data.sca.check.title', size: 15 },
          aggs: { info: { top_hits: { size: 1, _source: ['data.sca.check.remediation', 'data.sca.check.rationale'] } } },
        },
      },
    });
    return data.aggregations.chk.buckets.map((b) => {
      const src = b.info.hits.hits[0]?._source ?? {};
      const sca = (((src.data as Record<string, unknown>)?.sca as Record<string, unknown>)?.check ?? {}) as Record<string, unknown>;
      return {
        title: b.key,
        count: b.doc_count,
        remediation: (sca.remediation as string) ?? '',
        rationale: (sca.rationale as string) ?? '',
      };
    });
  } catch {
    return [];
  }
}
