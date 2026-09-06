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

export type ScaImpact = 'alto' | 'medio' | 'contextual';

export interface FailedCheck {
  title: string;
  count: number;
  remediation: string;
  rationale: string;
  impact: ScaImpact;
}

export interface ScaData {
  resumen: {
    agentesEvaluados: number;
    agentesActivos: number;
    activosSinSca: string[];   // activos sin política SCA (punto ciego de hardening)
    scorePromedio: number;
    totalChecks: number;
    pass: number;
    fail: number;
    failAlto: number;          // tipos de check de ALTO impacto que fallan
  };
  agentes: ScaPolicy[];
  topFallidos: FailedCheck[];
}

// Clasifica un check CIS por impacto de seguridad real (los checks de Wazuh no
// traen severidad propia). Alto = ataca la superficie que un adversario usa
// (auth/NTLM, acceso remoto, privilegios, red, auditoría). Contextual = depende
// de infraestructura (BitLocker) o es de UI/telemetría/módulos L2, baja prioridad.
const RE_CONTEXTUAL = /bitlocker|widget|universal windows|\buwp\b|cortana|cloud consumer|telemetry|onedrive|xbox|lock screen|start layout|kernel module|cramfs|freevxfs|jffs2|\bhfs\b|\budf\b|squashfs|gfs2|usb.*storage|screen ?saver|toast|spotlight/i;
const RE_ALTO = /lan manager|ntlm|kerberos|password|lockout|credential|anonymous|guest account|null session|\bsmb\b|remote desktop|\brdp\b|telnet|\bssh\b|root login|\bsudo\b|\buac\b|user account control|privilege|administrator|firewall|\baudit\b|logging|log ?on|logoff|remote access|winrm|powershell|\brpc\b|kerberos|encryption oracle|restrict.*client|controlled folder/i;

export function impactFor(title: string): ScaImpact {
  const t = title || '';
  if (RE_CONTEXTUAL.test(t)) return 'contextual';
  if (RE_ALTO.test(t)) return 'alto';
  return 'medio';
}
const IMPACT_RANK: Record<ScaImpact, number> = { alto: 0, medio: 1, contextual: 2 };

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

  // Cobertura honesta: qué agentes ACTIVOS no tienen política SCA (punto ciego).
  const conSca = new Set(policies.map((p) => p.agentId));
  const activosSinSca = agents.filter((a) => !conSca.has(a.id)).map((a) => a.name);
  const failAlto = topFallidos.filter((c) => c.impact === 'alto').length;

  const result: ScaData = {
    resumen: {
      agentesEvaluados: conSca.size,
      agentesActivos: agents.length,
      activosSinSca,
      scorePromedio, totalChecks, pass, fail, failAlto,
    },
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
          terms: { field: 'data.sca.check.title', size: 40 },
          aggs: { info: { top_hits: { size: 1, _source: ['data.sca.check.remediation', 'data.sca.check.rationale'] } } },
        },
      },
    });
    const checks: FailedCheck[] = data.aggregations.chk.buckets.map((b) => {
      const src = b.info.hits.hits[0]?._source ?? {};
      const sca = (((src.data as Record<string, unknown>)?.sca as Record<string, unknown>)?.check ?? {}) as Record<string, unknown>;
      return {
        title: b.key,
        count: b.doc_count,
        remediation: (sca.remediation as string) ?? '',
        rationale: (sca.rationale as string) ?? '',
        impact: impactFor(b.key),
      };
    });
    // Orden por impacto (alto primero), luego por cuántos equipos lo fallan.
    checks.sort((a, b) => IMPACT_RANK[a.impact] - IMPACT_RANK[b.impact] || b.count - a.count);
    return checks;
  } catch {
    return [];
  }
}
