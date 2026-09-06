/**
 * File Integrity Monitoring (FIM): cambios en archivos y claves de registro
 * detectados por syscheck (added / modified / deleted), con el usuario que los
 * realizo cuando esta disponible.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

export type FimEvent = 'added' | 'modified' | 'deleted';
export type FimCriticality = 'critica' | 'media' | 'baja';

export interface FimChange {
  path: string;
  event: FimEvent | string;
  mode: string;
  user: string;
  agent: string;
  level: number;
  sha256: string;
  timestamp: string;
  criticality: FimCriticality;
}

export interface FimData {
  resumen: { total: number; added: number; modified: number; deleted: number; agentes: number; criticos: number; signalOnly: boolean };
  porAgente: { agent: string; count: number }[];
  topPaths: { path: string; count: number; criticality: FimCriticality }[];
  recientes: FimChange[];
}

// Churn benigno de alto volumen que ahoga el FIM (telemetría del SO/virtualización,
// no cambios de seguridad). El lente "solo señal" (default) lo excluye; el toggle
// "ver todo" lo trae de vuelta. Substrings case-insensitive (sin backslashes para
// evitar el escape de wildcards de OpenSearch).
const FIM_NOISE_WILDCARDS = [
  '*lrm_status*',        // heartbeat del clúster Proxmox (se reescribe cada segundos)
  '*/etc/pve/*',         // estado interno de Proxmox
  '*services*diag*',     // registro \Services\*\Diag\ (diagnóstico VSS y otros)
  '*w32time*',           // servicio de hora de Windows
  '*sharedaccess*',      // registro del firewall/ICS
  '*dnscache*parameters*',
];

// Rutas sensibles: un cambio aquí es señal de persistencia/ataque, no churn.
// Nota: tareas bajo \Tasks\Microsoft\ son de Windows y cambian solas (UpdateOrchestrator,
// telemetría) → NO críticas; solo las tareas fuera de Microsoft son señal de persistencia.
const CRIT_FIM_RE = /(\\run\b|\\runonce|\\startup\\|\\programs\\startup|\\system32\\tasks\\(?!microsoft(\\|$))|\\drivers\\etc\\hosts|\\currentversion\\(run|winlogon|policies)|\\system32\\config\\|\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|\/etc\/cron|\/etc\/ssh\/sshd_config|authorized_keys|\/etc\/systemd\/|\/etc\/rc|\.ssh\/|\.(exe|dll|ps1|bat|vbs|scr|sh)$)/i;
// Zonas de sistema/config (impacto medio): binarios de sistema, /etc, Program Files, registro de servicios.
const MED_FIM_RE = /(\\system32\\|\\syswow64\\|\\program files|\\windows\\|\/etc\/|\/bin\/|\/sbin\/|\/usr\/(bin|sbin|lib)\/|\\currentcontrolset\\services\\)/i;

export function fimCriticality(path: string): FimCriticality {
  const p = path || '';
  if (CRIT_FIM_RE.test(p)) return 'critica';
  if (MED_FIM_RE.test(p)) return 'media';
  return 'baja';
}
const CRIT_RANK: Record<FimCriticality, number> = { critica: 0, media: 1, baja: 2 };

const cache = new Map<string, { at: number; data: FimData }>();
const TTL = 30_000;

export async function getFim(hours: number, signalOnly = true): Promise<FimData> {
  const key = `${hours}:${signalOnly}`;
  const cached = cache.get(key);
  if (cached && Date.now() - cached.at < TTL) return cached.data;

  const client = getIndexerClient();
  const mustNot = signalOnly
    ? FIM_NOISE_WILDCARDS.map((w) => ({ wildcard: { 'syscheck.path': { value: w, case_insensitive: true } } }))
    : [];
  const body = {
    size: 60,
    track_total_hits: true,
    sort: [{ timestamp: { order: 'desc' as const } }],
    _source: [
      'syscheck.path', 'syscheck.event', 'syscheck.mode', 'syscheck.uname_after',
      'syscheck.sha256_after', 'agent.name', 'rule.level', 'timestamp',
    ],
    query: {
      bool: {
        filter: [
          { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
          { exists: { field: 'syscheck.path' } },
        ],
        ...(mustNot.length ? { must_not: mustNot } : {}),
      },
    },
    aggs: {
      ev: { terms: { field: 'syscheck.event', size: 6 } },
      ag: { terms: { field: 'agent.name', size: 12 } },
      path: { terms: { field: 'syscheck.path', size: 12 } },
      agentes: { cardinality: { field: 'agent.name' } },
    },
  };

  let data: {
    hits: { total: { value: number }; hits: { _source: Record<string, unknown> }[] };
    aggregations: {
      ev: { buckets: { key: string; doc_count: number }[] };
      ag: { buckets: { key: string; doc_count: number }[] };
      path: { buckets: { key: string; doc_count: number }[] };
      agentes: { value: number };
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
    throw new HttpError(502, 'Error consultando File Integrity Monitoring');
  }

  const a = data.aggregations;
  const evCount = (e: string) => a.ev.buckets.find((b) => b.key === e)?.doc_count ?? 0;

  // Cambios recientes: los críticos primero (persistencia/ataque), luego por fecha.
  const recientes = data.hits.hits.map((h) => flatten(h._source));
  recientes.sort((x, y) => CRIT_RANK[x.criticality] - CRIT_RANK[y.criticality] || (x.timestamp < y.timestamp ? 1 : -1));

  const result: FimData = {
    resumen: {
      total: data.hits.total.value,
      added: evCount('added'),
      modified: evCount('modified'),
      deleted: evCount('deleted'),
      agentes: a.agentes.value,
      criticos: recientes.filter((c) => c.criticality === 'critica').length,
      signalOnly,
    },
    porAgente: a.ag.buckets.map((b) => ({ agent: b.key, count: b.doc_count })),
    topPaths: a.path.buckets
      .map((b) => ({ path: b.key, count: b.doc_count, criticality: fimCriticality(b.key) }))
      .sort((x, y) => CRIT_RANK[x.criticality] - CRIT_RANK[y.criticality] || y.count - x.count),
    recientes,
  };

  cache.set(key, { at: Date.now(), data: result });
  return result;
}

function flatten(src: Record<string, unknown>): FimChange {
  const sc = (src.syscheck ?? {}) as Record<string, unknown>;
  const agent = (src.agent ?? {}) as Record<string, unknown>;
  const rule = (src.rule ?? {}) as Record<string, unknown>;
  return {
    path: (sc.path as string) ?? '',
    event: (sc.event as string) ?? '',
    mode: (sc.mode as string) ?? '',
    user: (sc.uname_after as string) ?? '',
    agent: (agent.name as string) ?? '',
    level: (rule.level as number) ?? 0,
    sha256: (sc.sha256_after as string) ?? '',
    timestamp: (src.timestamp as string) ?? '',
    criticality: fimCriticality((sc.path as string) ?? ''),
  };
}
