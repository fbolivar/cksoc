/**
 * Vista por Activo (Asset 360): consolida TODO sobre un agente — estado, alertas,
 * vulnerabilidades, hardening (SCA), integridad (FIM) e inventario — reutilizando
 * los servicios de cada modulo, filtrado por agente.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { wazuhApiGet } from '../wazuh/wazuh.api.client';
import { env } from '../../config/env';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { getSca } from '../sca/sca.service';
import { getSummary as getHygieneSummary } from '../hygiene/hygiene.service';

export type AssetKind = 'servidor' | 'estacion';
// Salud operativa REAL (no solo el estado crudo del agente):
//  ok = reportando · apagado = estación offline reciente (normal, horario de oficina)
//  investigar = offline demasiado tiempo · alerta = un servidor caído · fantasma = registrado y nunca conectó
export type AssetHealth = 'ok' | 'apagado' | 'investigar' | 'alerta' | 'fantasma';

export interface AssetListItem {
  id: string;
  name: string;
  status: string;
  ip: string;
  os: string;
  version: string;
  lastKeepAlive: string | null;
  kind: AssetKind;
  staleDays: number | null;   // días desde el último keepalive (null si nunca)
  health: AssetHealth;
  reason: string;             // explicación en lenguaje llano
  needsAttention: boolean;    // punto ciego real (fantasma/investigar/alerta)
}

// Una estación puede estar apagada varios días (fin de semana); más de esto ya es raro.
const STALE_DAYS = 7;

/** Servidor vs estación: por SO (Linux/Windows Server) y nombre de infraestructura. */
function classifyKind(os: string, name: string): AssetKind {
  const o = (os || '').toLowerCase();
  if (/ubuntu|debian|linux|centos|red\s?hat|windows server|server\b/.test(o)) return 'servidor';
  if (/(^|[-_])(gvm-soc|pmx|srv|soc)([-_]|$)/i.test(name)) return 'servidor';
  return 'estacion'; // Windows 10/11 Pro y demás = estación de trabajo
}

/** Clasifica la salud operativa a partir del estado + antigüedad + tipo. */
function classifyHealth(status: string, staleDays: number | null, kind: AssetKind): { health: AssetHealth; reason: string } {
  if (status === 'active') return { health: 'ok', reason: 'Reportando normalmente.' };
  if (status === 'never_connected' || staleDays === null)
    return { health: 'fantasma', reason: 'Registrado pero NUNCA reportó: instalación fallida o equipo inexistente. Limpiar el registro o reinstalar el agente.' };
  if (staleDays >= STALE_DAYS)
    return { health: 'investigar', reason: `Sin reportar hace ${staleDays} días: probablemente dado de baja, dañado o con el agente detenido. Revisar.` };
  if (kind === 'servidor')
    return { health: 'alerta', reason: `Servidor caído (sin reportar hace ${staleDays} día(s)): un servidor no debería estar desconectado.` };
  return { health: 'apagado', reason: `Estación apagada hace ${staleDays} día(s): normal fuera de horario/fin de semana.` };
}

interface AgentApi {
  id: string; name: string; status: string; ip?: string; version?: string;
  os?: { name?: string }; lastKeepAlive?: string;
}

export async function getAssetList(): Promise<AssetListItem[]> {
  const d = await wazuhApiGet<{ affected_items: AgentApi[] }>('/agents', {
    select: 'id,name,status,ip,os.name,version,lastKeepAlive', limit: 500, sort: 'name',
  });
  const now = Date.now();
  return d.affected_items
    .filter((a) => a.id !== '000')
    .map((a) => {
      const os = a.os?.name ?? '';
      const lastKeepAlive = a.lastKeepAlive && !a.lastKeepAlive.startsWith('9999') ? a.lastKeepAlive : null;
      const staleDays = lastKeepAlive ? Math.floor((now - Date.parse(lastKeepAlive)) / 86400000) : null;
      const kind = classifyKind(os, a.name);
      const { health, reason } = classifyHealth(a.status, staleDays, kind);
      return {
        id: a.id, name: a.name, status: a.status, ip: a.ip ?? '', os, version: a.version ?? '',
        lastKeepAlive, kind, staleDays, health, reason,
        needsAttention: health === 'fantasma' || health === 'investigar' || health === 'alerta',
      };
    });
}

export interface AssetCoverage {
  total: number;
  reporting: number;            // activos
  servers: { total: number; reporting: number };
  workstations: { total: number; reporting: number };
  needsAttention: AssetListItem[];  // puntos ciegos reales (no estaciones apagadas)
  offNormal: number;            // estaciones apagadas (normal)
}

/** Resumen de cobertura honesto: separa servidores de estaciones y aísla los puntos ciegos reales. */
export async function getAssetCoverage(): Promise<{ coverage: AssetCoverage; assets: AssetListItem[] }> {
  const assets = await getAssetList();
  const servers = assets.filter((a) => a.kind === 'servidor');
  const workstations = assets.filter((a) => a.kind === 'estacion');
  const coverage: AssetCoverage = {
    total: assets.length,
    reporting: assets.filter((a) => a.status === 'active').length,
    servers: { total: servers.length, reporting: servers.filter((a) => a.status === 'active').length },
    workstations: { total: workstations.length, reporting: workstations.filter((a) => a.status === 'active').length },
    needsAttention: assets.filter((a) => a.needsAttention).sort((x, y) => (y.staleDays ?? 99999) - (x.staleDays ?? 99999)),
    offNormal: assets.filter((a) => a.health === 'apagado').length,
  };
  return { coverage, assets };
}

export interface AssetDetail {
  meta: AssetListItem;
  alertas: { total7d: number; critica: number; alta: number; media: number; baja: number; topReglas: { desc: string; count: number }[] };
  vulnerabilidades: { total: number; criticas: number; altas: number; top: { cve: string; severity: string; score: number | null }[] };
  hardening: { policy: string; score: number; pass: number; fail: number } | null;
  fim: { total30d: number; added: number; modified: number; deleted: number; recientes: { path: string; event: string; user: string; ts: string }[] };
  inventario: { cpu: string; cores: number; ramGB: number; packages: number; ports: number; users: number; hotfixes: number } | null;
}

export async function getAsset(name: string): Promise<AssetDetail | null> {
  const list = await getAssetList();
  const meta = list.find((a) => a.name === name);
  if (!meta) return null;

  const [alertas, fim, vuln, sca, hyg] = await Promise.all([
    alertsForAgent(name),
    fimForAgent(name),
    getVulnerabilities().catch(() => null),
    getSca().catch(() => null),
    getHygieneSummary().catch(() => null),
  ]);

  const vAg = vuln?.porAgente.find((a) => a.agent === name);
  const vTop = (vuln?.items ?? []).filter((i) => i.agent === name).slice(0, 5).map((i) => ({ cve: i.cve, severity: i.severity, score: i.score }));
  const scaAg = sca?.agentes.find((a) => a.agent === name);
  const host = hyg?.hosts.find((h) => h.agent === name);

  return {
    meta,
    alertas,
    vulnerabilidades: { total: vAg?.total ?? 0, criticas: vAg?.critical ?? 0, altas: vAg?.high ?? 0, top: vTop },
    hardening: scaAg ? { policy: scaAg.policy, score: scaAg.score, pass: scaAg.pass, fail: scaAg.fail } : null,
    fim,
    inventario: host ? { cpu: host.cpu, cores: host.cores, ramGB: host.ramGB, packages: host.packages, ports: host.ports, users: host.users, hotfixes: host.hotfixes } : null,
  };
}

async function alertsForAgent(name: string): Promise<AssetDetail['alertas']> {
  const client = getIndexerClient();
  const base = [{ range: { timestamp: { gte: 'now-7d' } } }, { term: { 'agent.name': name } }];
  const lvl = (r: Record<string, number>) => ({ filter: { bool: { filter: [...base, { range: { 'rule.level': r } }] } } });
  try {
    const { data } = await client.post<{
      hits: { total: { value: number } };
      aggregations: {
        critica: { doc_count: number }; alta: { doc_count: number }; media: { doc_count: number }; baja: { doc_count: number };
        topr: { buckets: { key: string; doc_count: number }[] };
      };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0, track_total_hits: true,
      query: { bool: { filter: base } },
      aggs: {
        critica: lvl({ gte: 12 }), alta: lvl({ gte: 8, lte: 11 }), media: lvl({ gte: 5, lte: 7 }), baja: lvl({ lte: 4 }),
        topr: { terms: { field: 'rule.description', size: 5 } },
      },
    });
    const a = data.aggregations;
    return {
      total7d: data.hits.total.value,
      critica: a.critica.doc_count, alta: a.alta.doc_count, media: a.media.doc_count, baja: a.baja.doc_count,
      topReglas: a.topr.buckets.map((b) => ({ desc: b.key, count: b.doc_count })),
    };
  } catch {
    return { total7d: 0, critica: 0, alta: 0, media: 0, baja: 0, topReglas: [] };
  }
}

async function fimForAgent(name: string): Promise<AssetDetail['fim']> {
  const client = getIndexerClient();
  try {
    const { data } = await client.post<{
      hits: { total: { value: number }; hits: { _source: Record<string, unknown> }[] };
      aggregations: { ev: { buckets: { key: string; doc_count: number }[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 5, track_total_hits: true,
      sort: [{ timestamp: { order: 'desc' } }],
      _source: ['syscheck.path', 'syscheck.event', 'syscheck.uname_after', 'timestamp'],
      query: { bool: { filter: [{ range: { timestamp: { gte: 'now-30d' } } }, { term: { 'agent.name': name } }, { exists: { field: 'syscheck.path' } }] } },
      aggs: { ev: { terms: { field: 'syscheck.event', size: 6 } } },
    });
    const ev = (e: string) => data.aggregations.ev.buckets.find((b) => b.key === e)?.doc_count ?? 0;
    return {
      total30d: data.hits.total.value,
      added: ev('added'), modified: ev('modified'), deleted: ev('deleted'),
      recientes: data.hits.hits.map((h) => {
        const sc = ((h._source.syscheck ?? {}) as Record<string, unknown>);
        return { path: (sc.path as string) ?? '', event: (sc.event as string) ?? '', user: (sc.uname_after as string) ?? '', ts: (h._source.timestamp as string) ?? '' };
      }),
    };
  } catch {
    return { total30d: 0, added: 0, modified: 0, deleted: 0, recientes: [] };
  }
}
