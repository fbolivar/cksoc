/**
 * AI Security (aisec): Inventario de IA + Monitoreo de M365 Copilot.
 *
 * Primer bloque del "Módulo de Seguridad de IA" de HexWatch. En vivo (sin BD
 * propia), a partir de telemetría que ya se recolecta:
 *   - RED: servicios de IA generativa por SNI del SonicWall (reusa el catálogo
 *     de Shadow-AI) → quién usa qué IA desde la red (aprobado vs shadow).
 *   - IDENTIDAD: interacciones de Microsoft 365 Copilot (CopilotInteraction en
 *     el log de auditoría O365) → usuarios, apps, documentos tocados, y señales
 *     de seguridad (JailbreakDetected = intento de prompt-injection que el
 *     propio Microsoft marca).
 *
 * NO bloquea nada: visibilidad + gobierno + detección. Alineado conceptualmente
 * a OWASP Top 10 for Agentic AI (discovery, data exposure, prompt injection).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { AI_SERVICES } from '../shadowai/shadowai.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
function gteOf(rangeIn?: string): { range: string; gte: string } {
  const range = rangeIn && RANGE[rangeIn] ? rangeIn : '7d';
  return { range, gte: RANGE[range] };
}

/** Servicio de IA que corresponde a un hostname (SNI), o null. */
function matchService(hostname: string): { id: string; name: string; vendor: string } | null {
  const h = hostname.toLowerCase();
  for (const s of AI_SERVICES) {
    for (const d of s.domains) if (h === d || h.endsWith('.' + d)) return { id: s.id, name: s.name, vendor: s.vendor };
  }
  return null;
}

async function sanctionedMap(): Promise<Map<string, boolean>> {
  const m = new Map<string, boolean>();
  try {
    const rows = await query<{ service: string; sanctioned: boolean }>('SELECT service, sanctioned FROM shadow_ai_policy');
    for (const r of rows) m.set(r.service, r.sanctioned);
  } catch { /* tabla opcional */ }
  return m;
}

// ---------- RED: uso de IA por SNI ----------
export interface NetAiRow { service: string; name: string; vendor: string; devices: number; hits: number; lastSeen: string; sanctioned: boolean }

async function networkAiUsage(gte: string): Promise<NetAiRow[]> {
  const { data } = await getIndexerClient().post<{
    aggregations?: { dom: { buckets: { key: string; doc_count: number; src: { buckets: { key: string }[] }; last: { value_as_string?: string } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { exists: { field: 'data.hostname' } }] } },
    aggs: { dom: { terms: { field: 'data.hostname', size: 5000 }, aggs: { src: { terms: { field: 'data.srcip', size: 100 } }, last: { max: { field: '@timestamp' } } } } },
  });
  const sanc = await sanctionedMap();
  const acc = new Map<string, { name: string; vendor: string; devices: Set<string>; hits: number; last: string }>();
  for (const dom of data.aggregations?.dom?.buckets ?? []) {
    const svc = matchService(dom.key);
    if (!svc) continue;
    const cur = acc.get(svc.id) ?? { name: svc.name, vendor: svc.vendor, devices: new Set<string>(), hits: 0, last: '' };
    cur.hits += dom.doc_count;
    for (const s of dom.src.buckets) cur.devices.add(s.key);
    const last = dom.last?.value_as_string ?? '';
    if (last > cur.last) cur.last = last;
    acc.set(svc.id, cur);
  }
  return [...acc.entries()]
    .map(([service, v]) => ({ service, name: v.name, vendor: v.vendor, devices: v.devices.size, hits: v.hits, lastSeen: v.last, sanctioned: sanc.get(service) ?? false }))
    .sort((a, b) => b.hits - a.hits);
}

// ---------- COPILOT (M365) ----------
const COPILOT_FILTER = { term: { 'data.office365.Operation': 'CopilotInteraction' } };
const WORK_START = Number(process.env.AISEC_WORK_START ?? 6); // horario laboral (hora local servidor) para "fuera de horario"
const WORK_END = Number(process.env.AISEC_WORK_END ?? 20);

interface CopilotDoc {
  '@timestamp'?: string;
  data?: { office365?: { UserId?: string; ClientIP?: string; CopilotEventData?: { AppHost?: string; Contexts?: { Id?: string }[]; Messages?: { JailbreakDetected?: boolean }[] } } };
}

export interface CopilotInteractionRow { time: string; user: string; app: string; clientIp: string | null; jailbreak: boolean; contexts: string[] }
export interface CopilotSummary {
  range: string;
  interactions: number;
  users: number;
  jailbreakAttempts: number;
  offHours: number;
  byApp: { key: string; count: number }[];
  topUsers: { key: string; count: number }[];
  topResources: { resource: string; hits: number }[];
  jailbreakList: CopilotInteractionRow[];
  recent: CopilotInteractionRow[];
}

function shortResource(url: string): string {
  try { const u = new URL(url); const seg = u.pathname.split('/').filter(Boolean); return decodeURIComponent(seg[seg.length - 1] || u.hostname); }
  catch { const parts = url.split('/'); return parts[parts.length - 1] || url; }
}

export async function getCopilot(rangeIn?: string): Promise<CopilotSummary> {
  const { range, gte } = gteOf(rangeIn);
  const client = getIndexerClient();
  const source = ['@timestamp', 'data.office365.UserId', 'data.office365.ClientIP', 'data.office365.CopilotEventData.AppHost', 'data.office365.CopilotEventData.Contexts', 'data.office365.CopilotEventData.Messages'];

  const { data } = await client.post<{
    hits: { total: { value: number }; hits: { _source: CopilotDoc }[] };
    aggregations?: {
      byApp: { buckets: { key: string; doc_count: number }[] };
      topUsers: { buckets: { key: string; doc_count: number }[] };
      users: { value: number };
      jail: { doc_count: number };
    };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 200,
    _source: source,
    sort: [{ '@timestamp': { order: 'desc' } }],
    query: { bool: { filter: [COPILOT_FILTER, { range: { '@timestamp': { gte } } }] } },
    aggs: {
      byApp: { terms: { field: 'data.office365.CopilotEventData.AppHost', size: 12 } },
      topUsers: { terms: { field: 'data.office365.UserId', size: 15 } },
      users: { cardinality: { field: 'data.office365.UserId' } },
      jail: { filter: { term: { 'data.office365.CopilotEventData.Messages.JailbreakDetected': true } } },
    },
  });

  const toRow = (s: CopilotDoc): CopilotInteractionRow => {
    const o = s.data?.office365; const c = o?.CopilotEventData;
    return {
      time: s['@timestamp'] ?? '',
      user: o?.UserId ?? '—',
      app: c?.AppHost ?? '—',
      clientIp: o?.ClientIP ?? null,
      jailbreak: Array.isArray(c?.Messages) && c!.Messages!.some((m) => m?.JailbreakDetected === true),
      contexts: Array.isArray(c?.Contexts) ? c!.Contexts!.map((x) => x?.Id ?? '').filter(Boolean) : [],
    };
  };

  const docs = (data.hits?.hits ?? []).map((h) => toRow(h._source));

  // Top recursos (documentos tocados) sobre la muestra reciente.
  const resAcc = new Map<string, number>();
  let offHours = 0;
  for (const d of docs) {
    for (const url of d.contexts) resAcc.set(url, (resAcc.get(url) ?? 0) + 1);
    if (d.time) { const h = new Date(d.time).getHours(); if (h < WORK_START || h >= WORK_END) offHours += 1; }
  }
  const topResources = [...resAcc.entries()].map(([url, hits]) => ({ resource: shortResource(url), hits })).sort((a, b) => b.hits - a.hits).slice(0, 15);

  return {
    range,
    interactions: data.hits?.total?.value ?? 0,
    users: data.aggregations?.users?.value ?? 0,
    jailbreakAttempts: data.aggregations?.jail?.doc_count ?? 0,
    offHours,
    byApp: (data.aggregations?.byApp?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    topUsers: (data.aggregations?.topUsers?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    topResources,
    jailbreakList: docs.filter((d) => d.jailbreak).slice(0, 25),
    recent: docs.slice(0, 40),
  };
}

// ---------- INVENTARIO UNIFICADO ----------
export interface AiInventory {
  range: string;
  kpis: { aiServices: number; shadowServices: number; networkDevices: number; copilotInteractions: number; copilotUsers: number; jailbreakAttempts: number };
  network: NetAiRow[];
  copilot: { interactions: number; users: number; jailbreakAttempts: number; lastSeen: string; byApp: { key: string; count: number }[] };
}

export async function getInventory(rangeIn?: string): Promise<AiInventory> {
  const { range, gte } = gteOf(rangeIn);
  const [network, cop] = await Promise.all([networkAiUsage(gte), getCopilot(range)]);
  const devices = new Set<string>();
  for (const n of network) { /* devices por servicio ya contadas; aproximamos el total por suma de servicios únicos */ void n; }
  const networkDevices = network.reduce((mx, n) => Math.max(mx, n.devices), 0);
  const lastSeen = cop.recent[0]?.time ?? '';
  return {
    range,
    kpis: {
      aiServices: network.length + (cop.interactions > 0 ? 1 : 0),
      shadowServices: network.filter((n) => !n.sanctioned).length,
      networkDevices,
      copilotInteractions: cop.interactions,
      copilotUsers: cop.users,
      jailbreakAttempts: cop.jailbreakAttempts,
    },
    network,
    copilot: { interactions: cop.interactions, users: cop.users, jailbreakAttempts: cop.jailbreakAttempts, lastSeen, byApp: cop.byApp },
  };
}
