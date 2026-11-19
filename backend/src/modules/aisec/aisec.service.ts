/**
 * AI Security (aisec): Inventario de IA + Monitoreo de M365 Copilot +
 * Exfiltración a GenAI + Grafo de riesgo de IA + Postura OWASP Agentic / AIVSS.
 *
 * Módulo de Seguridad de IA de HexWatch. En vivo (sin BD propia), sobre
 * telemetría ya recolectada:
 *   - RED: servicios de IA generativa por SNI del SonicWall (catálogo Shadow-AI)
 *     y BYTES SUBIDOS (data.sentbyte) → señal de exfiltración a GenAI.
 *   - IDENTIDAD: interacciones de M365 Copilot (CopilotInteraction en O365):
 *     usuarios, apps, documentos tocados y JailbreakDetected (prompt-injection).
 *
 * Visibilidad + gobierno + detección (no bloquea). Mapeo a OWASP Top 10 for
 * Agentic AI con severidad estilo AIVSS.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { AI_SERVICES } from '../shadowai/shadowai.service';
import { getAssetList } from '../assets/assets.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
function gteOf(rangeIn?: string): { range: string; gte: string } {
  const range = rangeIn && RANGE[rangeIn] ? rangeIn : '7d';
  return { range, gte: RANGE[range] };
}
const clamp = (n: number, lo = 0, hi = 100): number => Math.max(lo, Math.min(hi, Math.round(n)));
const MB = 1024 * 1024;
const EXFIL_MB = Number(process.env.AISEC_EXFIL_MB ?? 20);
const WORK_START = Number(process.env.AISEC_WORK_START ?? 6);
const WORK_END = Number(process.env.AISEC_WORK_END ?? 20);
function isOffHours(ts: string): boolean { if (!ts) return false; const h = new Date(ts).getHours(); return h < WORK_START || h >= WORK_END; }

function matchService(hostname: string): { id: string; name: string; vendor: string } | null {
  const h = hostname.toLowerCase();
  for (const s of AI_SERVICES) for (const d of s.domains) if (h === d || h.endsWith('.' + d)) return { id: s.id, name: s.name, vendor: s.vendor };
  return null;
}

async function sanctionedMap(): Promise<Map<string, boolean>> {
  const m = new Map<string, boolean>();
  try {
    const rows = await query<{ service: string; sanctioned: boolean }>('SELECT service, sanctioned FROM shadow_ai_policy');
    for (const r of rows) m.set(r.service, r.sanctioned);
  } catch { /* opcional */ }
  return m;
}
// M365 Copilot (identidad) es la herramienta oficial → aprobado salvo que la política diga lo contrario.
function copilotSanctioned(sanc: Map<string, boolean>): boolean { return sanc.get('m365_copilot') ?? true; }

async function nameByIp(): Promise<Map<string, string>> {
  const m = new Map<string, string>();
  try { for (const a of await getAssetList()) if (a.ip) m.set(a.ip, a.name); } catch { /* best-effort */ }
  return m;
}

// ---------- RED: uso de IA por SNI ----------
export interface NetAiRow { service: string; name: string; vendor: string; devices: number; hits: number; lastSeen: string; sanctioned: boolean }

async function networkAiUsage(gte: string, sanc: Map<string, boolean>): Promise<NetAiRow[]> {
  const { data } = await getIndexerClient().post<{
    aggregations?: { dom: { buckets: { key: string; doc_count: number; src: { buckets: { key: string }[] }; last: { value_as_string?: string } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { exists: { field: 'data.hostname' } }] } },
    aggs: { dom: { terms: { field: 'data.hostname', size: 5000 }, aggs: { src: { terms: { field: 'data.srcip', size: 200 } }, last: { max: { field: '@timestamp' } } } } },
  });
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

// ---------- EXFILTRACIÓN a GenAI (bytes subidos) ----------
export interface ExfilRow { srcip: string; host: string | null; service: string; name: string; sentMB: number; rcvdMB: number; hits: number; lastSeen: string; sanctioned: boolean; flagged: boolean }
export interface ExfilSummary { range: string; thresholdMB: number; totalSentMB: number; flagged: number; rows: ExfilRow[] }

// data.sentbyte/rcvdbyte están mapeados como KEYWORD (texto) → no se pueden sumar
// directo; se parsean a long con un script Painless. Y se pre-filtra a dominios
// de IA (wildcards) para que el scripted-sum sea barato.
const SENT_SUM = { sum: { script: { source: "def a=doc['data.sentbyte']; if(a.size()==0) return 0L; try { return Long.parseLong(a.value); } catch(Exception e){ return 0L; }" } } };
const RCVD_SUM = { sum: { script: { source: "def a=doc['data.rcvdbyte']; if(a.size()==0) return 0L; try { return Long.parseLong(a.value); } catch(Exception e){ return 0L; }" } } };
function aiHostnameShould(): { wildcard: { 'data.hostname': string } }[] {
  const doms = new Set<string>(); for (const s of AI_SERVICES) for (const d of s.domains) doms.add(d);
  return [...doms].map((d) => ({ wildcard: { 'data.hostname': `*${d}` } }));
}

async function exfilCompute(gte: string, sanc: Map<string, boolean>): Promise<Omit<ExfilSummary, 'range'>> {
  const ipName = await nameByIp();
  try {
    const { data } = await getIndexerClient().post<{
      aggregations?: { dom: { buckets: { key: string; doc_count: number; src: { buckets: { key: string; doc_count: number; sent: { value: number }; rcvd: { value: number }; last: { value_as_string?: string } }[] } }[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { exists: { field: 'data.hostname' } }], should: aiHostnameShould(), minimum_should_match: 1 } },
      aggs: {
        dom: {
          terms: { field: 'data.hostname', size: 500 },
          aggs: { src: { terms: { field: 'data.srcip', size: 200 }, aggs: { sent: SENT_SUM, rcvd: RCVD_SUM, last: { max: { field: '@timestamp' } } } } },
        },
      },
    });
    const acc = new Map<string, { srcip: string; service: string; name: string; sent: number; rcvd: number; hits: number; last: string }>();
    for (const dom of data.aggregations?.dom?.buckets ?? []) {
      const svc = matchService(dom.key);
      if (!svc) continue;
      for (const src of dom.src.buckets) {
        const key = `${src.key}|${svc.id}`;
        const cur = acc.get(key) ?? { srcip: src.key, service: svc.id, name: svc.name, sent: 0, rcvd: 0, hits: 0, last: '' };
        cur.sent += src.sent?.value ?? 0; cur.rcvd += src.rcvd?.value ?? 0; cur.hits += src.doc_count;
        const last = src.last?.value_as_string ?? ''; if (last > cur.last) cur.last = last;
        acc.set(key, cur);
      }
    }
    const rows: ExfilRow[] = [...acc.values()].map((v) => {
      const sentMB = +(v.sent / MB).toFixed(2);
      return { srcip: v.srcip, host: ipName.get(v.srcip) ?? null, service: v.service, name: v.name, sentMB, rcvdMB: +(v.rcvd / MB).toFixed(2), hits: v.hits, lastSeen: v.last, sanctioned: sanc.get(v.service) ?? false, flagged: sentMB >= EXFIL_MB };
    }).sort((a, b) => b.sentMB - a.sentMB).slice(0, 100);
    return { thresholdMB: EXFIL_MB, totalSentMB: +rows.reduce((s, r) => s + r.sentMB, 0).toFixed(2), flagged: rows.filter((r) => r.flagged).length, rows };
  } catch {
    return { thresholdMB: EXFIL_MB, totalSentMB: 0, flagged: 0, rows: [] };
  }
}

export async function getExfiltration(rangeIn?: string): Promise<ExfilSummary> {
  const { range, gte } = gteOf(rangeIn);
  return { range, ...(await exfilCompute(gte, await sanctionedMap())) };
}

// ---------- COPILOT (M365) ----------
const COPILOT_FILTER = { term: { 'data.office365.Operation': 'CopilotInteraction' } };
interface AccRes { Action?: string; Type?: string; Name?: string; SiteUrl?: string; XPIADetected?: boolean }
interface CopilotDoc { '@timestamp'?: string; data?: { office365?: { UserId?: string; ClientIP?: string; AppIdentity?: string; CopilotEventData?: { AppHost?: string; Contexts?: { Id?: string }[]; Messages?: { JailbreakDetected?: boolean }[]; AccessedResources?: AccRes[] } } } }
export interface CopilotInteractionRow { time: string; user: string; app: string; agent: string | null; clientIp: string | null; jailbreak: boolean; xpia: boolean; contexts: string[] }
export interface AiAgent { id: string; label: string; interactions: number; builtin: boolean }
export interface CitationRow { url: string; type: string; hits: number }
export interface CopilotSummary {
  range: string; interactions: number; users: number; jailbreakAttempts: number; xpiaAttempts: number; offHours: number; sanctioned: boolean;
  byApp: { key: string; count: number }[]; topUsers: { key: string; count: number }[];
  topResources: { resource: string; hits: number }[]; agents: AiAgent[]; externalCitations: number; topCitations: CitationRow[];
  jailbreakList: CopilotInteractionRow[]; xpiaList: CopilotInteractionRow[]; recent: CopilotInteractionRow[];
}
function shortResource(url: string): string {
  try { const u = new URL(url); const seg = u.pathname.split('/').filter(Boolean); return decodeURIComponent(seg[seg.length - 1] || u.hostname); }
  catch { const parts = url.split(/[\\/]/); return parts[parts.length - 1] || url; }
}
// AppIdentity "MicrosoftAgent.<Nombre>.<Id>" o "Copilot.M365Copilot.Apps" → nombre de agente o null (Copilot estándar).
function agentOf(appIdentity?: string): { id: string; label: string; builtin: boolean } | null {
  if (!appIdentity) return null;
  if (appIdentity.startsWith('Copilot.M365Copilot')) return null; // superficie estándar de Copilot
  const parts = appIdentity.split('.');
  const label = parts.length >= 2 ? parts[1] : appIdentity;
  return { id: appIdentity, label, builtin: appIdentity.startsWith('MicrosoftAgent.') };
}

export async function getCopilot(rangeIn?: string): Promise<CopilotSummary> {
  const { range, gte } = gteOf(rangeIn);
  const sanc = await sanctionedMap();
  const source = ['@timestamp', 'data.office365.UserId', 'data.office365.ClientIP', 'data.office365.AppIdentity', 'data.office365.CopilotEventData.AppHost', 'data.office365.CopilotEventData.Contexts', 'data.office365.CopilotEventData.Messages', 'data.office365.CopilotEventData.AccessedResources'];
  const { data } = await getIndexerClient().post<{
    hits: { total: { value: number }; hits: { _source: CopilotDoc }[] };
    aggregations?: { byApp: { buckets: { key: string; doc_count: number }[] }; topUsers: { buckets: { key: string; doc_count: number }[] }; users: { value: number }; jail: { doc_count: number }; xpia: { doc_count: number }; appId: { buckets: { key: string; doc_count: number }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 200, _source: source, sort: [{ '@timestamp': { order: 'desc' } }],
    query: { bool: { filter: [COPILOT_FILTER, { range: { '@timestamp': { gte } } }] } },
    aggs: {
      byApp: { terms: { field: 'data.office365.CopilotEventData.AppHost', size: 12 } },
      topUsers: { terms: { field: 'data.office365.UserId', size: 15 } },
      users: { cardinality: { field: 'data.office365.UserId' } },
      jail: { filter: { term: { 'data.office365.CopilotEventData.Messages.JailbreakDetected': true } } },
      xpia: { filter: { term: { 'data.office365.CopilotEventData.AccessedResources.XPIADetected': true } } },
      appId: { terms: { field: 'data.office365.AppIdentity', size: 30 } },
    },
  });
  const toRow = (s: CopilotDoc): CopilotInteractionRow => {
    const o = s.data?.office365; const c = o?.CopilotEventData;
    const ag = agentOf(o?.AppIdentity);
    return {
      time: s['@timestamp'] ?? '', user: o?.UserId ?? '—', app: c?.AppHost ?? '—', agent: ag?.label ?? null, clientIp: o?.ClientIP ?? null,
      jailbreak: Array.isArray(c?.Messages) && c!.Messages!.some((m) => m?.JailbreakDetected === true),
      xpia: Array.isArray(c?.AccessedResources) && c!.AccessedResources!.some((r) => r?.XPIADetected === true),
      contexts: Array.isArray(c?.Contexts) ? c!.Contexts!.map((x) => x?.Id ?? '').filter(Boolean) : [],
    };
  };
  const hits = data.hits?.hits ?? [];
  const docs = hits.map((h) => toRow(h._source));
  const resAcc = new Map<string, number>(); const citAcc = new Map<string, { type: string; hits: number }>(); let offHours = 0;
  for (let i = 0; i < docs.length; i++) {
    const d = docs[i]; const ar = hits[i]._source.data?.office365?.CopilotEventData?.AccessedResources ?? [];
    for (const url of d.contexts) resAcc.set(url, (resAcc.get(url) ?? 0) + 1);
    for (const r of ar) { const u = r.SiteUrl || r.Name; if (u && /^https?:\/\//i.test(u)) { const cur = citAcc.get(u) ?? { type: r.Type || 'CITATION', hits: 0 }; cur.hits += 1; citAcc.set(u, cur); } }
    if (isOffHours(d.time)) offHours += 1;
  }
  const topResources = [...resAcc.entries()].map(([url, h]) => ({ resource: shortResource(url), hits: h })).sort((a, b) => b.hits - a.hits).slice(0, 15);
  const topCitations = [...citAcc.entries()].map(([url, v]) => ({ url, type: v.type, hits: v.hits })).sort((a, b) => b.hits - a.hits).slice(0, 15);
  const agents: AiAgent[] = (data.aggregations?.appId?.buckets ?? [])
    .map((b) => ({ ag: agentOf(b.key), count: b.doc_count })).filter((x) => x.ag)
    .map((x) => ({ id: x.ag!.id, label: x.ag!.label, interactions: x.count, builtin: x.ag!.builtin }));
  return {
    range, interactions: data.hits?.total?.value ?? 0, users: data.aggregations?.users?.value ?? 0,
    jailbreakAttempts: data.aggregations?.jail?.doc_count ?? 0, xpiaAttempts: data.aggregations?.xpia?.doc_count ?? 0,
    offHours, sanctioned: copilotSanctioned(sanc),
    byApp: (data.aggregations?.byApp?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    topUsers: (data.aggregations?.topUsers?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    topResources, agents, externalCitations: topCitations.reduce((s, c) => s + c.hits, 0), topCitations,
    jailbreakList: docs.filter((d) => d.jailbreak).slice(0, 25), xpiaList: docs.filter((d) => d.xpia).slice(0, 25), recent: docs.slice(0, 40),
  };
}

// ---------- A2: uso de IA de una entidad (para enriquecer el grafo XDR) ----------
export interface AiEntityNode { id: string; label: string; weight: number; shadow: boolean; risk: number }
export async function aiUsageForEntity(type: 'ip' | 'host' | 'user' | 'domain', value: string, rangeIn?: string): Promise<AiEntityNode[]> {
  const { gte } = gteOf(rangeIn);
  const sanc = await sanctionedMap();
  try {
    if (type === 'user') {
      const { data } = await getIndexerClient().post<{ hits: { total: { value: number } }; aggregations?: { jail: { doc_count: number } } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
        size: 0, track_total_hits: true,
        query: { bool: { filter: [COPILOT_FILTER, { range: { '@timestamp': { gte } } }, { term: { 'data.office365.UserId': value } }] } },
        aggs: { jail: { filter: { term: { 'data.office365.CopilotEventData.Messages.JailbreakDetected': true } } } },
      });
      const n = data.hits?.total?.value ?? 0; if (!n) return [];
      const jb = data.aggregations?.jail?.doc_count ?? 0;
      return [{ id: 'aisvc:m365_copilot', label: 'M365 Copilot · IA', weight: n, shadow: false, risk: jb > 0 ? 12 : 3 }];
    }
    if (type === 'ip' || type === 'host') {
      let ip = value;
      if (type === 'host') { const a = (await getAssetList().catch(() => [])).find((x) => x.name?.toLowerCase() === value.toLowerCase()); if (!a?.ip) return []; ip = a.ip; }
      const { data } = await getIndexerClient().post<{ aggregations?: { dom: { buckets: { key: string; doc_count: number }[] } } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { exists: { field: 'data.hostname' } }, { term: { 'data.srcip': ip } }], should: aiHostnameShould(), minimum_should_match: 1 } },
        aggs: { dom: { terms: { field: 'data.hostname', size: 200 } } },
      });
      const acc = new Map<string, { name: string; hits: number }>();
      for (const b of data.aggregations?.dom?.buckets ?? []) { const svc = matchService(b.key); if (!svc) continue; const cur = acc.get(svc.id) ?? { name: svc.name, hits: 0 }; cur.hits += b.doc_count; acc.set(svc.id, cur); }
      return [...acc.entries()].map(([id, v]) => { const shadow = !(sanc.get(id) ?? false); return { id: `aisvc:${id}`, label: `${v.name} · IA`, weight: v.hits, shadow, risk: shadow ? 8 : 2 }; });
    }
    return [];
  } catch { return []; }
}

// ---------- INVENTARIO ----------
export interface AiInventory {
  range: string;
  kpis: { aiServices: number; shadowServices: number; networkDevices: number; copilotInteractions: number; copilotUsers: number; jailbreakAttempts: number };
  network: NetAiRow[];
  copilot: { interactions: number; users: number; jailbreakAttempts: number; sanctioned: boolean; lastSeen: string; byApp: { key: string; count: number }[] };
}
function buildInventory(range: string, network: NetAiRow[], cop: CopilotSummary): AiInventory {
  return {
    range,
    kpis: { aiServices: network.length + (cop.interactions > 0 ? 1 : 0), shadowServices: network.filter((n) => !n.sanctioned).length, networkDevices: network.reduce((mx, n) => Math.max(mx, n.devices), 0), copilotInteractions: cop.interactions, copilotUsers: cop.users, jailbreakAttempts: cop.jailbreakAttempts },
    network,
    copilot: { interactions: cop.interactions, users: cop.users, jailbreakAttempts: cop.jailbreakAttempts, sanctioned: cop.sanctioned, lastSeen: cop.recent[0]?.time ?? '', byApp: cop.byApp },
  };
}
export async function getInventory(rangeIn?: string): Promise<AiInventory> {
  const { range, gte } = gteOf(rangeIn);
  const sanc = await sanctionedMap();
  const [network, cop] = await Promise.all([networkAiUsage(gte, sanc), getCopilot(range)]);
  return buildInventory(range, network, cop);
}

// ---------- RIESGO + GRAFO ----------
export interface RiskEntity { id: string; kind: 'user' | 'device'; label: string; score: number; reasons: string[] }
export interface RiskNode { id: string; type: 'user' | 'device' | 'service' | 'resource'; label: string; risk: number }
export interface RiskEdge { from: string; to: string; weight: number; shadow?: boolean }
export interface AiRisk { range: string; entities: RiskEntity[]; graph: { nodes: RiskNode[]; edges: RiskEdge[] } }

function buildRisk(range: string, net: NetAiRow[], exfil: Omit<ExfilSummary, 'range'>, cop: CopilotSummary): AiRisk {
  // Dispositivos (por srcip) a partir de las filas de exfiltración (tienen srcip+servicio+bytes+sanción).
  const byDev = new Map<string, { host: string | null; services: Set<string>; shadow: number; sent: number; flagged: boolean }>();
  for (const r of exfil.rows) {
    const d = byDev.get(r.srcip) ?? { host: r.host, services: new Set<string>(), shadow: 0, sent: 0, flagged: false };
    d.services.add(r.service); if (!r.sanctioned) d.shadow += 1; d.sent += r.sentMB; d.flagged = d.flagged || r.flagged;
    byDev.set(r.srcip, d);
  }
  const devices: RiskEntity[] = [...byDev.entries()].map(([srcip, d]) => {
    const reasons: string[] = [];
    if (d.shadow > 0) reasons.push(`${d.shadow} servicio(s) de IA no aprobados`);
    if (d.flagged) reasons.push(`subida ≥ ${EXFIL_MB} MB a GenAI`);
    if (d.sent > 0) reasons.push(`${d.sent.toFixed(1)} MB subidos a IA`);
    const score = clamp(d.shadow * 25 + (d.flagged ? 35 : 0) + Math.min(20, d.sent / 5));
    return { id: `dev:${srcip}`, kind: 'device' as const, label: d.host ? `${d.host} (${srcip})` : srcip, score, reasons };
  });

  // Usuarios (Copilot) a partir de la muestra reciente + jailbreak + topUsers.
  const jbByUser = new Map<string, number>(); for (const j of cop.jailbreakList) jbByUser.set(j.user, (jbByUser.get(j.user) ?? 0) + 1);
  const intByUser = new Map<string, number>(); for (const t of cop.topUsers) intByUser.set(t.key, t.count);
  const offByUser = new Map<string, number>(); const docsByUser = new Map<string, Set<string>>();
  for (const d of cop.recent) {
    if (isOffHours(d.time)) offByUser.set(d.user, (offByUser.get(d.user) ?? 0) + 1);
    const set = docsByUser.get(d.user) ?? new Set<string>(); for (const c of d.contexts) set.add(c); docsByUser.set(d.user, set);
  }
  const userIds = new Set<string>([...intByUser.keys(), ...jbByUser.keys()]);
  const users: RiskEntity[] = [...userIds].map((u) => {
    const jb = jbByUser.get(u) ?? 0, off = offByUser.get(u) ?? 0, inter = intByUser.get(u) ?? 0, docs = docsByUser.get(u)?.size ?? 0;
    const reasons: string[] = [];
    if (jb > 0) reasons.push(`${jb} intento(s) de jailbreak en Copilot`);
    if (off > 0) reasons.push(`${off} uso(s) fuera de horario`);
    if (docs > 0) reasons.push(`${docs} documento(s) accedidos por Copilot`);
    if (inter > 0) reasons.push(`${inter} interacciones Copilot`);
    const score = clamp(jb * 40 + off * 4 + Math.min(25, inter / 20) + Math.min(15, docs * 2));
    return { id: `user:${u}`, kind: 'user' as const, label: u, score, reasons };
  });

  const entities = [...devices, ...users].sort((a, b) => b.score - a.score).slice(0, 25);

  // Grafo (bipartito compacto): top entidades ↔ servicios/recursos.
  const nodes = new Map<string, RiskNode>(); const edges: RiskEdge[] = [];
  const addNode = (n: RiskNode) => { if (!nodes.has(n.id)) nodes.set(n.id, n); };
  for (const e of entities.slice(0, 10)) addNode({ id: e.id, type: e.kind, label: e.label, risk: e.score });
  // usuarios -> M365 Copilot + recursos top
  const topUsersInGraph = entities.filter((e) => e.kind === 'user').slice(0, 6);
  if (topUsersInGraph.length) addNode({ id: 'svc:m365_copilot', type: 'service', label: 'M365 Copilot', risk: 0 });
  for (const u of topUsersInGraph) {
    edges.push({ from: u.id, to: 'svc:m365_copilot', weight: intByUser.get(u.label) ?? 1 });
    const docs = [...(docsByUser.get(u.label) ?? new Set<string>())].slice(0, 2);
    for (const doc of docs) { const rid = `res:${doc}`; addNode({ id: rid, type: 'resource', label: shortResource(doc), risk: 0 }); edges.push({ from: u.id, to: rid, weight: 1 }); }
  }
  // dispositivos -> servicios de IA (red)
  const topDevsInGraph = entities.filter((e) => e.kind === 'device').slice(0, 6);
  for (const dev of topDevsInGraph) {
    const srcip = dev.id.slice(4);
    for (const r of exfil.rows.filter((x) => x.srcip === srcip).slice(0, 3)) {
      const sid = `svc:${r.service}`; addNode({ id: sid, type: 'service', label: r.name, risk: 0 });
      edges.push({ from: dev.id, to: sid, weight: r.hits, shadow: !r.sanctioned });
    }
  }
  return { range, entities, graph: { nodes: [...nodes.values()], edges } };
}
export async function getRisk(rangeIn?: string): Promise<AiRisk> {
  const o = await getOverview(rangeIn); return o.risk;
}

// ---------- POSTURA (OWASP Agentic / AIVSS) ----------
export interface PostureItem { id: string; category: string; owasp: string; status: 'ok' | 'warn' | 'critical'; severity: number; evidence: number; finding: string; recommendation: string }
export interface AiPosture { range: string; score: number; items: PostureItem[] }

function buildPosture(range: string, net: NetAiRow[], exfil: Omit<ExfilSummary, 'range'>, cop: CopilotSummary): AiPosture {
  const shadow = net.filter((n) => !n.sanctioned);
  const sensitiveDocs = new Set<string>(); for (const d of cop.recent) for (const c of d.contexts) sensitiveDocs.add(c);
  const items: PostureItem[] = [
    {
      id: 'prompt-injection', category: 'Inyección de prompt (directa/indirecta)', owasp: 'ASI-01 / LLM01',
      status: cop.jailbreakAttempts + cop.xpiaAttempts > 0 ? 'critical' : 'ok', severity: 8.5, evidence: cop.jailbreakAttempts + cop.xpiaAttempts,
      finding: cop.jailbreakAttempts + cop.xpiaAttempts > 0
        ? `${cop.jailbreakAttempts} jailbreak (directo) y ${cop.xpiaAttempts} XPIA (inyección indirecta vía contenido) marcados por Copilot.`
        : 'Sin intentos de jailbreak ni inyección indirecta (XPIA) detectados en Copilot.',
      recommendation: 'Revisar usuarios/documentos implicados; reforzar políticas del asistente y DLP. XPIA = contenido externo que intenta manipular al agente.',
    },
    {
      id: 'data-exfil', category: 'Exfiltración de datos a GenAI', owasp: 'ASI-05 / LLM06',
      status: exfil.flagged > 0 ? 'critical' : exfil.totalSentMB > 0 ? 'warn' : 'ok', severity: 7.5, evidence: exfil.flagged,
      finding: exfil.flagged > 0 ? `${exfil.flagged} equipo/servicio con subida ≥ ${exfil.thresholdMB} MB a IA (total ${exfil.totalSentMB} MB).` : `Subida total a IA: ${exfil.totalSentMB} MB (sin umbral superado).`,
      recommendation: 'Validar qué se está enviando a GenAI; aplicar DLP/clasificación y bloquear servicios no aprobados en el firewall.',
    },
    {
      id: 'shadow-ai', category: 'IA no autorizada (Shadow-AI)', owasp: 'ASI-06 / Excessive Agency',
      status: shadow.length > 2 ? 'critical' : shadow.length > 0 ? 'warn' : 'ok', severity: 5.5, evidence: shadow.length,
      finding: shadow.length > 0 ? `${shadow.length} servicio(s) de IA sin aprobar en uso: ${shadow.slice(0, 5).map((s) => s.name).join(', ')}.` : 'Todo el uso de IA detectado está aprobado.',
      recommendation: 'Definir política de IA sancionada; aprobar o restringir cada servicio en el módulo Shadow-AI.',
    },
    {
      id: 'sensitive-access', category: 'Exposición de información sensible (Copilot)', owasp: 'ASI-04 / LLM02',
      status: sensitiveDocs.size > 20 ? 'warn' : 'ok', severity: 6.0, evidence: sensitiveDocs.size,
      finding: `Copilot accedió a ${sensitiveDocs.size} documento(s)/recurso(s) distintos en la muestra.`,
      recommendation: 'Revisar permisos de SharePoint/OneDrive (oversharing): Copilot hereda lo que el usuario puede ver.',
    },
    {
      id: 'off-hours', category: 'Uso de IA fuera de horario', owasp: 'ASI-03 / Identity',
      status: cop.offHours > 10 ? 'warn' : 'ok', severity: 4.0, evidence: cop.offHours,
      finding: `${cop.offHours} interacción(es) de Copilot fuera del horario ${WORK_START}:00–${WORK_END}:00.`,
      recommendation: 'Correlacionar con UEBA/ITDR por si indica cuenta comprometida o actividad anómala.',
    },
    {
      id: 'governance', category: 'Gobierno y visibilidad de IA', owasp: 'ASI-10 / Governance',
      status: 'ok', severity: 2.0, evidence: cop.interactions + net.reduce((s, n) => s + n.hits, 0),
      finding: 'HexWatch tiene visibilidad activa de IA (red + Copilot) con detección y alertas.',
      recommendation: 'Mantener el inventario de IA actualizado y revisar la postura periódicamente.',
    },
  ];
  // Puntaje de postura: 100 menos penalización por severidad*presencia.
  let penalty = 0;
  for (const it of items) if (it.id !== 'governance') { if (it.status === 'critical') penalty += it.severity * 1.2; else if (it.status === 'warn') penalty += it.severity * 0.5; }
  return { range, score: clamp(100 - penalty), items };
}
export async function getPosture(rangeIn?: string): Promise<AiPosture> {
  const o = await getOverview(rangeIn); return o.posture;
}

// ---------- OVERVIEW (una sola pasada) ----------
export interface AiOverview { range: string; inventory: AiInventory; copilot: CopilotSummary; exfil: ExfilSummary; risk: AiRisk; posture: AiPosture }

export async function getOverview(rangeIn?: string): Promise<AiOverview> {
  const { range, gte } = gteOf(rangeIn);
  const sanc = await sanctionedMap();
  const [net, exfilRaw, cop] = await Promise.all([networkAiUsage(gte, sanc), exfilCompute(gte, sanc), getCopilot(range)]);
  const exfil: ExfilSummary = { range, ...exfilRaw };
  return {
    range,
    inventory: buildInventory(range, net, cop),
    copilot: cop,
    exfil,
    risk: buildRisk(range, net, exfilRaw, cop),
    posture: buildPosture(range, net, exfilRaw, cop),
  };
}
