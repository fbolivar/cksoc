/**
 * NDR (Network Detection & Response) sobre la telemetría de red del FortiGate
 * (Application Control / Forward Traffic / IPS) que ya llega a Wazuh por syslog.
 * Da visibilidad de: quién habla con quién (top talkers), dominios/SNI más
 * visitados, aplicaciones, cruce de dominios/IPs con IOCs conocidos, y alertas IPS.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { getAssetList } from '../assets/assets.service';
import { collectLogins } from '../ueba/ueba.service';
import { enrichIp } from '../enrichment/enrichment.service';

const RANGE: Record<string, string> = { '1h': 'now-1h', '24h': 'now-24h', '7d': 'now-7d' };
const SESSION_SUBTYPES = ['app-ctrl', 'forward'];

export interface NdrTalker { ip: string; sessions: number; dstIps: number }
export interface NdrDomain { domain: string; count: number }
export interface NdrApp { app: string; count: number }
export interface NdrDst { ip: string; count: number }
export interface NdrIps { ts: string; srcip: string | null; dstip: string | null; msg: string; action: string; severity: string | null; attack: string | null }
export interface NdrTransfer {
  ts: string; srcip: string | null; dstip: string | null; sentbyte: number; rcvdbyte: number;
  dstport: string | null; service: string | null; duration: number; appcat: string | null;
  dstcountry: string | null; sessionid: string | null;
  // --- enriquecido por correlación ---
  srcHost: string | null;    // nombre de PC (agente Wazuh)
  srcOs: string | null;
  srcUser: string | null;    // último usuario logueado en ese host
  dstDomain: string | null;  // dominio destino (SNI del app-ctrl)
  dstVerdict: string | null; // malicioso | sospechoso | limpio | interno
  dstIsp: string | null;
  dstAbuse: number | null;
  dstIoc: boolean;
}
export interface NdrIoc { type: string; value: string; source: string; confidence: number; seen: 'domain' | 'ip' }

export interface NdrOverview {
  range: string;
  sessions: number;
  distinctDomains: number;
  distinctDstIps: number;
  ipsCount: number;
  topTalkers: NdrTalker[];
  topDomains: NdrDomain[];
  topApps: NdrApp[];
  topDstIps: NdrDst[];
  ipsAlerts: NdrIps[];
  iocHits: NdrIoc[];
  largeTransfers: NdrTransfer[];
  largeTransferCount: number;
  generatedAt: string;
}

interface TermBucket { key: string; doc_count: number }
interface TalkerBucket extends TermBucket { dst: { value: number } }

function client() { return getIndexerClient(); }

async function overviewAggs(gte: string) {
  const { data } = await client().post<{
    hits: { total: { value: number } | number };
    aggregations?: {
      domains: { buckets: TermBucket[] };
      talkers: { buckets: TalkerBucket[] };
      apps: { buckets: TermBucket[] };
      dstips: { buckets: TermBucket[] };
      cDomains: { value: number };
      cDst: { value: number };
    };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [
      { range: { '@timestamp': { gte } } },
      { match: { 'rule.groups': 'fortigate' } },
      { terms: { 'data.subtype': SESSION_SUBTYPES } },
    ] } },
    aggs: {
      domains: { terms: { field: 'data.hostname', size: 15 } },
      talkers: { terms: { field: 'data.srcip', size: 10 }, aggs: { dst: { cardinality: { field: 'data.dstip' } } } },
      apps: { terms: { field: 'data.app', size: 12 } },
      dstips: { terms: { field: 'data.dstip', size: 10 } },
      cDomains: { cardinality: { field: 'data.hostname' } },
      cDst: { cardinality: { field: 'data.dstip' } },
    },
  });
  const total = typeof data.hits.total === 'number' ? data.hits.total : data.hits.total.value;
  const a = data.aggregations;
  return {
    sessions: total,
    distinctDomains: a?.cDomains.value ?? 0,
    distinctDstIps: a?.cDst.value ?? 0,
    topDomains: (a?.domains.buckets ?? []).map((b) => ({ domain: b.key, count: b.doc_count })),
    topTalkers: (a?.talkers.buckets ?? []).map((b) => ({ ip: b.key, sessions: b.doc_count, dstIps: b.dst.value })),
    topApps: (a?.apps.buckets ?? []).map((b) => ({ app: b.key, count: b.doc_count })),
    topDstIps: (a?.dstips.buckets ?? []).map((b) => ({ ip: b.key, count: b.doc_count })),
  };
}

interface IpsHit { _source: { '@timestamp': string; data?: { srcip?: string; dstip?: string; msg?: string; action?: string; severity?: string; attack?: string } } }

async function ipsAlerts(gte: string): Promise<{ count: number; list: NdrIps[] }> {
  try {
    const { data } = await client().post<{ hits: { total: { value: number } | number; hits: IpsHit[] } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 25,
        query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'fortigate' } }, { term: { 'data.subtype': 'ips' } }] } },
        sort: [{ '@timestamp': { order: 'desc' } }],
        _source: ['@timestamp', 'data.srcip', 'data.dstip', 'data.msg', 'data.action', 'data.severity', 'data.attack'],
      },
    );
    const total = typeof data.hits.total === 'number' ? data.hits.total : data.hits.total.value;
    const list = data.hits.hits.map((h) => ({
      ts: h._source['@timestamp'], srcip: h._source.data?.srcip ?? null, dstip: h._source.data?.dstip ?? null,
      msg: h._source.data?.msg ?? '', action: h._source.data?.action ?? '', severity: h._source.data?.severity ?? null, attack: h._source.data?.attack ?? null,
    }));
    return { count: total, list };
  } catch { return { count: 0, list: [] }; }
}

interface XferData { srcip?: string; dstip?: string; sentbyte?: string; rcvdbyte?: string; dstport?: string; service?: string; duration?: string; appcat?: string; dstcountry?: string; sessionid?: string }
interface XferHit { _source: { '@timestamp': string; data?: XferData } }

/** Transferencias salientes grandes (regla 100600, posible exfiltración). */
async function largeTransfers(gte: string): Promise<{ count: number; list: NdrTransfer[] }> {
  try {
    const { data } = await client().post<{ hits: { total: { value: number } | number; hits: XferHit[] } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 25,
        query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { term: { 'rule.id': '100600' } }] } },
        sort: [{ 'data.sentbyte': { order: 'desc', unmapped_type: 'long' } }],
        _source: ['@timestamp', 'data.srcip', 'data.dstip', 'data.sentbyte', 'data.rcvdbyte', 'data.dstport', 'data.service', 'data.duration', 'data.appcat', 'data.dstcountry', 'data.sessionid'],
      },
    );
    const total = typeof data.hits.total === 'number' ? data.hits.total : data.hits.total.value;
    const list: NdrTransfer[] = data.hits.hits.map((h) => ({
      ts: h._source['@timestamp'], srcip: h._source.data?.srcip ?? null, dstip: h._source.data?.dstip ?? null,
      sentbyte: Number(h._source.data?.sentbyte ?? 0), rcvdbyte: Number(h._source.data?.rcvdbyte ?? 0),
      dstport: h._source.data?.dstport ?? null, service: h._source.data?.service ?? null,
      duration: Number(h._source.data?.duration ?? 0), appcat: h._source.data?.appcat ?? null,
      dstcountry: h._source.data?.dstcountry ?? null, sessionid: h._source.data?.sessionid ?? null,
      srcHost: null, srcOs: null, srcUser: null, dstDomain: null, dstVerdict: null, dstIsp: null, dstAbuse: null, dstIoc: false,
    }));
    return { count: total, list };
  } catch { return { count: 0, list: [] }; }
}

/** Dominio (SNI) más visto por cada IP destino, a partir del app-ctrl. */
async function dstDomains(ips: string[], gte: string): Promise<Map<string, string>> {
  const m = new Map<string, string>();
  if (!ips.length) return m;
  try {
    const { data } = await client().post<{ aggregations?: { d: { buckets: { key: string; h: { buckets: { key: string }[] } }[] } } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { term: { 'data.subtype': 'app-ctrl' } }, { terms: { 'data.dstip': ips } }] } },
        aggs: { d: { terms: { field: 'data.dstip', size: ips.length }, aggs: { h: { terms: { field: 'data.hostname', size: 1 } } } } },
      },
    );
    for (const b of data.aggregations?.d?.buckets ?? []) { const host = b.h.buckets[0]?.key; if (host) m.set(b.key, host); }
  } catch { /* best-effort */ }
  return m;
}

/**
 * Enriquece cada transferencia grande con contexto de investigación:
 * PC de origen + SO + usuario (correlación con inventario y logons de Wazuh),
 * dominio destino (SNI) y reputación del destino (geo/AbuseIPDB/IOC).
 */
async function enrichTransfers(list: NdrTransfer[], gte: string): Promise<NdrTransfer[]> {
  if (!list.length) return list;
  const [agents, logins] = await Promise.all([getAssetList().catch(() => []), collectLogins(24).catch(() => [])]);
  const agentByIp = new Map(agents.map((a) => [a.ip, a]));
  // host -> último usuario con logon exitoso (collectLogins viene ordenado asc, el último gana)
  const userByHost = new Map<string, string>();
  for (const l of logins) if (l.outcome === 'success' && l.host) userByHost.set(l.host, l.user);

  const dstips = [...new Set(list.map((t) => t.dstip).filter((x): x is string => Boolean(x)))];
  const domainByDst = await dstDomains(dstips, gte);
  // Reputación del destino (cacheada); acota a las primeras IPs únicas para no agotar cuota.
  const repByIp = new Map<string, Awaited<ReturnType<typeof enrichIp>>>();
  for (const ip of dstips.slice(0, 15)) { const e = await enrichIp(ip).catch(() => null); if (e) repByIp.set(ip, e); }

  return list.map((t) => {
    const ag = t.srcip ? agentByIp.get(t.srcip) : undefined;
    const rep = t.dstip ? repByIp.get(t.dstip) : undefined;
    return {
      ...t,
      srcHost: ag?.name ?? null,
      srcOs: ag?.os ?? null,
      srcUser: ag?.name ? (userByHost.get(ag.name) ?? null) : null,
      dstDomain: t.dstip ? (domainByDst.get(t.dstip) ?? null) : null,
      dstVerdict: rep?.verdict ?? null,
      dstIsp: rep?.reputation?.isp ?? null,
      dstAbuse: rep?.reputation?.abuseScore ?? null,
      dstIoc: rep?.ioc?.matched ?? false,
    };
  });
}

/** Cruza los dominios/IPs más vistos con los IOCs habilitados. */
async function iocHits(domains: string[], ips: string[]): Promise<NdrIoc[]> {
  if (!domains.length && !ips.length) return [];
  try {
    const rows = await query<{ ioc_type: string; value: string; source: string; confidence: number }>(
      `SELECT ioc_type, value, source, confidence FROM iocs
        WHERE enabled = TRUE AND (
          (ioc_type = 'domain' AND value = ANY($1::text[])) OR
          (ioc_type = 'ip' AND value = ANY($2::text[])))
        LIMIT 100`,
      [domains.map((d) => d.toLowerCase()), ips],
    );
    return rows.map((r) => ({ type: r.ioc_type, value: r.value, source: r.source, confidence: r.confidence, seen: r.ioc_type === 'domain' ? 'domain' : 'ip' }));
  } catch { return []; }
}

export async function getNdrOverview(rangeIn: string): Promise<NdrOverview> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const gte = RANGE[range];
  const [agg, ips, xfer] = await Promise.all([overviewAggs(gte), ipsAlerts(gte), largeTransfers(gte)]);
  const [hits, enrichedXfer] = await Promise.all([
    iocHits(agg.topDomains.map((d) => d.domain), agg.topDstIps.map((d) => d.ip)),
    enrichTransfers(xfer.list, gte),
  ]);
  return {
    range,
    sessions: agg.sessions,
    distinctDomains: agg.distinctDomains,
    distinctDstIps: agg.distinctDstIps,
    ipsCount: ips.count,
    topTalkers: agg.topTalkers,
    topDomains: agg.topDomains,
    topApps: agg.topApps,
    topDstIps: agg.topDstIps,
    ipsAlerts: ips.list,
    iocHits: hits,
    largeTransfers: enrichedXfer,
    largeTransferCount: xfer.count,
    generatedAt: new Date().toISOString(),
  };
}
