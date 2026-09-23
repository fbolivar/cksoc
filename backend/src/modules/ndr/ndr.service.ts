/**
 * NDR (Network Detection & Response) sobre la telemetría de red del SonicWall
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
import { fgGet } from '../response/fortigate.service';

const RANGE: Record<string, string> = { '1h': 'now-1h', '24h': 'now-24h', '7d': 'now-7d' };

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
  trusted: boolean;          // destino de nube conocida y reputación limpia
  riskRank: number;          // 0 (confiable) .. 5 (IOC) para ordenar
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
      { match: { 'rule.groups': 'sonicwall' } },
    ] } },
    aggs: {
      domains: { terms: { field: 'data.hostname', size: 15 } },
      talkers: { terms: { field: 'data.srcip', size: 10 }, aggs: { dst: { cardinality: { field: 'data.dstip' } } } },
      apps: { terms: { field: 'data.appName', size: 12 } },
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
        query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { terms: { 'rule.id': ['100206', '100210'] } }] } },
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
        query: {
          bool: {
            filter: [{ range: { '@timestamp': { gte } } }, { term: { 'rule.id': '100600' } }],
            // La exfiltración es hacia Internet: un destino PRIVADO (RFC1918) no es
            // exfiltración por definición (telemetría de agentes al SOC, RDP interno,
            // sincronización LAN…). Se excluye del panel para que solo muestre egress
            // externo real. (172.16/12 no se usa en esta red; se cubren 10/8 y 192.168/16.)
            must_not: [
              { prefix: { 'data.dstip': '192.168.' } },
              { prefix: { 'data.dstip': '10.' } },
              // Infraestructura propia conocida-benigna (además suprimida en el SIEM
              // por las reglas 100602/100603/100604): el DVR de cámaras Dahua
              // (192.168.0.31, sync de video) y los relays de HexDesk / soporte remoto
              // (OVH y Vultr). Se ocultan del panel para que solo muestre egress
              // externo DESCONOCIDO — que es lo único investigable como exfiltración.
              { match_phrase: { 'data.srcip': '192.168.0.31' } },
              { terms: { 'data.dstip': ['40.160.225.24', '209.250.254.15'] } },
            ],
          },
        },
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
      trusted: false, riskRank: 2,
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
        query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { terms: { 'data.dstip': ips } }] } },
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

  const enriched = list.map((t) => {
    const ag = t.srcip ? agentByIp.get(t.srcip) : undefined;
    const rep = t.dstip ? repByIp.get(t.dstip) : undefined;
    const verdict = rep?.verdict ?? null;
    const ioc = rep?.ioc?.matched ?? false;
    const isp = rep?.reputation?.isp ?? null;
    const domain = t.dstip ? (domainByDst.get(t.dstip) ?? null) : null;
    // Nube conocida + reputación limpia = confiable (ruido esperado).
    const trusted = !ioc && verdict === 'limpio' && TRUSTED_RE.test(`${t.service ?? ''} ${isp ?? ''} ${domain ?? ''}`);
    // Riesgo para ordenar: IOC > malicioso > sospechoso > desconocido > limpio-no-confiable > confiable.
    const riskRank = ioc ? 5 : verdict === 'malicioso' ? 4 : verdict === 'sospechoso' ? 3
      : (verdict === 'limpio' ? (trusted ? 0 : 1) : 2);
    return { ...t, srcHost: ag?.name ?? null, srcOs: ag?.os ?? null, srcUser: ag?.name ? (userByHost.get(ag.name) ?? null) : null, dstDomain: domain, dstVerdict: verdict, dstIsp: isp, dstAbuse: rep?.reputation?.abuseScore ?? null, dstIoc: ioc, trusted, riskRank };
  });
  // #1: los de mayor riesgo primero; a igual riesgo, mayor subida.
  enriched.sort((a, b) => b.riskRank - a.riskRank || b.sentbyte - a.sentbyte);
  return enriched;
}

// Destinos de nube corporativa esperada (no exfiltración): se separan del panel.
const TRUSTED_RE = /microsoft|office365|onedrive|sharepoint|windows|google|gmail|youtube|amazon|\baws\b|apple|icloud|dropbox|cloudflare|akamai|fastly|meta|whatsapp|facebook/i;

/**
 * Cruza TODO el tráfico de red (IPs origen+destino y dominios) contra el feed de
 * IOCs habilitados — no solo los de más volumen. Así un contacto con una IP/dominio
 * malicioso se detecta aunque sea UNA sola conexión (antes se perdía porque solo se
 * revisaban los ~10 destinos más frecuentes). Se carga el feed en memoria y se
 * intersecta con las IPs/dominios vistos en la ventana.
 */
async function iocHits(gte: string): Promise<NdrIoc[]> {
  let iocRows: { ioc_type: string; value: string; source: string; confidence: number }[] = [];
  try {
    iocRows = await query<{ ioc_type: string; value: string; source: string; confidence: number }>(
      "SELECT ioc_type, value, source, confidence FROM iocs WHERE enabled = TRUE AND ioc_type IN ('ip','domain')"
    );
  } catch { return []; }
  if (!iocRows.length) return [];
  // Plataformas de hosting COMPARTIDO legítimas que aparecen en feeds de URL
  // (URLhaus/ThreatFox) porque alojan malware en URLs puntuales — pero el dominio en
  // sí es legítimo y NO accionable (no vas a "bloquear github.com"). Se excluyen de
  // los IOC de DOMINIO. Los IOC de IP se conservan siempre (una IP en blocklist.de es
  // mala a nivel host).
  const LEGIT_HOSTING_RE = /(^|\.)(github|githubusercontent|google|googleapis|googleusercontent|gstatic|youtube|discord|discordapp|cloudinary|imgur|ibb|firebasestorage|licdn|linkedin|microsoft|office365?|windows|live|amazonaws|cloudfront|dropbox|apple|icloud|cloudflare|akamai|fastly|bitbucket|gitlab|wetransfer|whatsapp|facebook|fbcdn)\.[a-z]{2,}(\.[a-z]{2,})?$/i;
  const ipMap = new Map<string, { source: string; confidence: number }>();
  const domMap = new Map<string, { source: string; confidence: number }>();
  for (const r of iocRows) {
    (r.ioc_type === 'ip' ? ipMap : domMap).set(String(r.value).toLowerCase(), { source: r.source, confidence: r.confidence });
  }
  try {
    const { data } = await client().post<{ aggregations?: {
      dst: { buckets: TermBucket[] }; src: { buckets: TermBucket[] }; dom: { buckets: TermBucket[] };
    } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }] } },
      aggs: {
        dst: { terms: { field: 'data.dstip', size: 4000 } },
        src: { terms: { field: 'data.srcip', size: 4000 } },
        dom: { terms: { field: 'data.hostname', size: 4000 } },
      },
    });
    const a = data.aggregations;
    const hits: NdrIoc[] = [];
    const seenVal = new Set<string>();
    const push = (value: string, isIp: boolean): void => {
      const key = String(value).toLowerCase();
      // Los IOC de dominio sobre plataformas legítimas de hosting compartido no son
      // accionables (no bloqueas github/google); se descartan. Los de IP se conservan.
      if (!isIp && LEGIT_HOSTING_RE.test(key)) return;
      const m = isIp ? ipMap.get(key) : domMap.get(key);
      if (!m || seenVal.has(key)) return;
      seenVal.add(key);
      hits.push({ type: isIp ? 'ip' : 'domain', value, source: m.source, confidence: m.confidence, seen: isIp ? 'ip' : 'domain' });
    };
    for (const b of a?.dst.buckets ?? []) push(b.key, true);
    for (const b of a?.src.buckets ?? []) push(b.key, true);
    for (const b of a?.dom.buckets ?? []) push(b.key, false);
    return hits.slice(0, 100);
  } catch { return []; }
}

export async function getNdrOverview(rangeIn: string): Promise<NdrOverview> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const gte = RANGE[range];
  const [agg, ips, xfer] = await Promise.all([overviewAggs(gte), ipsAlerts(gte), largeTransfers(gte)]);
  const [hits, enrichedXfer] = await Promise.all([
    iocHits(gte),
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
    // El KPI cuenta solo las SOSPECHOSAS (no confiables): egress externo a destinos
    // que no son nube corporativa conocida ni con reputación limpia. Así el número
    // refleja lo investigable y no se dispara por tráfico benigno a AWS/Google/O365.
    // (El detalle sigue mostrando las confiables, colapsadas.)
    largeTransferCount: enrichedXfer.filter((t) => !t.trusted).length,
    generatedAt: new Date().toISOString(),
  };
}

// ==========================================================================
// VPN en tiempo real (sesiones SSL-VPN activas del SonicWall)
// ==========================================================================
export interface VpnSession {
  user: string; group: string; remoteHost: string; aip: string;
  durationSec: number; inBytes: number; outBytes: number; twoFactor: boolean; lastLogin: number;
}
export interface VpnLive {
  configured: boolean; count: number; totalInBytes: number; totalOutBytes: number;
  sessions: VpnSession[];
  byGroup: { group: string; sesiones: number; bytes: number }[];
  generatedAt: string;
}

interface SwVpnRow {
  user_name?: string; vpn_protocol?: string; client_virtual_ip?: string; client_wan_ip?: string;
  login_time?: string; inactivity_time?: string; logged_in?: string; dev_profile?: string; spn?: boolean;
}

function parseDurationSec(s?: string): number {
  const m = String(s ?? '').match(/(\d+)\s*(second|minute|hour|day)/i);
  if (!m) return 0;
  const n = Number(m[1]); const u = m[2].toLowerCase();
  return u.startsWith('sec') ? n : u.startsWith('min') ? n * 60 : u.startsWith('hour') ? n * 3600 : n * 86400;
}

/** Sesiones SSL-VPN activas del SonicWall (reporting API). No expone bytes por sesion. */
export async function getVpnSessions(): Promise<VpnLive> {
  const empty: VpnLive = { configured: false, count: 0, totalInBytes: 0, totalOutBytes: 0, sessions: [], byGroup: [], generatedAt: new Date().toISOString() };
  try {
    const data = await fgGet<SwVpnRow[]>('/reporting/ssl-vpn/sessions');
    const rows = Array.isArray(data) ? data : [];
    const sessions: VpnSession[] = rows.map((r) => ({
      user: r.user_name ?? '', group: r.dev_profile ?? r.vpn_protocol ?? '', remoteHost: r.client_wan_ip ?? '',
      aip: r.client_virtual_ip ?? '', durationSec: parseDurationSec(r.login_time),
      inBytes: 0, outBytes: 0, twoFactor: Boolean(r.spn), lastLogin: Date.parse(r.logged_in ?? '') || 0,
    })).sort((a, b) => b.durationSec - a.durationSec);
    const gmap = new Map<string, { group: string; sesiones: number; bytes: number }>();
    for (const s of sessions) {
      const e = gmap.get(s.group) ?? { group: s.group || '(sin perfil)', sesiones: 0, bytes: 0 };
      e.sesiones++; gmap.set(s.group, e);
    }
    return {
      configured: true, count: sessions.length, totalInBytes: 0, totalOutBytes: 0,
      sessions, byGroup: [...gmap.values()].sort((a, b) => b.sesiones - a.sesiones), generatedAt: new Date().toISOString(),
    };
  } catch { return empty; }
}

// ==========================================================================
// Actividad en Internet por equipo, clasificada por categoría (App Control) +
// marca de alto riesgo (proxy/anonimizador, acceso remoto, IA generativa, juegos,
// streaming, redes sociales). Atribución por EQUIPO (el SonicWall no identifica usuario).
// ==========================================================================
// Riesgo por categoria de SonicWall (App Control / CFS). Los nombres de categoria
// son cadenas libres del firewall; se puntuan por palabras clave para tolerar variantes.
function catRisk(cat: string): number {
  const c = (cat || '').toLowerCase();
  if (/proxy|anonym|tor/.test(c)) return 5;
  if (/malware|botnet|phish|command.?and.?control|c2|hack|exploit/.test(c)) return 5;
  if (/peer.?to.?peer|p2p|torrent/.test(c)) return 4;
  if (/remote access|remote.?desktop|vnc|rdp|teamviewer|anydesk/.test(c)) return 3;
  if (/gambl|casino/.test(c)) return 3;
  if (/porn|adult|nudity|sexual/.test(c)) return 3;
  if (/personal storage|file storage|file sharing|file transfer|online storage/.test(c)) return 2;
  if (/game|gaming/.test(c)) return 2;
  if (/social network/.test(c)) return 1;
  if (/stream|multimedia|video|audio|entertainment/.test(c)) return 1;
  if (/instant messag|chat/.test(c)) return 1;
  return 0;
}
const CAT_LABEL: Record<string, string> = {};

export interface DeviceActivity {
  ip: string; host: string | null; total: number;
  categorias: { cat: string; label: string; sesiones: number; riesgo: boolean }[];
  riesgoScore: number; nivel: 'alto' | 'medio' | 'bajo'; catsRiesgo: string[];
}
export interface UserActivity { range: string; total: number; dispositivos: DeviceActivity[]; generatedAt: string }

export async function getUserActivity(rangeIn: string): Promise<UserActivity> {
  const gte = RANGE[rangeIn] ?? RANGE['24h'];
  const client = getIndexerClient();
  const { data } = await client.post<{ aggregations?: { dev: { buckets: { key: string; doc_count: number; cat: { buckets: { key: string; doc_count: number }[] } }[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { exists: { field: 'data.appcat' } }, { exists: { field: 'data.srcip' } }] } },
      aggs: { dev: { terms: { field: 'data.srcip', size: 25 }, aggs: { cat: { terms: { field: 'data.appcat', size: 10 } } } } },
    }
  );
  const assets = await getAssetList().catch(() => []);
  const hostByIp = new Map<string, string>();
  for (const a of assets) if (a.ip) hostByIp.set(a.ip, a.name);

  const devs: DeviceActivity[] = (data.aggregations?.dev.buckets ?? []).map((d) => {
    const cats = (d.cat.buckets ?? []).map((c) => ({ cat: c.key, label: CAT_LABEL[c.key] ?? c.key, sesiones: c.doc_count, riesgo: catRisk(c.key) > 0 }));
    const riesgoScore = cats.reduce((n, c) => n + c.sesiones * catRisk(c.cat), 0);
    const riesgoSes = cats.filter((c) => c.riesgo).reduce((n, c) => n + c.sesiones, 0);
    const hasProxy = cats.some((c) => catRisk(c.cat) >= 5);
    const share = d.doc_count ? riesgoSes / d.doc_count : 0;
    const nivel: 'alto' | 'medio' | 'bajo' = hasProxy || share >= 0.4 ? 'alto' : share >= 0.15 ? 'medio' : 'bajo';
    return {
      ip: d.key, host: hostByIp.get(d.key) ?? null, total: d.doc_count,
      categorias: cats.sort((a, b) => b.sesiones - a.sesiones).slice(0, 6),
      riesgoScore, nivel, catsRiesgo: cats.filter((c) => c.riesgo).map((c) => c.label),
    };
  }).sort((a, b) => b.riesgoScore - a.riesgoScore || b.total - a.total);

  return { range: rangeIn, total: devs.length, dispositivos: devs, generatedAt: new Date().toISOString() };
}
