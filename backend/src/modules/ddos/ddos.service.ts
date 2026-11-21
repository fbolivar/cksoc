/**
 * Detección DDoS / Bots — sobre los flujos del SonicWall que ya llegan a Wazuh
 * (data.srcip/dstip/dstport/protocol/appName). Aporta lo que ni flows ni NDR hacen:
 *   - FAN-IN volumétrico: MUCHOS orígenes externos -> UN destino (patrón DDoS).
 *   - Amplificación/reflexión: UDP desde puertos de servicio (53/123/1900/11211).
 *   - Bots: UN origen externo -> UN destino con volumen alto y pocos puertos
 *     (scraping, HTTP flood, credential stuffing).
 * En vivo, sin persistencia. Volumen = nº de flujos (el SonicWall no loguea bytes).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { geolocate, isPublicIP } from '../geo/geoip.service';

const RANGE: Record<string, string> = { '1h': 'now-1h', '24h': 'now-24h', '7d': 'now-7d' };
const SW = { match: { 'rule.groups': 'sonicwall' } };

const FANIN_MIN_SOURCES = Number(process.env.DDOS_FANIN_SOURCES) || 25;
const FANIN_MIN_FLOWS = Number(process.env.DDOS_FANIN_FLOWS) || 150;
const BOT_MIN_FLOWS = Number(process.env.DDOS_BOT_FLOWS) || 300;
const BOT_MAX_PORTS = Number(process.env.DDOS_BOT_PORTS) || 3;
// Resolutores/CDN benignos cuyo tráfico de respuesta no es ataque.
const BENIGN = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220']);
// Puertos de servicio usados como vectores de amplificación/reflexión.
const AMP_PORTS = new Set([53, 123, 1900, 11211, 389, 161, 19]);

function client() { return getIndexerClient(); }

async function iocIpSet(): Promise<Set<string>> {
  try { const r = await query<{ value: string }>("SELECT value FROM iocs WHERE enabled=TRUE AND ioc_type='ip'"); return new Set(r.map((x) => x.value)); }
  catch { return new Set(); }
}

export interface TopSource { ip: string; flows: number; pais: string | null; publica: boolean; ioc: boolean }
export interface DdosSignal {
  tipo: 'fan-in' | 'amplificacion' | 'flood';
  target: string;
  sources: number;
  flows: number;
  topPort: number;
  protocol: string;
  appName: string;
  topSources: TopSource[];
  publicosTop: number;
  iocsTop: number;
  severidad: 'alta' | 'media' | 'baja';
  descripcion: string;
}
export interface BotSignal {
  tipo: 'scraping' | 'credential-stuffing' | 'http-flood' | 'bot';
  source: string;
  target: string;
  flows: number;
  puertos: number;
  topPort: number;
  protocol: string;
  appName: string;
  pais: string | null;
  ioc: boolean;
  severidad: 'alta' | 'media' | 'baja';
  descripcion: string;
}
export interface DdosReport {
  range: string;
  generadoEn: string;
  resumen: { flujos: number; volumetricos: number; bots: number };
  volumetric: DdosSignal[];
  bots: BotSignal[];
}

type Bkt = { key: string | number; doc_count: number; [k: string]: unknown };
function top1(o: unknown): Bkt | undefined { return (o as { buckets?: Bkt[] } | undefined)?.buckets?.[0]; }
function bkts(o: unknown): Bkt[] { return (o as { buckets?: Bkt[] } | undefined)?.buckets ?? []; }
function card(o: unknown): number { return (o as { value?: number } | undefined)?.value ?? 0; }

export async function getDdosBots(rangeIn = '24h'): Promise<DdosReport> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const gte = RANGE[range];
  const c = client();
  const iocs = await iocIpSet();

  const base = { bool: { filter: [{ range: { '@timestamp': { gte } } }, SW, { exists: { field: 'data.srcip' } }, { exists: { field: 'data.dstip' } }] } };

  // --- FAN-IN: por destino, nº de orígenes distintos + volumen ---
  const faninResp = await c.post<{ aggregations?: { dst: { buckets: Bkt[] } } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0, query: base,
    aggs: {
      dst: {
        terms: { field: 'data.dstip', size: 120 },
        aggs: {
          s: { cardinality: { field: 'data.srcip' } },
          port: { terms: { field: 'data.dstport', size: 1 } },
          proto: { terms: { field: 'data.protocol', size: 1 } },
          app: { terms: { field: 'data.appName', size: 1 } },
          topsrc: { terms: { field: 'data.srcip', size: 8 } },
        },
      },
    },
  }).then((r) => r.data).catch(() => ({ aggregations: undefined }));

  const volumetric: DdosSignal[] = [];
  for (const b of faninResp.aggregations?.dst?.buckets ?? []) {
    const target = String(b.key);
    const sources = card(b.s);
    const flows = b.doc_count;
    if (sources < FANIN_MIN_SOURCES || flows < FANIN_MIN_FLOWS) continue;
    const topSources: TopSource[] = bkts(b.topsrc).map((x) => {
      const ip = String(x.key);
      const g = isPublicIP(ip) ? geolocate(ip) : null;
      return { ip, flows: x.doc_count, pais: g?.country ?? null, publica: isPublicIP(ip), ioc: iocs.has(ip) };
    });
    const publicosTop = topSources.filter((s) => s.publica).length;
    const iocsTop = topSources.filter((s) => s.ioc).length;
    // Si casi todos los orígenes top son internos, es tráfico legítimo cliente->servidor, no DDoS entrante.
    if (publicosTop < 2) continue;
    const topPort = Number(top1(b.port)?.key ?? 0);
    const protocol = String(top1(b.proto)?.key ?? '');
    const appName = String(top1(b.app)?.key ?? '');
    const esAmp = /udp/i.test(protocol) && AMP_PORTS.has(topPort);
    const tipo: DdosSignal['tipo'] = esAmp ? 'amplificacion' : sources >= FANIN_MIN_SOURCES * 2 ? 'fan-in' : 'flood';
    const severidad: DdosSignal['severidad'] = iocsTop > 0 || sources >= 200 ? 'alta' : sources >= FANIN_MIN_SOURCES * 2 ? 'alta' : 'media';
    volumetric.push({
      tipo, target, sources, flows, topPort, protocol, appName, topSources, publicosTop, iocsTop, severidad,
      descripcion: esAmp
        ? `Posible reflexión/amplificación ${protocol.toUpperCase()} (puerto ${topPort}): ${sources} orígenes contra ${target}.`
        : `Posible DDoS por saturación: ${sources} orígenes distintos (${publicosTop} públicos${iocsTop ? `, ${iocsTop} con IOC` : ''}) generaron ${flows.toLocaleString('es-CO')} flujos contra ${target}${topPort ? ` (puerto ${topPort})` : ''}.`,
    });
  }
  volumetric.sort((a, b) => b.sources - a.sources);

  // --- BOTS: por origen, volumen alto a pocos puertos (externo) ---
  const botResp = await c.post<{ aggregations?: { src: { buckets: Bkt[] } } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0, query: base,
    aggs: {
      src: {
        terms: { field: 'data.srcip', size: 120 },
        aggs: {
          p: { cardinality: { field: 'data.dstport' } },
          dst: { terms: { field: 'data.dstip', size: 1 } },
          port: { terms: { field: 'data.dstport', size: 1 } },
          proto: { terms: { field: 'data.protocol', size: 1 } },
          app: { terms: { field: 'data.appName', size: 1 } },
        },
      },
    },
  }).then((r) => r.data).catch(() => ({ aggregations: undefined }));

  const bots: BotSignal[] = [];
  for (const b of botResp.aggregations?.src?.buckets ?? []) {
    const source = String(b.key);
    const flows = b.doc_count;
    const puertos = card(b.p);
    if (flows < BOT_MIN_FLOWS || puertos > BOT_MAX_PORTS) continue;
    if (!isPublicIP(source) || BENIGN.has(source)) continue; // bot externo contra nosotros
    const target = String(top1(b.dst)?.key ?? '');
    const topPort = Number(top1(b.port)?.key ?? 0);
    const protocol = String(top1(b.proto)?.key ?? '');
    const appName = String(top1(b.app)?.key ?? '');
    const g = geolocate(source);
    const web = topPort === 443 || topPort === 80 || /http/i.test(protocol);
    const tipo: BotSignal['tipo'] = web ? (flows >= BOT_MIN_FLOWS * 4 ? 'http-flood' : 'scraping') : 'bot';
    const severidad: BotSignal['severidad'] = iocs.has(source) || flows >= BOT_MIN_FLOWS * 4 ? 'alta' : 'media';
    bots.push({
      tipo, source, target, flows, puertos, topPort, protocol, appName,
      pais: g?.country ?? null, ioc: iocs.has(source), severidad,
      descripcion: `${source}${g?.country ? ` (${g.country})` : ''} generó ${flows.toLocaleString('es-CO')} flujos a ${target}${topPort ? `:${topPort}` : ''} en solo ${puertos} puerto(s) — patrón de ${web ? 'scraping/HTTP flood' : 'bot/automatización'}.`,
    });
  }
  bots.sort((a, b) => b.flows - a.flows);

  const totalFlows = (faninResp.aggregations?.dst?.buckets ?? []).reduce((n, b) => n + b.doc_count, 0);
  return {
    range, generadoEn: new Date().toISOString(),
    resumen: { flujos: totalFlows, volumetricos: volumetric.length, bots: bots.length },
    volumetric: volumetric.slice(0, 30),
    bots: bots.slice(0, 30),
  };
}
