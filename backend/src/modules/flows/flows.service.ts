/**
 * Flujos de red — analítica tipo NetFlow/QFlow sobre los registros de conexión
 * del SonicWall que ya llegan a Wazuh (5-tupla srcip/dstip/dstport + app). Aporta
 * lo que el NDR no hace:
 *   - overview: top conversaciones, puertos, apps y tendencia de flujos.
 *   - beaconing: conexiones PERIÓDICAS a un destino externo (patrón de C2).
 *   - escaneo/fan-out: un origen que toca muchos destinos/puertos.
 * En vivo, sin persistencia. No es captura de paquetes (eso requiere un sensor
 * Zeek/Suricata en SPAN); es analítica de FLUJOS, que es el valor de NetFlow.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { geolocate, isPublicIP } from '../geo/geoip.service';

const RANGE: Record<string, string> = { '1h': 'now-1h', '24h': 'now-24h', '7d': 'now-7d' };
const HIST: Record<string, string> = { '1h': '2m', '24h': '30m', '7d': '3h' };
const BEACON_MIN = Number(env.FLOWS_BEACON_MIN) || 12;
const BEACON_CV_MAX = Number(env.FLOWS_BEACON_CV) || 0.35;
const SCAN_DST = Number(env.FLOWS_SCAN_DST) || 250;
const SCAN_PORT = Number(env.FLOWS_SCAN_PORT) || 150;

function client() { return getIndexerClient(); }
const SW = { match: { 'rule.groups': 'sonicwall' } };

async function iocIpSet(): Promise<Set<string>> {
  try { const r = await query<{ value: string }>("SELECT value FROM iocs WHERE enabled=TRUE AND ioc_type='ip'"); return new Set(r.map((x) => x.value)); } catch { return new Set(); }
}

interface TB { key: string; doc_count: number }
interface TBcard extends TB { c?: { value: number } }

export async function getOverview(rangeIn = '24h'): Promise<unknown> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const { data } = await client().post<{
    hits: { total: { value: number } | number };
    aggregations?: {
      talkers: { buckets: (TB & { dst: { value: number } })[] };
      dst: { buckets: (TB & { s: { buckets: TB[] } })[] };
      ports: { buckets: TB[] };
      apps: { buckets: TB[] };
      tl: { buckets: { key_as_string: string; doc_count: number }[] };
    };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte: RANGE[range] } } }, SW, { exists: { field: 'data.srcip' } }] } },
    aggs: {
      talkers: { terms: { field: 'data.srcip', size: 15 }, aggs: { dst: { cardinality: { field: 'data.dstip' } } } },
      dst: { terms: { field: 'data.dstip', size: 60 }, aggs: { s: { terms: { field: 'data.srcip', size: 1 } } } },
      ports: { terms: { field: 'data.dstport', size: 15 } },
      apps: { terms: { field: 'data.appName', size: 12 } },
      tl: { date_histogram: { field: '@timestamp', fixed_interval: HIST[range], min_doc_count: 0 } },
    },
  });
  const a = data.aggregations;
  const total = typeof data.hits.total === 'number' ? data.hits.total : data.hits.total.value;
  const iocs = await iocIpSet();
  const topDst = (a?.dst.buckets ?? []).filter((b) => isPublicIP(b.key)).slice(0, 15).map((b) => {
    const g = geolocate(b.key);
    return { ip: b.key, flows: b.doc_count, talker: b.s.buckets[0]?.key ?? '', pais: g?.country ?? null, ioc: iocs.has(b.key) };
  });
  return {
    range, flows: total,
    timeline: (a?.tl.buckets ?? []).map((b) => ({ ts: b.key_as_string, flows: b.doc_count })),
    topTalkers: (a?.talkers.buckets ?? []).map((b) => ({ ip: b.key, flows: b.doc_count, destinos: b.dst.value })),
    topDst,
    topPorts: (a?.ports.buckets ?? []).map((b) => ({ port: b.key, flows: b.doc_count })),
    topApps: (a?.apps.buckets ?? []).map((b) => ({ app: b.key, flows: b.doc_count })),
  };
}

export interface Beacon { src: string; dst: string; flows: number; intervaloSeg: number; regularidad: number; pais: string | null; ioc: boolean }
export async function getBeaconing(rangeIn = '24h'): Promise<Beacon[]> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const { data } = await client().post<{ aggregations?: { dst: { buckets: (TB & { s: { buckets: TB[] }; ts: { hits: { hits: { _source: { '@timestamp': string } }[] } } })[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte: RANGE[range] } } }, SW, { exists: { field: 'data.dstip' } }, { exists: { field: 'data.srcip' } }] } },
      aggs: { dst: { terms: { field: 'data.dstip', size: 300, min_doc_count: BEACON_MIN }, aggs: {
        s: { terms: { field: 'data.srcip', size: 1 } },
        ts: { top_hits: { size: 80, _source: ['@timestamp'], sort: [{ '@timestamp': { order: 'asc' } }] } },
      } } },
    },
  );
  const iocs = await iocIpSet();
  const out: Beacon[] = [];
  for (const b of data.aggregations?.dst.buckets ?? []) {
    if (!isPublicIP(b.key)) continue;
    const ts = b.ts.hits.hits.map((h) => new Date(h._source['@timestamp']).getTime()).sort((x, y) => x - y);
    if (ts.length < BEACON_MIN) continue;
    const deltas: number[] = [];
    for (let i = 1; i < ts.length; i++) deltas.push((ts[i] - ts[i - 1]) / 1000);
    const mean = deltas.reduce((s, d) => s + d, 0) / deltas.length;
    if (mean < 20 || mean > 21600) continue; // 20s .. 6h
    const std = Math.sqrt(deltas.reduce((s, d) => s + (d - mean) ** 2, 0) / deltas.length);
    const cv = mean ? std / mean : 1;
    if (cv > BEACON_CV_MAX) continue;
    const g = geolocate(b.key);
    out.push({ src: b.s.buckets[0]?.key ?? '', dst: b.key, flows: b.doc_count, intervaloSeg: Math.round(mean), regularidad: Math.round((1 - cv) * 100), pais: g?.country ?? null, ioc: iocs.has(b.key) });
  }
  return out.sort((x, y) => y.regularidad - x.regularidad || y.flows - x.flows).slice(0, 40);
}

// Fuentes benignas cuyo alto nº de puertos es tráfico de RESPUESTA (DNS/CDN), no escaneo.
const BENIGN_SRC = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', ...(env.ATTACKS_EXCLUDE_IPS || '').split(',').map((s) => s.trim()).filter(Boolean)]);
export interface ScanSrc { src: string; destinos: number; puertos: number; flows: number; nivel: 'alto' | 'medio'; tipo: string; pais: string | null }
export async function getScans(rangeIn = '24h'): Promise<ScanSrc[]> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const { data } = await client().post<{ aggregations?: { src: { buckets: (TB & { d: { value: number }; p: { value: number } })[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: { bool: { filter: [{ range: { '@timestamp': { gte: RANGE[range] } } }, SW, { exists: { field: 'data.srcip' } }] } },
      aggs: { src: { terms: { field: 'data.srcip', size: 200 }, aggs: { d: { cardinality: { field: 'data.dstip' } }, p: { cardinality: { field: 'data.dstport' } } } } },
    },
  );
  const out: ScanSrc[] = [];
  for (const b of data.aggregations?.src.buckets ?? []) {
    const src = b.key; if (BENIGN_SRC.has(src)) continue;
    const destinos = b.d.value, puertos = b.p.value;
    const pub = isPublicIP(src);
    let tipo: string | null = null;
    // Escaneo ENTRANTE: IP pública que toca POCOS destinos (nuestras IPs) en MUCHOS puertos.
    if (pub && destinos <= 5 && puertos >= SCAN_PORT) tipo = 'escaneo entrante';
    // Barrido SALIENTE: host interno que toca MUCHOS destinos externos.
    else if (!pub && destinos >= SCAN_DST) tipo = 'barrido saliente';
    else continue; // el resto (pública con muchos destinos+puertos) es ruido de respuesta
    const nivel: 'alto' | 'medio' = (puertos >= SCAN_PORT * 2 || destinos >= SCAN_DST * 2) ? 'alto' : 'medio';
    const g = pub ? geolocate(src) : null;
    out.push({ src, destinos, puertos, flows: b.doc_count, nivel, tipo, pais: g?.country ?? null });
  }
  return out.sort((x, y) => (y.puertos + y.destinos) - (x.puertos + x.destinos)).slice(0, 30);
}
