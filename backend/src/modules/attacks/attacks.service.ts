/**
 * Servicio de mapa de ataques: agrega alertas con IP publica (srcip/remip)
 * por ubicacion geografica. Cachea el resultado unos segundos.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { checkReputation, isThreatIntelConfigured } from '../threatintel/abuseipdb.service';

export type Clasificacion = 'malicioso' | 'sospechoso' | 'usuario' | 'desconocido';

export interface AttackOrigin {
  country: string;
  city: string;
  isoCode: string;
  lat: number;
  lon: number;
  count: number;
  severity_max: number;
  last_seen: string;
  ips: string[];
  // Enriquecimiento con reputacion/ISP (AbuseIPDB)
  isp: string | null;
  usageType: string | null;
  abuseScore: number;
  clasificacion: Clasificacion;
  esExterno: boolean; // true = ataque externo real (reputacion mala o infraestructura)
}

// usageType que delata infraestructura (hosting/datacenter/VPS): origen tipico de
// atacantes, nunca de un empleado normal navegando.
const HOSTING_RE = /hosting|data\s*center|datacenter|colo|vps|server|cloud|transit/i;

function classify(
  rep: { configured: boolean; abuseScore: number; usageType: string | null },
  threshold: number
): { clasificacion: Clasificacion; esExterno: boolean } {
  if (!rep.configured) return { clasificacion: 'desconocido', esExterno: false };
  if (rep.abuseScore >= threshold) return { clasificacion: 'malicioso', esExterno: true };
  if (rep.usageType && HOSTING_RE.test(rep.usageType)) return { clasificacion: 'sospechoso', esExterno: true };
  return { clasificacion: 'usuario', esExterno: false };
}

/** Enriquece los primeros N origenes con reputacion/ISP y los clasifica. */
async function enrich(origins: AttackOrigin[]): Promise<void> {
  if (!isThreatIntelConfigured()) return;
  const top = origins.slice(0, env.ATTACKS_ENRICH_MAX);
  const chunk = 8; // limita la concurrencia hacia AbuseIPDB
  for (let i = 0; i < top.length; i += chunk) {
    await Promise.all(
      top.slice(i, i + chunk).map(async (o) => {
        const rep = await checkReputation(o.ips[0]);
        o.isp = rep.isp;
        o.usageType = rep.usageType;
        o.abuseScore = rep.abuseScore;
        const c = classify(rep, env.ATTACKS_ABUSE_THRESHOLD);
        o.clasificacion = c.clasificacion;
        o.esExterno = c.esExterno;
      })
    );
  }
}

interface IpBucket {
  key: string;
  doc_count: number;
  lvl: { value: number | null };
  last: { value_as_string?: string };
}

const cache = new Map<number, { at: number; data: AttackOrigin[] }>();

export async function getAttackGeo(hours: number): Promise<AttackOrigin[]> {
  const cached = cache.get(hours);
  if (cached && Date.now() - cached.at < env.ATTACKS_CACHE_SECONDS * 1000) {
    return cached.data;
  }

  const client = getIndexerClient();
  const body = {
    size: 0,
    query: { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
    aggs: {
      remip: {
        terms: { field: 'data.remip', size: 300 },
        aggs: { lvl: { max: { field: 'rule.level' } }, last: { max: { field: 'timestamp' } } },
      },
      srcip: {
        terms: { field: 'data.srcip', size: 300 },
        aggs: { lvl: { max: { field: 'rule.level' } }, last: { max: { field: 'timestamp' } } },
      },
    },
  };

  let buckets: IpBucket[];
  try {
    const { data } = await client.post<{
      aggregations: { remip: { buckets: IpBucket[] }; srcip: { buckets: IpBucket[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
    buckets = [...data.aggregations.srcip.buckets, ...data.aggregations.remip.buckets];
  } catch (err) {
    const e = err as { code?: string };
    if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') {
      throw new HttpError(502, 'No se pudo conectar al Wazuh Indexer');
    }
    throw new HttpError(502, 'Error consultando el Indexer');
  }

  // Agrega por ubicacion (isoCode + ciudad + coordenadas redondeadas)
  const byLoc = new Map<string, AttackOrigin>();
  for (const b of buckets) {
    if (!isPublicIP(b.key)) continue;
    const geo = geolocate(b.key);
    if (!geo) continue;
    const locKey = `${geo.isoCode}|${geo.city}|${geo.lat.toFixed(2)},${geo.lon.toFixed(2)}`;
    const lvl = b.lvl.value ?? 0;
    const last = b.last.value_as_string ?? '';
    const existing = byLoc.get(locKey);
    if (existing) {
      existing.count += b.doc_count;
      existing.severity_max = Math.max(existing.severity_max, lvl);
      if (last > existing.last_seen) existing.last_seen = last;
      if (!existing.ips.includes(b.key)) existing.ips.push(b.key);
    } else {
      byLoc.set(locKey, {
        country: geo.country,
        city: geo.city,
        isoCode: geo.isoCode,
        lat: geo.lat,
        lon: geo.lon,
        count: b.doc_count,
        severity_max: lvl,
        last_seen: last,
        ips: [b.key],
        isp: null,
        usageType: null,
        abuseScore: 0,
        clasificacion: 'desconocido',
        esExterno: false,
      });
    }
  }

  const result = [...byLoc.values()].sort((a, b) => b.count - a.count);
  await enrich(result);
  cache.set(hours, { at: Date.now(), data: result });
  return result;
}
