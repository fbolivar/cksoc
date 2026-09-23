/**
 * Servicio de mapa de ataques: agrega alertas con IP publica (srcip/remip)
 * por ubicacion geografica. Cachea el resultado unos segundos.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { checkReputation, isThreatIntelConfigured } from '../threatintel/abuseipdb.service';
import { query } from '../../config/db';

// Grupos de regla que denotan un ATAQUE (no tráfico normal): IPS/IDS del SonicWall,
// intrusiones, ataques web. Se usan para el modo "Solo amenazas".
const ATTACK_GROUPS = ['attack', 'ids', 'intrusion_detection', 'web_attack', 'ips'];
const THREAT_MIN_LEVEL = 8;

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
  ioc: string | null; // fuente del IOC si alguna IP del origen está en la lista de bloqueo
  threat: boolean;    // ¿es amenaza? (IOC, o alertas de ataque/IPS, o nivel alto, o reputación mala)
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
  attackHits: { doc_count: number };
}

const cache = new Map<string, { at: number; data: AttackOrigin[] }>();

export async function getAttackGeo(hours: number, threatsOnly = true): Promise<AttackOrigin[]> {
  const key = `${hours}:${threatsOnly ? 'threats' : 'all'}`;
  const cached = cache.get(key);
  if (cached && Date.now() - cached.at < env.ATTACKS_CACHE_SECONDS * 1000) {
    return cached.data;
  }

  const client = getIndexerClient();
  const ipAggs = {
    lvl: { max: { field: 'rule.level' } },
    last: { max: { field: 'timestamp' } },
    attackHits: { filter: { terms: { 'rule.groups': ATTACK_GROUPS } } },
  };
  const body = {
    size: 0,
    query: { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
    aggs: {
      remip: { terms: { field: 'data.remip', size: 300 }, aggs: ipAggs },
      srcip: { terms: { field: 'data.srcip', size: 300 }, aggs: ipAggs },
    },
  };

  // IOCs de IP (feed local, gratis e ilimitado) para marcar orígenes maliciosos
  // conocidos aunque AbuseIPDB esté sin cuota.
  const iocRows = await query<{ value: string; source: string }>(
    "SELECT value, source FROM iocs WHERE ioc_type = 'ip' AND enabled = TRUE"
  ).catch(() => [] as { value: string; source: string }[]);
  const iocMap = new Map(iocRows.map((r) => [r.value, r.source]));

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
    const iocSrc = iocMap.get(b.key) ?? null;
    // Una IP es "amenaza" si: está en un IOC, o generó alertas de ataque/IPS, o
    // tuvo una alerta de nivel alto. (La reputación mala se añade luego en enrich.)
    const isThreatIp = lvl >= THREAT_MIN_LEVEL || b.attackHits.doc_count > 0 || !!iocSrc;
    const existing = byLoc.get(locKey);
    if (existing) {
      existing.count += b.doc_count;
      existing.severity_max = Math.max(existing.severity_max, lvl);
      if (last > existing.last_seen) existing.last_seen = last;
      if (!existing.ips.includes(b.key)) existing.ips.push(b.key);
      existing.threat = existing.threat || isThreatIp;
      if (!existing.ioc && iocSrc) existing.ioc = iocSrc;
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
        ioc: iocSrc,
        threat: isThreatIp,
      });
    }
  }

  let result = [...byLoc.values()];
  // Ordena amenazas primero para que el enriquecimiento (rep, con cuota limitada de
  // AbuseIPDB) se gaste en las IPs que importan, no en el tráfico benigno.
  result.sort((a, b) => (Number(b.threat) - Number(a.threat)) || (b.severity_max - a.severity_max) || (b.count - a.count));
  await enrich(result);

  // "Solo amenazas": muestra únicamente orígenes con IOC, alertas de ataque/IPS,
  // nivel alto o reputación mala (malicioso/sospechoso). Oculta el tráfico benigno
  // (teletrabajo, navegación normal a nubes). Apagable con ?all=1.
  if (threatsOnly) {
    result = result.filter((o) => o.threat || o.clasificacion === 'malicioso' || o.clasificacion === 'sospechoso');
  }
  // Prioriza AMENAZA real (malicioso/IOC/ataque) por encima del volumen crudo.
  const rank = (o: AttackOrigin) =>
    (o.clasificacion === 'malicioso' ? 1000 : 0) + (o.ioc ? 500 : 0) +
    (o.clasificacion === 'sospechoso' ? 200 : 0) + o.severity_max * 10 + Math.min(50, o.count);
  result.sort((a, b) => rank(b) - rank(a));

  cache.set(key, { at: Date.now(), data: result });
  return result;
}
