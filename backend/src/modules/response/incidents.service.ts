/**
 * Cola de incidentes que ameritan respuesta: agrupa alertas de fuerza bruta
 * (IP publica en remip/srcip) por IP, y enriquece con geolocalizacion,
 * reputacion (AbuseIPDB) y estado de bloqueo actual.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { checkReputation, type IpReputation } from '../threatintel/abuseipdb.service';
import { listBlocked } from './fortigate.service';
import { isFortigateConfigured } from './fortigate.service';
import { isWhitelisted } from './whitelist';

export interface Incident {
  ip: string;
  attempts: number;
  severityMax: number;
  lastSeen: string;
  ruleDescription: string;
  country: string;
  city: string;
  lat: number | null;
  lon: number | null;
  reputation: IpReputation | null;
  blocked: boolean;
  // Clasificación de amenaza: por qué (o por qué no) es candidato real a bloquear.
  ioc: boolean;          // aparece en el feed de IOCs (malicioso conocido)
  attack: boolean;       // grupo attack/ids/ips/web del SonicWall/Wazuh
  threat: boolean;       // hay señal real de amenaza (IOC | attack | nivel alto | mala reputación)
  whitelisted: boolean;  // infraestructura crítica: nunca bloquear
  threatScore: number;
}

// Un candidato es amenaza si su nivel llega a esto (o tiene IOC/attack/mala reputación).
const THREAT_MIN_LEVEL = 8;
// Ruido de conectividad benigna: eventos de usuarios legítimos (VPN, login) que
// NUNCA deben proponerse para bloqueo — bloquearlos corta a los propios empleados.
const BENIGN_CONNECTIVITY_RE = /vpn user (connected|disconnected)|ssl[- ]?vpn (tunnel|login|logout)|tunnel (up|down)|user .*(logged (in|out)|login|logout)|administrator .* logged|dhcp/i;

interface IpBucket {
  key: string;
  doc_count: number;
  lvl: { value: number | null };
  last: { value_as_string?: string };
  rule: { buckets: { key: string }[] };
  grp?: { buckets: { key: string }[] };
}

/** Carga el set de IPs maliciosas conocidas del feed IOC local (gratis; AbuseIPDB se agota). */
async function iocIpSet(): Promise<Set<string>> {
  try {
    const rows = await query<{ value: string }>("SELECT value FROM iocs WHERE ioc_type='ip' AND enabled=true");
    return new Set(rows.map((r) => r.value));
  } catch { return new Set(); }
}

/**
 * Candidatos a bloquear. Por defecto SOLO amenazas reales (IOC + grupo attack/IPS +
 * nivel alto + mala reputación), excluyendo el ruido de conectividad benigna
 * (usuarios de VPN, logins) que jamás debe proponerse para bloqueo. `threatsOnly=false`
 * trae todo el volumen. Ordena por amenaza, no por volumen.
 */
export async function getIncidents(hours: number, top = 15, threatsOnly = true): Promise<Incident[]> {
  const client = getIndexerClient();
  const sub = {
    lvl: { max: { field: 'rule.level' } },
    last: { max: { field: 'timestamp' } },
    rule: { terms: { field: 'rule.description', size: 1 } },
    grp: { terms: { field: 'rule.groups', size: 8 } },
  };
  const body = {
    size: 0,
    query: { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
    aggs: {
      remip: { terms: { field: 'data.remip', size: 200 }, aggs: sub },
      srcip: { terms: { field: 'data.srcip', size: 200 }, aggs: sub },
    },
  };

  let buckets: IpBucket[];
  try {
    const { data } = await client.post<{
      aggregations: { remip: { buckets: IpBucket[] }; srcip: { buckets: IpBucket[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
    buckets = [...data.aggregations.remip.buckets, ...data.aggregations.srcip.buckets];
  } catch {
    throw new HttpError(502, 'No se pudo consultar el Indexer de Wazuh');
  }

  // Fusiona por IP (puede aparecer en ambos campos), quedandose con el mayor count
  const byIp = new Map<string, IpBucket>();
  for (const b of buckets) {
    if (!isPublicIP(b.key)) continue;
    const ex = byIp.get(b.key);
    if (!ex || b.doc_count > ex.doc_count) byIp.set(b.key, b);
  }

  const iocSet = await iocIpSet();

  // Clasifica cada IP y decide si es candidato real a bloquear.
  interface Scored { b: IpBucket; ioc: boolean; attack: boolean; threat: boolean; whitelisted: boolean; benign: boolean; score: number }
  const scored: Scored[] = [];
  for (const b of byIp.values()) {
    const desc = b.rule.buckets[0]?.key ?? '';
    const groups = (b.grp?.buckets ?? []).map((g) => g.key).join(',');
    const lvl = b.lvl.value ?? 0;
    const ioc = iocSet.has(b.key);
    const attack = /(^|,)(attack|ids|ips|web[_-]?attack)(,|$)/i.test(groups);
    const whitelisted = isWhitelisted(b.key);
    const benign = BENIGN_CONNECTIVITY_RE.test(desc) && !attack && lvl < THREAT_MIN_LEVEL && !ioc;
    const threat = !whitelisted && !benign && (ioc || attack || lvl >= THREAT_MIN_LEVEL);
    const score = (ioc ? 500 : 0) + (attack ? 200 : 0) + Math.min(lvl, 15) * 8 + Math.min(b.doc_count, 100) * 0.1;
    scored.push({ b, ioc, attack, threat, whitelisted, benign, score });
  }

  // Nunca proponer whitelist ni ruido de conectividad. En modo amenazas, solo threat.
  let candidates = scored.filter((s) => !s.whitelisted && !s.benign);
  if (threatsOnly) candidates = candidates.filter((s) => s.threat);
  candidates.sort((a, b) => b.score - a.score || b.b.doc_count - a.b.doc_count);
  candidates = candidates.slice(0, top);

  // Estado de bloqueo actual (lee el SonicWall una sola vez)
  let blockedSet = new Set<string>();
  if (isFortigateConfigured()) {
    try {
      const blocked = await listBlocked();
      blockedSet = new Set(blocked.map((x) => x.ip));
    } catch {
      /* si el SonicWall no responde, mostramos los incidentes sin estado */
    }
  }

  const incidents: Incident[] = [];
  for (const s of candidates) {
    const b = s.b;
    const geo = geolocate(b.key);
    // Reputación solo para candidatos reales (pocos); AbuseIPDB tiene cuota diaria.
    const reputation = await checkReputation(b.key);
    if (reputation && (reputation.abuseScore ?? 0) >= 50 && !s.threat) s.threat = true;
    incidents.push({
      ip: b.key,
      attempts: b.doc_count,
      severityMax: b.lvl.value ?? 0,
      lastSeen: b.last.value_as_string ?? '',
      ruleDescription: b.rule.buckets[0]?.key ?? '',
      country: geo?.country ?? 'Desconocido',
      city: geo?.city ?? '',
      lat: geo?.lat ?? null,
      lon: geo?.lon ?? null,
      reputation,
      blocked: blockedSet.has(b.key),
      ioc: s.ioc,
      attack: s.attack,
      threat: s.threat,
      whitelisted: s.whitelisted,
      threatScore: Math.round(s.score),
    });
  }
  return incidents;
}
