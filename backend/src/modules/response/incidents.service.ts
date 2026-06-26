/**
 * Cola de incidentes que ameritan respuesta: agrupa alertas de fuerza bruta
 * (IP publica en remip/srcip) por IP, y enriquece con geolocalizacion,
 * reputacion (AbuseIPDB) y estado de bloqueo actual.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { checkReputation, type IpReputation } from '../threatintel/abuseipdb.service';
import { listBlocked } from './fortigate.service';
import { isFortigateConfigured } from './fortigate.service';

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
}

interface IpBucket {
  key: string;
  doc_count: number;
  lvl: { value: number | null };
  last: { value_as_string?: string };
  rule: { buckets: { key: string }[] };
}

/** Top incidentes (IPs publicas atacantes) enriquecidos. */
export async function getIncidents(hours: number, top = 15): Promise<Incident[]> {
  const client = getIndexerClient();
  const sub = {
    lvl: { max: { field: 'rule.level' } },
    last: { max: { field: 'timestamp' } },
    rule: { terms: { field: 'rule.description', size: 1 } },
  };
  const body = {
    size: 0,
    query: { range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } },
    aggs: {
      remip: { terms: { field: 'data.remip', size: 100 }, aggs: sub },
      srcip: { terms: { field: 'data.srcip', size: 100 }, aggs: sub },
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

  const ordered = [...byIp.values()].sort((a, b) => b.doc_count - a.doc_count).slice(0, top);

  // Estado de bloqueo actual (lee el FortiGate una sola vez)
  let blockedSet = new Set<string>();
  if (isFortigateConfigured()) {
    try {
      const blocked = await listBlocked();
      blockedSet = new Set(blocked.map((x) => x.ip));
    } catch {
      /* si el FortiGate no responde, mostramos los incidentes sin estado */
    }
  }

  const incidents: Incident[] = [];
  for (const b of ordered) {
    const geo = geolocate(b.key);
    const reputation = await checkReputation(b.key);
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
    });
  }
  return incidents;
}
