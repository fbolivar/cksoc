/**
 * Enriquecimiento de IPs: dado un indicador, reúne en un solo objeto la
 * geolocalización, reputación (AbuseIPDB), coincidencia con IOC conocido y la
 * actividad reciente en alertas — para que el analista no tenga que pivotear a
 * mano. Reutiliza geoip, abuseipdb (threatintel) e IOCs de la BD.
 */
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { checkReputation } from '../threatintel/abuseipdb.service';
import { query } from '../../config/db';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';

export type Verdict = 'malicioso' | 'sospechoso' | 'limpio' | 'interno' | 'desconocido';

export interface IpEnrichment {
  ip: string;
  isPublic: boolean;
  verdict: Verdict;
  geo: { country: string; city: string; isoCode: string } | null;
  reputation: { abuseScore: number; totalReports: number; isp: string | null; usageType: string | null; domain: string | null; lastReportedAt: string | null; configured: boolean } | null;
  ioc: { matched: boolean; source?: string; description?: string } | null;
  alerts24h: number;
  generatedAt: string;
}

async function iocMatch(ip: string): Promise<{ matched: boolean; source?: string; description?: string }> {
  const rows = await query<{ source: string; description: string | null }>(
    "SELECT source, description FROM iocs WHERE ioc_type='ip' AND value=$1 AND enabled=TRUE LIMIT 1", [ip],
  ).catch(() => [] as { source: string; description: string | null }[]);
  if (!rows.length) return { matched: false };
  return { matched: true, source: rows[0].source, description: rows[0].description ?? undefined };
}

async function alertsFor(ip: string): Promise<number> {
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{ count: number }>(`/${env.WAZUH_ALERTS_INDEX}/_count`, {
      query: { bool: { filter: [
        { range: { '@timestamp': { gte: 'now-24h' } } },
        { term: { 'data.srcip': ip } },
      ] } },
    });
    return data.count ?? 0;
  } catch { return 0; }
}

function decideVerdict(pub: boolean, ioc: boolean, abuse: number, repConfigured: boolean): Verdict {
  if (!pub) return 'interno';
  if (ioc) return 'malicioso';
  if (abuse >= 50) return 'malicioso';
  if (abuse >= 25) return 'sospechoso';
  if (repConfigured) return 'limpio';
  return 'desconocido';
}

/** Enriquecimiento completo de una IP (geo + reputación + IOC + actividad). */
export async function enrichIp(ip: string): Promise<IpEnrichment> {
  const pub = isPublicIP(ip);
  if (!pub) {
    return { ip, isPublic: false, verdict: 'interno', geo: null, reputation: null, ioc: { matched: false }, alerts24h: await alertsFor(ip), generatedAt: new Date().toISOString() };
  }
  const [rep, ioc, alerts24h] = await Promise.all([
    checkReputation(ip).catch(() => null),
    iocMatch(ip),
    alertsFor(ip),
  ]);
  const g = geolocate(ip);
  const geo = g ? { country: g.country, city: g.city, isoCode: g.isoCode } : null;
  const reputation = rep ? { abuseScore: rep.abuseScore, totalReports: rep.totalReports, isp: rep.isp, usageType: rep.usageType, domain: rep.domain, lastReportedAt: rep.lastReportedAt, configured: rep.configured } : null;
  const verdict = decideVerdict(pub, ioc.matched, rep?.abuseScore ?? 0, Boolean(rep?.configured));
  return { ip, isPublic: true, verdict, geo, reputation, ioc, alerts24h, generatedAt: new Date().toISOString() };
}
