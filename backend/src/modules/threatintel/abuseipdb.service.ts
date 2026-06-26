/**
 * Consulta de reputacion de IPs en AbuseIPDB (threat intel minimo).
 * Cachea resultados para no agotar la cuota (free tier ~1000/dia).
 */
import axios from 'axios';
import { env } from '../../config/env';

export interface IpReputation {
  ip: string;
  abuseScore: number; // 0-100 (abuseConfidenceScore)
  totalReports: number;
  countryCode: string | null;
  isp: string | null;
  domain: string | null;
  lastReportedAt: string | null;
  configured: boolean;
}

const cache = new Map<string, { at: number; data: IpReputation }>();
const TTL_MS = 30 * 60_000; // 30 min

export function isThreatIntelConfigured(): boolean {
  return Boolean(env.ABUSEIPDB_API_KEY);
}

/** Devuelve la reputacion de una IP, o un objeto "no configurado" si no hay API key. */
export async function checkReputation(ip: string): Promise<IpReputation> {
  if (!isThreatIntelConfigured()) {
    return emptyRep(ip, false);
  }
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.at < TTL_MS) return cached.data;

  try {
    const { data } = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: env.ABUSEIPDB_API_KEY as string, Accept: 'application/json' },
      timeout: 8000,
    });
    const d = data.data;
    const rep: IpReputation = {
      ip,
      abuseScore: d.abuseConfidenceScore ?? 0,
      totalReports: d.totalReports ?? 0,
      countryCode: d.countryCode ?? null,
      isp: d.isp ?? null,
      domain: d.domain ?? null,
      lastReportedAt: d.lastReportedAt ?? null,
      configured: true,
    };
    cache.set(ip, { at: Date.now(), data: rep });
    return rep;
  } catch {
    // Un fallo de la API no debe romper el flujo: devolvemos vacio "configurado".
    return emptyRep(ip, true);
  }
}

function emptyRep(ip: string, configured: boolean): IpReputation {
  return {
    ip,
    abuseScore: 0,
    totalReports: 0,
    countryCode: null,
    isp: null,
    domain: null,
    lastReportedAt: null,
    configured,
  };
}
