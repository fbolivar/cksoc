/**
 * Inteligencia de CVEs para priorización por riesgo real de explotación.
 *  - CISA KEV (Known Exploited Vulnerabilities): catálogo de CVEs explotadas
 *    activamente en el mundo. Estar aquí = máxima prioridad.
 *  - EPSS (FIRST.org): probabilidad (0-1) de explotación en los próximos 30 días.
 *
 * Ambas fuentes son públicas y sin API key. Los datos se cachean en la tabla
 * cve_intel; un scheduler los refresca (KEV diario, EPSS cada 6 h para las CVEs
 * presentes en el entorno). getVulnerabilities() solo LEE de la tabla (rápido).
 */
import axios from 'axios';
import { query } from '../../config/db';
import { getStatesClient } from '../wazuh/wazuh.client';
import { logger } from '../../config/logger';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const STATES_INDEX = 'wazuh-states-vulnerabilities-*';

export interface CveIntel { cve: string; inKev: boolean; kevName: string | null; kevDue: string | null; epss: number | null; epssPct: number | null }

const CVE_RE = /^CVE-\d{4}-\d{3,7}$/i;

/** Refresca el catálogo CISA KEV completo en cve_intel. */
export async function refreshKev(): Promise<number> {
  try {
    const { data } = await axios.get<{ vulnerabilities?: { cveID: string; vulnerabilityName?: string; dateAdded?: string; dueDate?: string }[] }>(
      KEV_URL, { timeout: 30000, headers: { 'User-Agent': 'HexWatch-SOC' } }
    );
    const list = (data.vulnerabilities ?? []).filter((v) => v.cveID && CVE_RE.test(v.cveID));
    for (let i = 0; i < list.length; i += 500) {
      const chunk = list.slice(i, i + 500);
      const vals: string[] = [];
      const params: unknown[] = [];
      chunk.forEach((v, j) => {
        const b = j * 4;
        vals.push(`($${b + 1}, TRUE, $${b + 2}, $${b + 3}, $${b + 4})`);
        params.push(v.cveID.toUpperCase(), v.vulnerabilityName ?? null, v.dateAdded ?? null, v.dueDate ?? null);
      });
      await query(
        `INSERT INTO cve_intel (cve, in_kev, kev_name, kev_added, kev_due) VALUES ${vals.join(',')}
         ON CONFLICT (cve) DO UPDATE SET in_kev = TRUE, kev_name = EXCLUDED.kev_name,
           kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due, updated_at = now()`,
        params
      );
    }
    await recordFeed('cisa_kev', list.length, 'ok');
    logger.info({ count: list.length }, 'CVE intel: CISA KEV actualizado');
    return list.length;
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'error';
    await recordFeed('cisa_kev', 0, `error: ${msg}`.slice(0, 250));
    logger.warn({ err: msg }, 'CVE intel: fallo al refrescar CISA KEV');
    return 0;
  }
}

/** Consulta EPSS para un conjunto de CVEs (por lotes de 100) y las guarda. */
export async function enrichEpss(cves: string[]): Promise<number> {
  const unique = [...new Set(cves.map((c) => c.toUpperCase()).filter((c) => CVE_RE.test(c)))].slice(0, 800);
  if (!unique.length) return 0;
  let n = 0;
  try {
    for (let i = 0; i < unique.length; i += 100) {
      const chunk = unique.slice(i, i + 100);
      const { data } = await axios.get<{ data?: { cve: string; epss: string; percentile: string }[] }>(
        EPSS_URL, { params: { cve: chunk.join(','), pretty: false }, timeout: 20000, headers: { 'User-Agent': 'HexWatch-SOC' } }
      );
      for (const r of data.data ?? []) {
        if (!CVE_RE.test(r.cve)) continue;
        await query(
          `INSERT INTO cve_intel (cve, epss, epss_pct, epss_at) VALUES ($1, $2, $3, now())
           ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss, epss_pct = EXCLUDED.epss_pct, epss_at = now(), updated_at = now()`,
          [r.cve.toUpperCase(), Number(r.epss), Number(r.percentile)]
        );
        n++;
      }
    }
    await recordFeed('epss', n, 'ok');
    return n;
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'error';
    await recordFeed('epss', n, `error: ${msg}`.slice(0, 250));
    logger.warn({ err: msg }, 'CVE intel: fallo al consultar EPSS');
    return n;
  }
}

/** CVEs distintas presentes en el entorno (índice de estado de vulnerabilidades). */
export async function getEnvCves(limit = 800): Promise<string[]> {
  try {
    const client = getStatesClient();
    const { data } = await client.post<{ aggregations?: { c: { buckets: { key: string }[] } } }>(
      `/${STATES_INDEX}/_search`,
      { size: 0, aggs: { c: { terms: { field: 'vulnerability.id', size: limit } } } }
    );
    return (data.aggregations?.c.buckets ?? []).map((b) => b.key).filter((c) => CVE_RE.test(c));
  } catch {
    return [];
  }
}

/** Mapa de inteligencia para las CVEs dadas (solo lectura de la tabla). */
export async function getIntelMap(cves: string[]): Promise<Map<string, CveIntel>> {
  const unique = [...new Set(cves.map((c) => c.toUpperCase()).filter(Boolean))];
  if (!unique.length) return new Map();
  const rows = await query<{ cve: string; in_kev: boolean; kev_name: string | null; kev_due: string | null; epss: number | null; epss_pct: number | null }>(
    'SELECT cve, in_kev, kev_name, kev_due, epss, epss_pct FROM cve_intel WHERE cve = ANY($1)', [unique]
  ).catch(() => []);
  const map = new Map<string, CveIntel>();
  for (const r of rows) {
    map.set(r.cve, { cve: r.cve, inKev: r.in_kev, kevName: r.kev_name, kevDue: r.kev_due, epss: r.epss, epssPct: r.epss_pct });
  }
  return map;
}

export interface IntelStatus { kevCount: number; epssCount: number; feeds: { name: string; last_run_at: string | null; last_count: number; last_status: string | null }[] }
export async function intelStatus(): Promise<IntelStatus> {
  const kev = await query<{ n: string }>('SELECT COUNT(*)::int AS n FROM cve_intel WHERE in_kev = TRUE').catch(() => [{ n: '0' }]);
  const epss = await query<{ n: string }>('SELECT COUNT(*)::int AS n FROM cve_intel WHERE epss IS NOT NULL').catch(() => [{ n: '0' }]);
  const feeds = await query<{ name: string; last_run_at: string | null; last_count: number; last_status: string | null }>(
    'SELECT name, last_run_at, last_count, last_status FROM cve_intel_feeds ORDER BY name'
  ).catch(() => []);
  return { kevCount: Number(kev[0]?.n ?? 0), epssCount: Number(epss[0]?.n ?? 0), feeds };
}

/** Refresco completo: KEV + EPSS para las CVEs del entorno. */
export async function refreshIntel(): Promise<{ kev: number; epss: number }> {
  const kev = await refreshKev();
  const cves = await getEnvCves();
  const epss = await enrichEpss(cves);
  return { kev, epss };
}

async function recordFeed(name: string, count: number, status: string): Promise<void> {
  await query(
    `INSERT INTO cve_intel_feeds (name, last_run_at, last_count, last_status) VALUES ($1, now(), $2, $3)
     ON CONFLICT (name) DO UPDATE SET last_run_at = now(), last_count = $2, last_status = $3`,
    [name, count, status]
  ).catch(() => undefined);
}
