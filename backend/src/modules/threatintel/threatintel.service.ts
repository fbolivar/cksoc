/**
 * Threat Intelligence: catálogo de IOCs (feeds + manual) y cruce automático
 * contra las IPs vistas en las alertas (Wazuh + FortiGate) del Indexer.
 */
import { query } from '../../config/db';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { FEEDS, fetchFeed } from './feeds';

export type IocType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';
export const IOC_TYPES: IocType[] = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256'];

export interface Ioc {
  id: string;
  ioc_type: IocType;
  value: string;
  source: string;
  description: string | null;
  tags: string[];
  enabled: boolean;
  last_match_at: string | null;
  match_count: number;
  created_at: string;
}

export interface IocMatch {
  value: string;
  type: 'ip';
  source: string;
  alertCount: number;
  lastSeen: string;
  sampleRule: string;
  agent: string;
}

const VALIDATORS: Record<IocType, RegExp> = {
  ip: /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/,
  domain: /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$/i,
  url: /^https?:\/\/.{3,}$/i,
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
};

export async function listIocs(opts: { type?: string; q?: string; limit?: number }): Promise<Ioc[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.type && IOC_TYPES.includes(opts.type as IocType)) { params.push(opts.type); where.push(`ioc_type = $${params.length}`); }
  if (opts.q) { params.push(`%${opts.q}%`); where.push(`value ILIKE $${params.length}`); }
  const lim = Math.min(Math.max(opts.limit ?? 200, 1), 1000);
  const sql = `SELECT * FROM iocs ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY match_count DESC, created_at DESC LIMIT ${lim}`;
  return query<Ioc>(sql, params);
}

export async function countByType(): Promise<{ total: number; byType: Record<string, number> }> {
  const rows = await query<{ ioc_type: string; n: string }>('SELECT ioc_type, COUNT(*)::int AS n FROM iocs GROUP BY ioc_type');
  const byType: Record<string, number> = {};
  let total = 0;
  for (const r of rows) { byType[r.ioc_type] = Number(r.n); total += Number(r.n); }
  return { total, byType };
}

export async function addIoc(input: { type: string; value: string; description?: string; tags?: string[] }, userId: string): Promise<Ioc> {
  const type = String(input.type) as IocType;
  const value = String(input.value || '').trim();
  if (!IOC_TYPES.includes(type)) throw new HttpError(400, 'Tipo de IOC inválido');
  if (!VALIDATORS[type].test(value)) throw new HttpError(400, `Valor no válido para tipo ${type}`);
  const tags = Array.isArray(input.tags) ? input.tags.slice(0, 10).map((t) => String(t).slice(0, 40)) : [];
  const rows = await query<Ioc>(
    `INSERT INTO iocs (ioc_type, value, source, description, tags, added_by)
     VALUES ($1, $2, 'manual', $3, $4, $5)
     ON CONFLICT (ioc_type, value) DO UPDATE SET description = EXCLUDED.description, tags = EXCLUDED.tags, enabled = TRUE
     RETURNING *`,
    [type, value.toLowerCase(), input.description ?? null, tags, userId]
  );
  return rows[0];
}

export async function removeIoc(id: string): Promise<void> {
  const rows = await query('DELETE FROM iocs WHERE id = $1 RETURNING id', [id]);
  if (rows.length === 0) throw new HttpError(404, 'IOC no encontrado');
}

export async function getFeeds(): Promise<{ name: string; last_run_at: string | null; last_count: number; last_status: string | null }[]> {
  const known = FEEDS.map((f) => f.name);
  const rows = await query<{ name: string; last_run_at: string | null; last_count: number; last_status: string | null }>('SELECT * FROM ioc_feeds');
  const map = new Map(rows.map((r) => [r.name, r]));
  return known.map((name) => map.get(name) ?? { name, last_run_at: null, last_count: 0, last_status: 'nunca ejecutado' });
}

/** Descarga todos los feeds y hace upsert de sus IOCs. */
export async function refreshFeeds(): Promise<{ name: string; count: number; status: string }[]> {
  const results: { name: string; count: number; status: string }[] = [];
  for (const def of FEEDS) {
    let count = 0;
    let status = 'ok';
    try {
      const values = await fetchFeed(def);
      if (values.length) {
        await query(
          `INSERT INTO iocs (ioc_type, value, source)
           SELECT $1, LOWER(v), $2 FROM unnest($3::text[]) AS v
           ON CONFLICT (ioc_type, value) DO UPDATE SET source = EXCLUDED.source, enabled = TRUE`,
          [def.type, def.name, values]
        );
      }
      count = values.length;
    } catch (err) {
      status = err instanceof Error ? err.message.slice(0, 200) : 'error';
    }
    await query(
      `INSERT INTO ioc_feeds (name, last_run_at, last_count, last_status)
       VALUES ($1, now(), $2, $3)
       ON CONFLICT (name) DO UPDATE SET last_run_at = now(), last_count = EXCLUDED.last_count, last_status = EXCLUDED.last_status`,
      [def.name, count, status]
    );
    results.push({ name: def.name, count, status });
  }
  return results;
}

/** Cruza los IOCs de IP habilitados contra las IPs vistas en alertas (24h). */
export async function getMatches(): Promise<IocMatch[]> {
  const ipIocs = await query<{ value: string; source: string }>(
    "SELECT value, source FROM iocs WHERE ioc_type = 'ip' AND enabled = TRUE"
  );
  if (ipIocs.length === 0) return [];
  const srcMap = new Map(ipIocs.map((i) => [i.value, i.source]));

  const client = getIndexerClient();
  const { data } = await client.post<{
    aggregations?: { ips: { buckets: { key: string; doc_count: number; last: { value_as_string?: string }; rule: { hits: { hits: { _source: { rule?: { description?: string }; agent?: { name?: string } } }[] } } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }, { exists: { field: 'data.srcip' } }] } },
    aggs: {
      ips: {
        terms: { field: 'data.srcip', size: 3000 },
        aggs: {
          last: { max: { field: '@timestamp' } },
          rule: { top_hits: { size: 1, _source: ['rule.description', 'agent.name'] } },
        },
      },
    },
  });

  const matches: IocMatch[] = [];
  for (const b of data.aggregations?.ips?.buckets ?? []) {
    const source = srcMap.get(b.key);
    if (!source) continue;
    const hit = b.rule.hits.hits[0]?._source;
    matches.push({
      value: b.key,
      type: 'ip',
      source,
      alertCount: b.doc_count,
      lastSeen: b.last.value_as_string ?? '',
      sampleRule: hit?.rule?.description ?? '',
      agent: hit?.agent?.name ?? '',
    });
  }
  matches.sort((a, b) => b.alertCount - a.alertCount);

  // Actualiza estadísticas de coincidencia de los IOCs que dieron match.
  if (matches.length) {
    const hitValues = matches.map((m) => m.value);
    await query(
      `UPDATE iocs SET last_match_at = now(), match_count = match_count + 1
       WHERE ioc_type = 'ip' AND value = ANY($1::text[])`,
      [hitValues]
    ).catch(() => undefined);
  }
  return matches;
}
