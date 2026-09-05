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
  confidence: number;              // confianza base 0-100
  last_seen_feed: string | null;   // última vez reportado por un feed (NULL = manual)
  effective_confidence: number;    // confianza tras el envejecimiento
  age_days: number;                // días desde que se vio por última vez
}

// Decaimiento de confianza por día sin re-observación en feeds (los IOCs manuales
// no envejecen). A ~3 pts/día, un IOC que sale de todos los feeds pierde relevancia
// en ~2-3 semanas, y a los 30 días el aging lo deshabilita.
const DECAY_PER_DAY = 3;
const STALE_DAYS = 30;
const AGE_DAYS_SQL = "FLOOR(EXTRACT(EPOCH FROM (now() - COALESCE(last_seen_feed, created_at))) / 86400)::int";
const EFF_CONF_SQL =
  `CASE WHEN last_seen_feed IS NULL THEN confidence
        ELSE GREATEST(0, confidence - ${AGE_DAYS_SQL} * ${DECAY_PER_DAY}) END`;

// Plataformas de hosting compartido legítimas: los feeds de URL (URLhaus/ThreatFox)
// listan estos dominios por una URL maliciosa puntual alojada ahí, pero el dominio en
// sí es benigno y no accionable. Se filtran SOLO en el cruce de dominios (los IOC de IP
// se conservan siempre). Mismo criterio que el módulo NDR.
const LEGIT_HOSTING_RE = /(^|\.)(github|githubusercontent|google|googleapis|googleusercontent|gstatic|youtube|discord|discordapp|cloudinary|imgur|ibb|firebasestorage|licdn|linkedin|microsoft|office365?|windows|live|amazonaws|cloudfront|dropbox|apple|icloud|cloudflare|akamai|fastly|bitbucket|gitlab|wetransfer|whatsapp|facebook|fbcdn)\.[a-z]{2,}(\.[a-z]{2,})?$/i;

export interface IocMatch {
  value: string;
  type: IocType;
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
  const sql = `SELECT *, ${AGE_DAYS_SQL} AS age_days, ${EFF_CONF_SQL} AS effective_confidence
               FROM iocs ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
               ORDER BY match_count DESC, ${EFF_CONF_SQL} DESC, created_at DESC LIMIT ${lim}`;
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
    `INSERT INTO iocs (ioc_type, value, source, description, tags, added_by, confidence)
     VALUES ($1, $2, 'manual', $3, $4, $5, 90)
     ON CONFLICT (ioc_type, value) DO UPDATE SET description = EXCLUDED.description, tags = EXCLUDED.tags, enabled = TRUE, confidence = 90
     RETURNING *, ${AGE_DAYS_SQL} AS age_days, ${EFF_CONF_SQL} AS effective_confidence`,
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
      const iocs = await fetchFeed(def);
      // Agrupa por tipo (un feed puede traer varios) e inserta por lotes.
      const byType = new Map<string, string[]>();
      for (const it of iocs) {
        const arr = byType.get(it.type) ?? [];
        arr.push(it.value);
        byType.set(it.type, arr);
      }
      const conf = def.confidence ?? 60;
      for (const [type, vals] of byType) {
        for (let i = 0; i < vals.length; i += 2000) {
          const chunk = vals.slice(i, i + 2000);
          await query(
            `INSERT INTO iocs (ioc_type, value, source, confidence, last_seen_feed)
             SELECT $1, v, $2, $3, now() FROM unnest($4::text[]) AS v
             ON CONFLICT (ioc_type, value) DO UPDATE
               SET source = EXCLUDED.source, enabled = TRUE, last_seen_feed = now(),
                   confidence = GREATEST(iocs.confidence, EXCLUDED.confidence)`,
            [type, def.name, conf, chunk]
          );
        }
      }
      count = iocs.length;
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
  // Aging: deshabilita IOCs de feeds no re-observados en STALE_DAYS (los manuales
  // no envejecen). Si vuelven a un feed, el upsert los reactiva.
  await query(
    `UPDATE iocs SET enabled = FALSE
      WHERE source <> 'manual' AND enabled = TRUE
        AND last_seen_feed IS NOT NULL
        AND last_seen_feed < now() - ($1 || ' days')::interval`,
    [STALE_DAYS]
  ).catch(() => undefined);
  return results;
}

/** Cruza los IOCs de IP habilitados contra las IPs vistas en alertas (7d). */
interface AggBucket { key: string; doc_count: number; last: { value_as_string?: string }; rule: { hits: { hits: { _source: { rule?: { description?: string }; agent?: { name?: string } } }[] } } }

/** Agrega los valores más vistos de un campo de alerta en 7d (o [] si el campo no existe).
 *  Ventana de 7d (no 24h): las coincidencias de IOC son raras y valiosas; una ventana corta
 *  se pierde los hits de días anteriores (p.ej. una IP atacante vista una sola vez). */
async function aggField(field: string, size = 1500, lean = false): Promise<AggBucket[]> {
  try {
    const client = getIndexerClient();
    // Modo lean (para el agg de IPs, de alta cardinalidad): omite el top_hits por bucket
    // —que es lo costoso sobre ~10.7k buckets— y se enriquecen luego solo los coincidentes.
    const sub = lean ? {} : { aggs: { last: { max: { field: '@timestamp' } }, rule: { top_hits: { size: 1, _source: ['rule.description', 'agent.name'] } } } };
    const { data } = await client.post<{ aggregations?: { v: { buckets: AggBucket[] } } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-7d' } } }, { exists: { field } }] } },
        aggs: { v: { terms: { field, size }, ...sub } },
      }
    );
    return data.aggregations?.v?.buckets ?? [];
  } catch { return []; }
}

/** Enriquece una IP coincidente con su última alerta (regla, agente, hora) — barato: 1 hit. */
async function ipSample(ip: string): Promise<{ lastSeen: string; rule: string; agent: string }> {
  try {
    const { data } = await getIndexerClient().post<{ hits: { hits: { _source: { '@timestamp'?: string; rule?: { description?: string }; agent?: { name?: string } } }[] } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 1,
        sort: [{ '@timestamp': { order: 'desc' } }],
        _source: ['@timestamp', 'rule.description', 'agent.name'],
        query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-7d' } } }], should: [{ term: { 'data.srcip': ip } }, { term: { 'data.dstip': ip } }, { term: { 'data.remip': ip } }], minimum_should_match: 1 } },
      }
    );
    const h = data.hits.hits[0]?._source;
    return { lastSeen: h?.['@timestamp'] ?? '', rule: h?.rule?.description ?? '', agent: h?.agent?.name ?? '' };
  } catch { return { lastSeen: '', rule: '', agent: '' }; }
}

/**
 * Cruza los IOCs habilitados contra los valores vistos en alertas (7d):
 *   - IP     → data.srcip, data.dstip, data.remip (origen y destino del tráfico)
 *   - dominio→ data.dns.question.name, data.win.eventdata.queryName, data.dstname
 *   - URL    → data.url
 *   - hash   → syscheck.{sha256,sha1,md5}_after (FIM), data.win.eventdata.hashes
 * La cobertura depende de la telemetría disponible (DNS/proxy/FIM/Sysmon).
 */
export async function getMatches(): Promise<IocMatch[]> {
  const iocRows = await query<{ ioc_type: string; value: string; source: string }>(
    "SELECT ioc_type, value, source FROM iocs WHERE enabled = TRUE"
  );
  if (iocRows.length === 0) return [];

  // Mapas de búsqueda por familia de tipo.
  const ipMap = new Map<string, string>();
  const domainMap = new Map<string, string>();
  const urlMap = new Map<string, string>();
  const hashMap = new Map<string, { type: string; source: string }>();
  for (const i of iocRows) {
    if (i.ioc_type === 'ip') ipMap.set(i.value, i.source);
    else if (i.ioc_type === 'domain') domainMap.set(i.value.toLowerCase(), i.source);
    else if (i.ioc_type === 'url') urlMap.set(i.value, i.source);
    else if (i.ioc_type === 'md5' || i.ioc_type === 'sha1' || i.ioc_type === 'sha256') hashMap.set(i.value.toLowerCase(), { type: i.ioc_type, source: i.source });
  }

  const matches: IocMatch[] = [];
  const push = (b: AggBucket, type: IocType, source: string) => {
    const hit = b.rule.hits.hits[0]?._source;
    matches.push({ value: b.key, type, source, alertCount: b.doc_count, lastSeen: b.last.value_as_string ?? '', sampleRule: hit?.rule?.description ?? '', agent: hit?.agent?.name ?? '' });
  };

  // IPs: cruza ORIGEN y DESTINO (+remip). Las IPs maliciosas suelen ser el DESTINO
  // al que la red se conecta (egress a infraestructura del atacante); antes solo se
  // miraba data.srcip y por eso se perdían las conexiones "hacia lo malo".
  if (ipMap.size) {
    // size 12.000 + lean: cubre la cardinalidad de dstip (~10.7k/7d) sin perder destinos
    // maliciosos de baja frecuencia (1 conexión = egress a C2), y sin el top_hits caro.
    const ipHit = new Map<string, { count: number; source: string }>();
    for (const field of ['data.srcip', 'data.dstip', 'data.remip']) {
      for (const b of await aggField(field, 12000, true)) {
        const key = String(b.key);
        const s = ipMap.get(key);
        if (s && !ipHit.has(key)) ipHit.set(key, { count: b.doc_count, source: s });
      }
    }
    // Enriquece solo los coincidentes (pocos) con regla/agente/última vez.
    for (const [ip, info] of ipHit) {
      const meta = await ipSample(ip);
      matches.push({ value: ip, type: 'ip', source: info.source, alertCount: info.count, lastSeen: meta.lastSeen, sampleRule: meta.rule, agent: meta.agent });
    }
  }

  // Dominios (incluye el SNI/hostname del FortiGate — Application Control).
  // Se descartan IOCs de dominio sobre plataformas de hosting compartido legítimas
  // (github/google/etc.): los feeds URLhaus/ThreatFox las listan por una URL puntual,
  // pero el dominio en sí es benigno y no accionable (mismo criterio que NDR).
  if (domainMap.size) {
    for (const field of ['data.dns.question.name', 'data.win.eventdata.queryName', 'data.dstname', 'data.hostname']) {
      for (const b of await aggField(field)) {
        const host = String(b.key).toLowerCase();
        if (LEGIT_HOSTING_RE.test(host)) continue;
        const s = domainMap.get(host); if (s) push(b, 'domain', s);
      }
    }
  }
  // URLs.
  if (urlMap.size) for (const b of await aggField('data.url')) { const s = urlMap.get(b.key); if (s) push(b, 'url', s); }

  // Hashes (FIM + Sysmon).
  if (hashMap.size) {
    for (const field of ['syscheck.sha256_after', 'syscheck.sha1_after', 'syscheck.md5_after', 'data.win.eventdata.hashes']) {
      for (const b of await aggField(field)) {
        const info = hashMap.get(String(b.key).toLowerCase());
        if (info) push(b, info.type as IocType, info.source);
      }
    }
  }

  // Dedup por (tipo+valor) conservando el mayor conteo, y ordena.
  const dedup = new Map<string, IocMatch>();
  for (const m of matches) {
    const k = `${m.type}|${m.value}`;
    const cur = dedup.get(k);
    if (!cur || m.alertCount > cur.alertCount) dedup.set(k, m);
  }
  const out = [...dedup.values()].sort((a, b) => b.alertCount - a.alertCount);

  // Actualiza estadísticas de coincidencia.
  if (out.length) {
    const values = [...new Set(out.map((m) => m.value))];
    await query(
      `UPDATE iocs SET last_match_at = now(), match_count = match_count + 1 WHERE value = ANY($1::text[]) AND enabled = TRUE`,
      [values]
    ).catch(() => undefined);
  }
  return out;
}
