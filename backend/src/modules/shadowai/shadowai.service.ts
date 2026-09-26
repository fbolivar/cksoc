/**
 * Shadow-AI: detección de uso de servicios de IA generativa desde la red del
 * cliente, a partir del SNI/dominio (data.hostname) que el SonicWall ya reporta
 * a Wazuh (ver [[ndr]]). Agrupa por equipo (data.srcip -> host/usuario) y por
 * servicio de IA, y separa el uso APROBADO (sancionado por la organización) del
 * "shadow AI" (no autorizado). Persiste el uso para detectar novedades y avisar.
 *
 * NO bloquea nada: es visibilidad + alerta. La contención (si se quisiera) es
 * manual desde el firewall.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';
import { getAssetList } from '../assets/assets.service';
import { collectLogins } from '../ueba/ueba.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };

export interface AiService { id: string; name: string; vendor: string; domains: string[] }
// Catálogo de servicios de IA generativa (dominios de SNI). Ampliable.
export const AI_SERVICES: AiService[] = [
  { id: 'openai', name: 'ChatGPT / OpenAI', vendor: 'OpenAI', domains: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'sora.com'] },
  { id: 'anthropic', name: 'Claude', vendor: 'Anthropic', domains: ['anthropic.com', 'claude.ai'] },
  { id: 'gemini', name: 'Gemini / Google AI', vendor: 'Google', domains: ['gemini.google.com', 'bard.google.com', 'aistudio.google.com', 'makersuite.google.com', 'generativelanguage.googleapis.com'] },
  { id: 'copilot', name: 'Microsoft Copilot', vendor: 'Microsoft', domains: ['copilot.microsoft.com', 'copilot.cloud.microsoft'] },
  { id: 'github_copilot', name: 'GitHub Copilot', vendor: 'GitHub', domains: ['githubcopilot.com'] },
  { id: 'perplexity', name: 'Perplexity', vendor: 'Perplexity', domains: ['perplexity.ai'] },
  { id: 'huggingface', name: 'Hugging Face', vendor: 'Hugging Face', domains: ['huggingface.co', 'hf.co'] },
  { id: 'deepseek', name: 'DeepSeek', vendor: 'DeepSeek', domains: ['deepseek.com'] },
  { id: 'mistral', name: 'Mistral AI', vendor: 'Mistral', domains: ['mistral.ai'] },
  { id: 'midjourney', name: 'Midjourney', vendor: 'Midjourney', domains: ['midjourney.com'] },
  { id: 'xai', name: 'Grok (xAI)', vendor: 'xAI', domains: ['x.ai', 'grok.com'] },
  { id: 'stability', name: 'Stability AI', vendor: 'Stability', domains: ['stability.ai'] },
  { id: 'poe', name: 'Poe', vendor: 'Quora', domains: ['poe.com'] },
  { id: 'character', name: 'Character.AI', vendor: 'Character.AI', domains: ['character.ai'] },
  { id: 'elevenlabs', name: 'ElevenLabs', vendor: 'ElevenLabs', domains: ['elevenlabs.io'] },
  { id: 'runway', name: 'Runway', vendor: 'Runway', domains: ['runwayml.com'] },
  { id: 'jasper', name: 'Jasper', vendor: 'Jasper', domains: ['jasper.ai'] },
  { id: 'copyai', name: 'Copy.ai', vendor: 'Copy.ai', domains: ['copy.ai'] },
  { id: 'quillbot', name: 'QuillBot', vendor: 'QuillBot', domains: ['quillbot.com'] },
  { id: 'deepl', name: 'DeepL', vendor: 'DeepL', domains: ['deepl.com'] },
];
const NAME_BY_ID = new Map(AI_SERVICES.map((s) => [s.id, s.name] as const));

// Permite extender/forzar el catálogo por env (id:dominio1|dominio2 separados por coma). Opcional.
function extraServices(): AiService[] {
  const raw = (env.SHADOW_AI_EXTRA_DOMAINS || '').trim();
  if (!raw) return [];
  const out: AiService[] = [];
  for (const part of raw.split(',')) {
    const [id, doms] = part.split(':');
    if (id && doms) out.push({ id: id.trim(), name: id.trim(), vendor: 'custom', domains: doms.split('|').map((d) => d.trim().toLowerCase()).filter(Boolean) });
  }
  return out;
}
function catalog(): AiService[] { return [...AI_SERVICES, ...extraServices()]; }

/** Devuelve el servicio de IA que corresponde a un hostname (SNI), o null. */
function matchService(hostname: string): AiService | null {
  const h = hostname.toLowerCase();
  for (const s of catalog()) {
    for (const d of s.domains) { if (h === d || h.endsWith('.' + d)) return s; }
  }
  return null;
}

export function isShadowAiEnabled(): boolean {
  return String(env.SHADOW_AI_ENABLED ?? 'true').toLowerCase() !== 'false';
}

// --- Política de sanción (aprobado / no autorizado) ---
async function loadPolicy(): Promise<Map<string, boolean>> {
  const m = new Map<string, boolean>();
  try {
    const rows = await query<{ service: string; sanctioned: boolean }>('SELECT service, sanctioned FROM shadow_ai_policy');
    for (const r of rows) m.set(r.service, r.sanctioned);
  } catch { /* tabla aún no creada */ }
  return m;
}
function defaultSanctioned(): Set<string> {
  return new Set((env.SHADOW_AI_SANCTIONED || '').split(',').map((s) => s.trim()).filter(Boolean));
}

export interface ScanResult { window: string; devices: number; services: number; nuevos: number; nuevosShadow: { srcip: string; host: string | null; service: string; }[] }

export async function scan(rangeIn = '7d'): Promise<ScanResult> {
  const range = RANGE[rangeIn] ? rangeIn : '7d';
  const gte = RANGE[range];
  const policy = await loadPolicy();
  const def = defaultSanctioned();
  const sanctionedOf = (id: string): boolean => policy.has(id) ? !!policy.get(id) : def.has(id);

  const { data } = await getIndexerClient().post<{
    aggregations?: { dom: { buckets: { key: string; doc_count: number; src: { buckets: { key: string; doc_count: number; last: { value_as_string?: string } }[] } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { match: { 'rule.groups': 'sonicwall' } }, { exists: { field: 'data.hostname' } }] } },
    aggs: { dom: { terms: { field: 'data.hostname', size: 5000 }, aggs: { src: { terms: { field: 'data.srcip', size: 25 }, aggs: { last: { max: { field: '@timestamp' } } } } } } },
  });

  // Acumula por (srcip, servicio)
  const acc = new Map<string, { srcip: string; service: string; vendor: string; hits: number; last: string }>();
  for (const dom of data.aggregations?.dom?.buckets ?? []) {
    const svc = matchService(dom.key);
    if (!svc) continue;
    for (const src of dom.src.buckets) {
      const key = `${src.key}|${svc.id}`;
      const last = src.last?.value_as_string ?? new Date().toISOString();
      const cur = acc.get(key);
      if (cur) { cur.hits += src.doc_count; if (last > cur.last) cur.last = last; }
      else acc.set(key, { srcip: src.key, service: svc.id, vendor: svc.vendor, hits: src.doc_count, last });
    }
  }

  // Resolución host/usuario (best-effort)
  const [assets, logins] = await Promise.all([getAssetList().catch(() => []), collectLogins(24).catch(() => [])]);
  const nameByIp = new Map<string, string>();
  for (const a of assets) if (a.ip) nameByIp.set(a.ip, a.name);
  const userByHost = new Map<string, string>();
  for (const l of logins) if (l.outcome === 'success' && l.host) userByHost.set(l.host, l.user);

  let nuevos = 0;
  const nuevosShadow: { srcip: string; host: string | null; service: string }[] = [];
  const devices = new Set<string>();
  const services = new Set<string>();
  for (const v of acc.values()) {
    devices.add(v.srcip); services.add(v.service);
    const host = nameByIp.get(v.srcip) ?? null;
    const user = host ? (userByHost.get(host) ?? null) : null;
    const sanctioned = sanctionedOf(v.service);
    const rows = await query<{ nuevo: boolean }>(
      `INSERT INTO shadow_ai_usage (srcip, host, srcuser, service, vendor, sanctioned, hits, last_seen)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (srcip, service) DO UPDATE
         SET host=EXCLUDED.host, srcuser=EXCLUDED.srcuser, vendor=EXCLUDED.vendor,
             sanctioned=EXCLUDED.sanctioned, hits=EXCLUDED.hits, last_seen=EXCLUDED.last_seen
       RETURNING (xmax = 0) AS nuevo`,
      [v.srcip, host, user, v.service, v.vendor, sanctioned, v.hits, v.last],
    );
    if (rows[0]?.nuevo) { nuevos++; if (!sanctioned) nuevosShadow.push({ srcip: v.srcip, host, service: NAME_BY_ID.get(v.service) ?? v.service }); }
  }
  await query("INSERT INTO shadow_ai_meta (k, v) VALUES ('last_scan', now()::text) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v").catch(() => undefined);
  return { window: range, devices: devices.size, services: services.size, nuevos, nuevosShadow };
}

// --- Lecturas para la UI ---
export interface AiUsageRow { srcip: string; host: string | null; srcuser: string | null; service: string; name: string; vendor: string; sanctioned: boolean; hits: number; first_seen: string; last_seen: string }

export async function getOverview(): Promise<unknown> {
  const svc = await query<{ service: string; vendor: string; sanctioned: boolean; hits: number; devices: number; last_seen: string }>(
    `SELECT service, max(vendor) AS vendor, bool_and(sanctioned) AS sanctioned, sum(hits)::int AS hits,
            count(DISTINCT srcip)::int AS devices, max(last_seen) AS last_seen
       FROM shadow_ai_usage GROUP BY service ORDER BY bool_and(sanctioned) ASC, sum(hits) DESC`,
  );
  const dev = await query<{ srcip: string; host: string | null; srcuser: string | null; servicios: number; hits: number; shadow: boolean; last_seen: string }>(
    `SELECT srcip, max(host) AS host, max(srcuser) AS srcuser, count(DISTINCT service)::int AS servicios,
            sum(hits)::int AS hits, bool_or(NOT sanctioned) AS shadow, max(last_seen) AS last_seen
       FROM shadow_ai_usage GROUP BY srcip ORDER BY bool_or(NOT sanctioned) DESC, sum(hits) DESC`,
  );
  const meta = await query<{ v: string }>("SELECT v FROM shadow_ai_meta WHERE k='last_scan'").catch(() => [] as { v: string }[]);
  const services = svc.map((s) => ({ ...s, name: NAME_BY_ID.get(s.service) ?? s.service }));
  const kpis = {
    dispositivos: dev.length,
    servicios: svc.length,
    shadowDispositivos: dev.filter((d) => d.shadow).length,
    shadowServicios: svc.filter((s) => !s.sanctioned).length,
    shadowHits: svc.filter((s) => !s.sanctioned).reduce((n, s) => n + s.hits, 0),
  };
  return { kpis, services, devices: dev, lastScan: meta[0]?.v ?? null };
}

export async function listUsage(opts: { shadow?: boolean } = {}): Promise<AiUsageRow[]> {
  const rows = await query<AiUsageRow>(
    `SELECT srcip, host, srcuser, service, vendor, sanctioned, hits, first_seen, last_seen
       FROM shadow_ai_usage ${opts.shadow ? 'WHERE sanctioned = false' : ''}
       ORDER BY sanctioned ASC, hits DESC LIMIT 1000`,
  );
  return rows.map((r) => ({ ...r, name: NAME_BY_ID.get(r.service) ?? r.service }));
}

export async function listServices(): Promise<{ id: string; name: string; vendor: string; sanctioned: boolean }[]> {
  const policy = await loadPolicy();
  const def = defaultSanctioned();
  return AI_SERVICES.map((s) => ({ id: s.id, name: s.name, vendor: s.vendor, sanctioned: policy.has(s.id) ? !!policy.get(s.id) : def.has(s.id) }));
}

export async function setPolicy(service: string, sanctioned: boolean, userId: string | null): Promise<void> {
  if (!service) throw new HttpError(400, 'Servicio requerido');
  await query(
    `INSERT INTO shadow_ai_policy (service, sanctioned, updated_by, updated_at)
       VALUES ($1,$2,$3, now())
     ON CONFLICT (service) DO UPDATE SET sanctioned=EXCLUDED.sanctioned, updated_by=EXCLUDED.updated_by, updated_at=now()`,
    [service, sanctioned, userId],
  );
  await query('UPDATE shadow_ai_usage SET sanctioned=$2 WHERE service=$1', [service, sanctioned]);
}

export async function forget(srcip: string, service: string): Promise<void> {
  await query('DELETE FROM shadow_ai_usage WHERE srcip=$1 AND service=$2', [srcip, service]);
}
