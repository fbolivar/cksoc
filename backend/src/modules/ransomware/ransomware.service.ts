/**
 * Inteligencia de Ransomware — vigilancia de sitios de extorsión/filtración usando
 * la fuente pública ransomware.live. Muestra grupos activos y víctimas recientes, y
 * RESALTA lo relevante para el cliente (su marca/dominio, su país, su sector).
 *
 * PRIVACIDAD: se descarga el feed público completo y se filtra LOCALMENTE; nunca se
 * envía la marca ni el dominio del cliente a la API externa.
 */
import axios from 'axios';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

const BASE = process.env.RANSOMWARE_API_URL || 'https://api.ransomware.live';
const COUNTRY = (process.env.RANSOMWARE_COUNTRY || 'CO').toUpperCase();
const SECTORS = (process.env.RANSOMWARE_SECTORS || 'law,legal,attorney,abogad,juris,court,notar,litig')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const WATCH = (process.env.RANSOMWARE_WATCH || '')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

const http = axios.create({ timeout: 20000, headers: { 'User-Agent': 'hexwatch-soc/1.0', Accept: 'application/json' } });

export type Relevance = 'directo' | 'pais' | 'sector' | null;
export interface RwVictim {
  victim: string; group: string; country: string | null; sector: string | null;
  discovered: string | null; published: string | null; domain: string | null; url: string | null;
  description: string | null; relevance: Relevance; relWhy: string | null;
}

function clip(s: unknown, n = 280): string | null {
  if (typeof s !== 'string') return null;
  const t = s.replace(/\s+/g, ' ').trim();
  return t ? t.slice(0, n) : null;
}

function assess(v: RwVictim): RwVictim {
  const hay = `${v.victim} ${v.domain ?? ''} ${v.description ?? ''}`.toLowerCase();
  const hit = WATCH.find((w) => w && hay.includes(w));
  if (hit) { v.relevance = 'directo'; v.relWhy = `coincide "${hit}"`; return v; }
  if (v.country && v.country.toUpperCase() === COUNTRY) { v.relevance = 'pais'; v.relWhy = v.country; return v; }
  const sec = (v.sector ?? '').toLowerCase();
  const descr = (v.description ?? '').toLowerCase();
  const sm = SECTORS.find((s) => sec.includes(s) || descr.includes(s));
  if (sm) { v.relevance = 'sector'; v.relWhy = v.sector || sm; return v; }
  return v;
}

function normRecent(r: Record<string, unknown>): RwVictim {
  return assess({
    victim: String(r.victim ?? '').trim() || '(sin nombre)',
    group: String(r.group ?? '').trim() || '?',
    country: (r.country as string) ?? null,
    sector: (r.activity as string) ?? null,
    discovered: (r.discovered as string) ?? null,
    published: (r.attackdate as string) ?? (r.discovered as string) ?? null,
    domain: (r.domain as string) ?? null,
    url: (r.url as string) ?? (r.claim_url as string) ?? null,
    description: clip(r.description),
    relevance: null, relWhy: null,
  });
}
function normCountry(r: Record<string, unknown>): RwVictim {
  return assess({
    victim: String(r.post_title ?? r.victim ?? '').trim() || '(sin nombre)',
    group: String(r.group_name ?? r.group ?? '').trim() || '?',
    country: (r.country as string) ?? null,
    sector: (r.activity as string) ?? null,
    discovered: (r.discovered as string) ?? null,
    published: (r.published as string) ?? (r.discovered as string) ?? null,
    domain: (r.website as string) ?? null,
    url: (r.post_url as string) ?? null,
    description: clip(r.description),
    relevance: null, relWhy: null,
  });
}

async function fetchRecent(): Promise<RwVictim[]> {
  const { data } = await http.get<Record<string, unknown>[]>(`${BASE}/v2/recentvictims`);
  return Array.isArray(data) ? data.map(normRecent) : [];
}
async function fetchCountry(): Promise<RwVictim[]> {
  try {
    const { data } = await http.get<Record<string, unknown>[]>(`${BASE}/v2/countryvictims/${COUNTRY}`);
    return Array.isArray(data) ? data.map(normCountry) : [];
  } catch { return []; }
}

function dateOf(v: RwVictim): number {
  const d = v.published || v.discovered;
  const t = d ? Date.parse(d) : NaN;
  return Number.isFinite(t) ? t : 0;
}
const keyOf = (v: RwVictim): string => `${v.group}|${v.victim}`.toLowerCase();

export interface RwOverview {
  generatedAt: string; configured: boolean; pais: string; watchActivo: boolean;
  kpis: { recientes: number; gruposActivos: number; victimasPais: number; sectorHits: number; directos: number };
  relevantes: RwVictim[]; recientes: RwVictim[]; topGrupos: { group: string; count: number }[];
}

export async function getOverview(days = 30): Promise<RwOverview> {
  const [recent, country] = await Promise.all([fetchRecent().catch(() => [] as RwVictim[]), fetchCountry().catch(() => [] as RwVictim[])]);
  const since = Date.now() - days * 86400000;
  const inRange = (v: RwVictim) => { const t = dateOf(v); return t === 0 || t >= since; };
  const recientes = recent.filter(inRange).sort((a, b) => dateOf(b) - dateOf(a));
  const paisRecent = country.filter((v) => dateOf(v) >= since).sort((a, b) => dateOf(b) - dateOf(a));

  const byKey = new Map<string, RwVictim>();
  for (const v of [...recientes, ...paisRecent]) if (v.relevance) { const k = keyOf(v); if (!byKey.has(k)) byKey.set(k, v); }
  const rank = (x: RwVictim) => (x.relevance === 'directo' ? 0 : x.relevance === 'pais' ? 1 : 2);
  const relevantes = [...byKey.values()].sort((a, b) => rank(a) - rank(b) || dateOf(b) - dateOf(a)).slice(0, 60);

  const gc = new Map<string, number>();
  for (const v of recientes) gc.set(v.group, (gc.get(v.group) ?? 0) + 1);
  const topGrupos = [...gc.entries()].map(([group, count]) => ({ group, count })).sort((a, b) => b.count - a.count).slice(0, 12);

  return {
    generatedAt: new Date().toISOString(), configured: true, pais: COUNTRY, watchActivo: WATCH.length > 0,
    kpis: {
      recientes: recientes.length,
      gruposActivos: gc.size,
      victimasPais: country.length,
      sectorHits: recientes.filter((v) => v.relevance === 'sector').length,
      directos: [...byKey.values()].filter((v) => v.relevance === 'directo').length,
    },
    relevantes, recientes: recientes.slice(0, 100), topGrupos,
  };
}

// ─── Dedup de alertas ───
export async function ensureSchema(): Promise<void> {
  await query(
    `CREATE TABLE IF NOT EXISTS ransomware_alerted (
       victim_key TEXT PRIMARY KEY, group_name TEXT, victim TEXT, relevance TEXT, country TEXT,
       alerted_at TIMESTAMPTZ NOT NULL DEFAULT now()
     )`, [],
  );
}

/** Inserta en la tabla las víctimas relevantes aún no vistas y las devuelve (las nuevas). */
export async function findNewRelevant(days = 60): Promise<RwVictim[]> {
  await ensureSchema();
  const ov = await getOverview(days);
  const fresh: RwVictim[] = [];
  for (const v of ov.relevantes) {
    const key = keyOf(v);
    const rows = await query('SELECT 1 FROM ransomware_alerted WHERE victim_key=$1', [key]);
    if (rows.length === 0) {
      await query(
        'INSERT INTO ransomware_alerted(victim_key,group_name,victim,relevance,country) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
        [key, v.group, v.victim, v.relevance, v.country],
      );
      fresh.push(v);
    }
  }
  return fresh;
}

/** Siembra la tabla con lo relevante actual SIN alertar (evita avalancha de histórico al primer arranque). */
export async function seedBaseline(): Promise<boolean> {
  await ensureSchema();
  const rows = await query<{ n: number }>('SELECT count(*)::int AS n FROM ransomware_alerted', []);
  if ((rows[0]?.n ?? 0) > 0) return false;
  await findNewRelevant(90);
  logger.info('🩸 Ransomware: baseline sembrado (sin alertar histórico)');
  return true;
}
