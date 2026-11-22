/**
 * Dark Web Radar — centro de fugas: unifica las señales de exposición del cliente en
 * fuentes OSINT accesibles y es honesto sobre su cobertura.
 *   - Sitios de extorsión / ransomware (ransomware.live)      -> ACTIVO
 *   - Credenciales en brechas (HIBP, vía credexp)             -> ACTIVO
 *   - Exposición en GitHub público (search/code)              -> requiere GITHUB_TOKEN
 *   - Pastes públicos / dark web profundo (Tor)               -> requiere feed comercial
 * PRIVACIDAD: solo busca por DOMINIO público del cliente, nunca por correos/nombres.
 */
import axios from 'axios';
import { logger } from '../../config/logger';
import { getSummary as credSummary } from '../credexp/credexp.service';
import { getOverview as rwOverview } from '../ransomware/ransomware.service';

const DOMAINS = (process.env.DARKWEB_DOMAINS || 'col-law.com').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const http = axios.create({ timeout: 20000, headers: { 'User-Agent': 'hexwatch-soc/1.0' } });

export type Sev = 'critica' | 'alta' | 'media' | 'baja';
export interface DwFinding { source: string; severity: Sev; title: string; detail: string; url: string | null; date: string | null }
export interface DwSource { key: string; label: string; estado: 'activo' | 'requiere_config' | 'requiere_feed'; nota: string }
export interface DwRadar {
  generatedAt: string;
  kpis: { total: number; credenciales: number; ransomware: number; github: number };
  fuentes: DwSource[];
  hallazgos: DwFinding[];
}

async function githubSearch(): Promise<DwFinding[]> {
  if (!GH_TOKEN) return [];
  const out: DwFinding[] = [];
  for (const d of DOMAINS) {
    try {
      const { data } = await http.get<{ items?: { html_url: string; repository: { full_name: string }; path: string }[] }>(
        `https://api.github.com/search/code?q=${encodeURIComponent('"' + d + '"')}&per_page=20`,
        { headers: { Authorization: `Bearer ${GH_TOKEN}`, Accept: 'application/vnd.github+json' } },
      );
      for (const it of data.items ?? []) {
        out.push({ source: 'GitHub público', severity: 'media', title: `${it.repository.full_name}/${it.path}`, detail: `Mención de ${d} en repositorio público`, url: it.html_url, date: null });
      }
    } catch (e) { logger.warn({ err: (e as Error).message, d }, 'darkweb: github search'); }
  }
  return out;
}

const sevRank = (s: Sev): number => (s === 'critica' ? 0 : s === 'alta' ? 1 : s === 'media' ? 2 : 3);

let cache: { at: number; data: DwRadar } | null = null;
const TTL = 5 * 60_000;

export async function getRadar(force = false): Promise<DwRadar> {
  if (!force && cache && Date.now() - cache.at < TTL) return cache.data;
  const fuentes: DwSource[] = [];
  const hallazgos: DwFinding[] = [];
  let credN = 0, rwN = 0, ghN = 0;

  // Credenciales / brechas (credexp → HIBP)
  try {
    const s = (await credSummary()) as { totalExpuestas?: number; cuentasCriticas?: number; topBrechas?: { title: string; cuentas: number }[]; dominios?: { ultimo_error?: string | null }[] };
    credN = s.totalExpuestas ?? 0;
    const err = (s.dominios ?? []).map((d) => d.ultimo_error).find(Boolean) ?? null;
    fuentes.push({ key: 'cred', label: 'Credenciales en brechas (HIBP)', estado: 'activo', nota: err ? `activo · aviso: ${String(err).slice(0, 70)}` : `${credN} cuenta(s) expuesta(s)` });
    for (const b of s.topBrechas ?? []) {
      hallazgos.push({ source: 'Credenciales', severity: b.cuentas >= 5 ? 'alta' : 'media', title: `${b.cuentas} cuenta(s) en ${b.title}`, detail: 'Credenciales corporativas en una brecha de datos pública', url: null, date: null });
    }
  } catch { fuentes.push({ key: 'cred', label: 'Credenciales en brechas (HIBP)', estado: 'requiere_config', nota: 'no disponible (revisar HIBP_API_KEY)' }); }

  // Sitios de extorsión / ransomware (ransomware.live)
  try {
    const o = await rwOverview(60);
    const dir = o.relevantes.filter((v) => v.relevance === 'directo');
    rwN = dir.length;
    fuentes.push({ key: 'ransomware', label: 'Sitios de extorsión (ransomware.live)', estado: 'activo', nota: rwN ? `${rwN} aparición(es) directa(s) del cliente` : 'sin aparición directa del cliente' });
    for (const v of dir) hallazgos.push({ source: 'Extorsión/Ransomware', severity: 'critica', title: `${v.group}: ${v.victim}`, detail: 'El cliente aparece publicado en un sitio de extorsión', url: v.url, date: v.published });
  } catch { fuentes.push({ key: 'ransomware', label: 'Sitios de extorsión', estado: 'requiere_config', nota: 'no disponible' }); }

  // GitHub público (latente sin token)
  if (GH_TOKEN) {
    const gh = await githubSearch();
    ghN = gh.length; hallazgos.push(...gh);
    fuentes.push({ key: 'github', label: 'Exposición en GitHub público', estado: 'activo', nota: `${ghN} mención(es) en repos públicos` });
  } else {
    fuentes.push({ key: 'github', label: 'Exposición en GitHub público', estado: 'requiere_config', nota: 'Configurar GITHUB_TOKEN (token de solo lectura) para activar la búsqueda de código' });
  }

  // Fuentes que requieren feed comercial (honestidad)
  fuentes.push({ key: 'pastes', label: 'Pastes y volcados públicos', estado: 'requiere_feed', nota: 'Las APIs gratuitas (p. ej. psbdmp) se descontinuaron; requiere un feed' });
  fuentes.push({ key: 'tor', label: 'Dark web profundo (mercados/foros Tor)', estado: 'requiere_feed', nota: 'Requiere un feed comercial de inteligencia (p. ej. Flare, IntelX)' });

  hallazgos.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const data: DwRadar = {
    generatedAt: new Date().toISOString(),
    kpis: { total: credN + rwN + ghN, credenciales: credN, ransomware: rwN, github: ghN },
    fuentes, hallazgos: hallazgos.slice(0, 100),
  };
  cache = { at: Date.now(), data };
  return data;
}

export function invalidateRadar(): void { cache = null; }
