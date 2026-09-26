/**
 * Feeds públicos de Threat Intelligence (gratuitos, sin API key). Cubren IPs,
 * dominios, URLs y hashes, que cruzan contra los eventos de Wazuh/SonicWall/FIM.
 * Fuentes: familia abuse.ch (Feodo, SSLBL, URLhaus, ThreatFox, MalwareBazaar).
 */
import axios from 'axios';

export type FeedIocType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';
export interface TypedIoc { type: FeedIocType; value: string }

export interface FeedDef {
  name: string;
  /** URL de descarga (feeds de texto/CSV). Omitir si se usa `fetch`. */
  url?: string;
  /** Parseo de la descarga a IOCs tipados. Requerido junto con `url`. */
  parse?: (raw: string) => TypedIoc[];
  /** Recolector propio (para APIs con paginación/clave, p.ej. OTX). Alternativa a url+parse. */
  fetch?: () => Promise<TypedIoc[]>;
  /** Tope de indicadores a ingerir por corrida (acota tamaño/tiempo). */
  cap?: number;
  /** Confianza base (0-100) de los IOCs de este feed. */
  confidence?: number;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;
const SHA1 = /^[a-f0-9]{40}$/i;
const MD5 = /^[a-f0-9]{32}$/i;

const lines = (raw: string): string[] =>
  raw.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && !l.startsWith('//'));

/** Extrae el host de una URL para derivar un IOC de dominio. */
function hostOf(url: string): string | null {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return DOMAIN.test(h) ? h : null;
  } catch { return null; }
}

/** Parseo tolerante de una línea CSV con campos entre comillas (sep. `","` o `", "`). */
function csvCols(line: string): string[] {
  return line.replace(/^"|"$/g, '').split(/",\s*"/).map((c) => c.trim());
}

export const FEEDS: FeedDef[] = [
  {
    name: 'abuse.ch Feodo Tracker',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    confidence: 90,
    parse: (raw) => lines(raw).filter((l) => IPV4.test(l)).map((v) => ({ type: 'ip', value: v })),
  },
  {
    name: 'abuse.ch SSLBL',
    url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    confidence: 85,
    parse: (raw) => lines(raw).map((l) => l.split(',')[0].trim()).filter((l) => IPV4.test(l)).map((v) => ({ type: 'ip', value: v })),
  },
  {
    name: 'blocklist.de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    cap: 40000,
    confidence: 65,
    parse: (raw) => lines(raw).filter((l) => IPV4.test(l)).map((v) => ({ type: 'ip', value: v })),
  },
  {
    name: 'abuse.ch URLhaus',
    url: 'https://urlhaus.abuse.ch/downloads/text_online/',
    cap: 6000,
    confidence: 80,
    parse: (raw) => {
      const out: TypedIoc[] = [];
      for (const l of lines(raw)) {
        if (!/^https?:\/\//i.test(l)) continue;
        out.push({ type: 'url', value: l });
        const h = hostOf(l);
        if (h) out.push({ type: 'domain', value: h });
      }
      return out;
    },
  },
  {
    name: 'abuse.ch ThreatFox',
    url: 'https://threatfox.abuse.ch/export/csv/recent/',
    cap: 8000,
    confidence: 80,
    parse: (raw) => {
      const out: TypedIoc[] = [];
      for (const l of lines(raw)) {
        const c = csvCols(l);
        if (c.length < 4) continue;
        const rawVal = c[2];
        const kind = c[3];
        if (!rawVal) continue;
        if (kind === 'ip:port') { const ip = rawVal.split(':')[0]; if (IPV4.test(ip)) out.push({ type: 'ip', value: ip }); }
        else if (kind === 'domain' && DOMAIN.test(rawVal)) out.push({ type: 'domain', value: rawVal.toLowerCase() });
        else if (kind === 'url' && /^https?:\/\//i.test(rawVal)) out.push({ type: 'url', value: rawVal });
        else if (kind === 'md5_hash' && MD5.test(rawVal)) out.push({ type: 'md5', value: rawVal.toLowerCase() });
        else if (kind === 'sha256_hash' && SHA256.test(rawVal)) out.push({ type: 'sha256', value: rawVal.toLowerCase() });
      }
      return out;
    },
  },
  {
    name: 'abuse.ch MalwareBazaar',
    url: 'https://bazaar.abuse.ch/export/txt/sha256/recent/',
    cap: 6000,
    confidence: 85,
    parse: (raw) => lines(raw).filter((l) => SHA256.test(l)).map((v) => ({ type: 'sha256', value: v.toLowerCase() })),
  },
];

// --------------------------------------------------------------------------
// AlienVault OTX (API con clave). Aporta IOCs de "pulses" de la comunidad —
// campañas y APTs dirigidas que los feeds de abuse.ch/blocklist no traen.
// Se activa solo si OTX_API_KEY está en el entorno.
// --------------------------------------------------------------------------
const OTX_KEY = process.env.OTX_API_KEY || '';
const OTX_BASE = process.env.OTX_BASE_URL || 'https://otx.alienvault.com';
const OTX_CAP = Number(process.env.OTX_CAP || 20000);
const OTX_MAX_PAGES = Number(process.env.OTX_MAX_PAGES || 40);

/** Mapea el tipo de indicador de OTX a nuestro tipo (o null si no aplica/ inválido). */
function mapOtx(type: string, value: string): TypedIoc | null {
  const v = String(value || '').trim();
  switch (type) {
    case 'IPv4': return IPV4.test(v) ? { type: 'ip', value: v } : null;
    case 'domain':
    case 'hostname': return DOMAIN.test(v) ? { type: 'domain', value: v.toLowerCase() } : null;
    case 'URL':
    case 'URI': return /^https?:\/\//i.test(v) ? { type: 'url', value: v } : null;
    case 'FileHash-MD5': return MD5.test(v) ? { type: 'md5', value: v.toLowerCase() } : null;
    case 'FileHash-SHA1': return SHA1.test(v) ? { type: 'sha1', value: v.toLowerCase() } : null;
    case 'FileHash-SHA256': return SHA256.test(v) ? { type: 'sha256', value: v.toLowerCase() } : null;
    default: return null; // CIDR, email, CVE, Mutex, YARA, etc. → se ignoran
  }
}

interface OtxPulse { indicators?: { indicator: string; type: string }[] }
interface OtxPage { results?: OtxPulse[]; next?: string | null }

/** Recorre los pulses suscritos paginando y extrae indicadores hasta el tope. */
async function fetchOtx(): Promise<TypedIoc[]> {
  if (!OTX_KEY) throw new Error('OTX_API_KEY no configurada');
  const out: TypedIoc[] = [];
  for (let page = 1; page <= OTX_MAX_PAGES && out.length < OTX_CAP; page++) {
    const { data } = await axios.get<OtxPage>(`${OTX_BASE}/api/v1/pulses/subscribed`, {
      params: { limit: 50, page },
      timeout: 30_000,
      headers: { 'X-OTX-API-KEY': OTX_KEY, 'User-Agent': 'HexWatch-ThreatIntel/1.0' },
    });
    const results = data.results ?? [];
    if (results.length === 0) break;
    for (const pulse of results) {
      for (const ind of pulse.indicators ?? []) {
        const m = mapOtx(ind.type, ind.indicator);
        if (m) out.push(m);
        if (out.length >= OTX_CAP) break;
      }
      if (out.length >= OTX_CAP) break;
    }
    if (!data.next) break;
  }
  return out;
}

if (OTX_KEY) {
  FEEDS.push({ name: 'AlienVault OTX', fetch: fetchOtx, cap: OTX_CAP, confidence: 75 });
}

// --------------------------------------------------------------------------
// MISP (instancia propia / compartida). Se activa con MISP_URL + MISP_API_KEY.
// Trae atributos to_ids=true (accionables), respetando la warninglist de MISP.
// --------------------------------------------------------------------------
const MISP_URL = (process.env.MISP_URL || '').replace(/\/+$/, '');
const MISP_KEY = process.env.MISP_API_KEY || '';
const MISP_CAP = Number(process.env.MISP_CAP || 20000);
const MISP_TAGS = (process.env.MISP_TAGS || '').split(',').map((s) => s.trim()).filter(Boolean);
const MISP_LAST = process.env.MISP_LAST || '30d';

function mapMisp(type: string, value: string): TypedIoc | null {
  const v = String(value || '').trim();
  switch (type) {
    case 'ip-src': case 'ip-dst': case 'ip': { const ip = v.split('|')[0].split(':')[0]; return IPV4.test(ip) ? { type: 'ip', value: ip } : null; }
    case 'domain': case 'hostname': { const d = v.split('|')[0]; return DOMAIN.test(d) ? { type: 'domain', value: d.toLowerCase() } : null; }
    case 'url': case 'uri': return /^https?:\/\//i.test(v) ? { type: 'url', value: v } : null;
    case 'md5': return MD5.test(v) ? { type: 'md5', value: v.toLowerCase() } : null;
    case 'sha1': return SHA1.test(v) ? { type: 'sha1', value: v.toLowerCase() } : null;
    case 'sha256': return SHA256.test(v) ? { type: 'sha256', value: v.toLowerCase() } : null;
    default: return null;
  }
}

interface MispResp { response?: { Attribute?: { type: string; value: string }[] } }
async function fetchMisp(): Promise<TypedIoc[]> {
  if (!MISP_URL || !MISP_KEY) throw new Error('MISP_URL/MISP_API_KEY no configurados');
  const body: Record<string, unknown> = {
    returnFormat: 'json',
    type: ['ip-src', 'ip-dst', 'domain', 'hostname', 'url', 'md5', 'sha1', 'sha256'],
    to_ids: true, enforceWarninglist: true, limit: MISP_CAP, last: MISP_LAST,
  };
  if (MISP_TAGS.length) body.tags = MISP_TAGS;
  const { data } = await axios.post<MispResp>(`${MISP_URL}/attributes/restSearch`, body, {
    timeout: 60_000,
    headers: { Authorization: MISP_KEY, Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'HexWatch-ThreatIntel/1.0' },
  });
  const attrs = data?.response?.Attribute ?? [];
  const out: TypedIoc[] = [];
  for (const a of attrs) { const m = mapMisp(a.type, a.value); if (m) out.push(m); if (out.length >= MISP_CAP) break; }
  return out;
}
if (MISP_URL && MISP_KEY) FEEDS.push({ name: 'MISP', fetch: fetchMisp, cap: MISP_CAP, confidence: 85 });

// --------------------------------------------------------------------------
// STIX 2.x — parser de indicadores compartido por TAXII y por el import manual.
// Extrae de los patrones STIX: ipv4-addr / domain-name / url / file:hashes.
// --------------------------------------------------------------------------
export function parseStixIndicators(objects: unknown[]): TypedIoc[] {
  const out: TypedIoc[] = [];
  for (const raw of objects) {
    const o = raw as { type?: string; pattern?: string } | null;
    if (!o || o.type !== 'indicator' || typeof o.pattern !== 'string') continue;
    const p = o.pattern;
    for (const m of p.matchAll(/ipv4-addr:value\s*=\s*'([^']+)'/g)) if (IPV4.test(m[1])) out.push({ type: 'ip', value: m[1] });
    for (const m of p.matchAll(/domain-name:value\s*=\s*'([^']+)'/g)) if (DOMAIN.test(m[1])) out.push({ type: 'domain', value: m[1].toLowerCase() });
    for (const m of p.matchAll(/url:value\s*=\s*'([^']+)'/g)) if (/^https?:\/\//i.test(m[1])) out.push({ type: 'url', value: m[1] });
    for (const m of p.matchAll(/hashes\.(?:'?SHA-?256'?|"SHA-256")\s*=\s*'([a-f0-9]{64})'/gi)) out.push({ type: 'sha256', value: m[1].toLowerCase() });
    for (const m of p.matchAll(/hashes\.(?:'?SHA-?1'?|"SHA-1")\s*=\s*'([a-f0-9]{40})'/gi)) out.push({ type: 'sha1', value: m[1].toLowerCase() });
    for (const m of p.matchAll(/hashes\.(?:'?MD5'?|"MD5")\s*=\s*'([a-f0-9]{32})'/gi)) out.push({ type: 'md5', value: m[1].toLowerCase() });
  }
  return out;
}

/** Normaliza la entrada (bundle STIX, envelope TAXII, array o indicador suelto) a lista de objetos. */
export function extractStixObjects(json: unknown): unknown[] {
  if (Array.isArray(json)) return json;
  if (json && typeof json === 'object') {
    const o = json as { objects?: unknown[]; type?: string };
    if (Array.isArray(o.objects)) return o.objects;
    if (o.type === 'indicator') return [o];
  }
  return [];
}

// --------------------------------------------------------------------------
// TAXII 2.1 — poll de una colección de objetos STIX. Se activa con TAXII_URL
// (URL completa .../collections/<id>/objects/). Auth por Bearer o Basic.
// --------------------------------------------------------------------------
const TAXII_URL = (process.env.TAXII_URL || '').trim();
const TAXII_TOKEN = process.env.TAXII_TOKEN || '';
const TAXII_USER = process.env.TAXII_USER || '';
const TAXII_PASS = process.env.TAXII_PASS || '';
const TAXII_CAP = Number(process.env.TAXII_CAP || 20000);

async function fetchTaxii(): Promise<TypedIoc[]> {
  if (!TAXII_URL) throw new Error('TAXII_URL no configurada');
  const headers: Record<string, string> = {
    Accept: 'application/taxii+json;version=2.1, application/stix+json;version=2.1, application/json',
    'User-Agent': 'HexWatch-ThreatIntel/1.0',
  };
  if (TAXII_TOKEN) headers.Authorization = `Bearer ${TAXII_TOKEN}`;
  const auth = (!TAXII_TOKEN && TAXII_USER) ? { username: TAXII_USER, password: TAXII_PASS } : undefined;
  const { data } = await axios.get<unknown>(TAXII_URL, { timeout: 60_000, headers, auth, params: { limit: TAXII_CAP } });
  return parseStixIndicators(extractStixObjects(data)).slice(0, TAXII_CAP);
}
if (TAXII_URL) FEEDS.push({ name: 'TAXII', fetch: fetchTaxii, cap: TAXII_CAP, confidence: 80 });

/** Descarga un feed y devuelve los indicadores tipados únicos (aplicando el tope). */
export async function fetchFeed(def: FeedDef): Promise<TypedIoc[]> {
  let items: TypedIoc[];
  if (def.fetch) {
    items = await def.fetch();
  } else {
    const { data } = await axios.get<string>(def.url as string, {
      timeout: 30_000,
      responseType: 'text',
      headers: { 'User-Agent': 'HexWatch-ThreatIntel/1.0' },
    });
    items = def.parse ? def.parse(String(data)) : [];
  }
  const seen = new Set<string>();
  const out: TypedIoc[] = [];
  for (const it of items) {
    const k = `${it.type}|${it.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(it);
    if (def.cap && out.length >= def.cap) break;
  }
  return out;
}
