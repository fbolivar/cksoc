/**
 * Feeds públicos de Threat Intelligence (gratuitos, sin API key). Cubren IPs,
 * dominios, URLs y hashes, que cruzan contra los eventos de Wazuh/FortiGate/FIM.
 * Fuentes: familia abuse.ch (Feodo, SSLBL, URLhaus, ThreatFox, MalwareBazaar).
 */
import axios from 'axios';

export type FeedIocType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';
export interface TypedIoc { type: FeedIocType; value: string }

export interface FeedDef {
  name: string;
  url: string;
  parse: (raw: string) => TypedIoc[];
  /** Tope de indicadores a ingerir por corrida (acota tamaño/tiempo). */
  cap?: number;
  /** Confianza base (0-100) de los IOCs de este feed. */
  confidence?: number;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;
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

/** Descarga un feed y devuelve los indicadores tipados únicos (aplicando el tope). */
export async function fetchFeed(def: FeedDef): Promise<TypedIoc[]> {
  const { data } = await axios.get<string>(def.url, {
    timeout: 30_000,
    responseType: 'text',
    headers: { 'User-Agent': 'HexWatch-ThreatIntel/1.0' },
  });
  const seen = new Set<string>();
  const out: TypedIoc[] = [];
  for (const it of def.parse(String(data))) {
    const k = `${it.type}|${it.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(it);
    if (def.cap && out.length >= def.cap) break;
  }
  return out;
}
