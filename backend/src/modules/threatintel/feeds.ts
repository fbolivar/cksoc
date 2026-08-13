/**
 * Feeds públicos de Threat Intelligence (gratuitos, sin API key). Se centran en
 * IPs, que son las que cruzan directamente contra los eventos de red (Wazuh +
 * FortiGate). El catálogo es ampliable.
 */
import axios from 'axios';

export interface FeedDef {
  name: string;
  type: 'ip' | 'domain' | 'url';
  url: string;
  parse: (raw: string) => string[];
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const lines = (raw: string): string[] =>
  raw.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && !l.startsWith('//'));

export const FEEDS: FeedDef[] = [
  {
    name: 'abuse.ch Feodo Tracker',
    type: 'ip',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    parse: (raw) => lines(raw).filter((l) => IPV4.test(l)),
  },
  {
    name: 'abuse.ch SSLBL',
    type: 'ip',
    url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    // CSV-ish: la primera columna que sea IP.
    parse: (raw) => lines(raw).map((l) => l.split(',')[0].trim()).filter((l) => IPV4.test(l)),
  },
];

/** Descarga un feed y devuelve los indicadores únicos. */
export async function fetchFeed(def: FeedDef): Promise<string[]> {
  const { data } = await axios.get<string>(def.url, {
    timeout: 20_000,
    responseType: 'text',
    headers: { 'User-Agent': 'HexWatch-ThreatIntel/1.0' },
  });
  return Array.from(new Set(def.parse(String(data))));
}
