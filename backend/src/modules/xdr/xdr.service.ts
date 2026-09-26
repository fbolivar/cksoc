/**
 * XDR — grafo de actividad cross-dominio (estilo SmartGrouping).
 * Enlaza alertas por ENTIDADES compartidas (IP, host, usuario, dominio) para
 * contar UNA historia en vez de N alertas sueltas:
 *   - getGroups(): agrupa alertas notables que comparten entidades (union-find)
 *     en "grupos de actividad" — señales dispersas unidas en un caso.
 *   - getGraph(seed): expande un nodo (entidad) y devuelve el grafo de entidades
 *     relacionadas + una línea de tiempo, para pivotear la investigación.
 * Todo en vivo sobre el Indexer (sin persistencia). Cross-dominio: red
 * (srcip/dstip), endpoint (agent), identidad (O365/Windows), DNS/SNI.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { HttpError } from '../auth/auth.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
export type EntType = 'ip' | 'host' | 'user' | 'domain';

interface Ent { id: string; type: EntType; label: string }
interface Src {
  '@timestamp'?: string;
  rule?: { description?: string; level?: number; id?: string; groups?: string[] };
  agent?: { name?: string };
  data?: {
    srcip?: string; dstip?: string; remip?: string; srcuser?: string; hostname?: string; dstname?: string;
    office365?: { UserId?: string; ClientIP?: string };
    win?: { eventdata?: { targetUserName?: string; subjectUserName?: string } };
    dns?: { question?: { name?: string } };
  };
}

function client() { return getIndexerClient(); }

const NOISE_HOST = /^(localhost|\-|unknown|n\/a)$/i;
function ent(type: EntType, val: unknown): Ent | null {
  const v = String(val ?? '').trim();
  if (!v || v === '-' || v === '::1' || v === '127.0.0.1' || NOISE_HOST.test(v)) return null;
  if (type === 'user' && (v.endsWith('$') || !/[a-z0-9]/i.test(v))) return null; // cuentas de máquina
  const label = type === 'domain' || type === 'user' ? v.toLowerCase() : v;
  return { id: `${type}:${label.toLowerCase()}`, type, label };
}

/** Extrae todas las entidades presentes en una alerta (cross-dominio). */
function entitiesOf(s: Src): Ent[] {
  const d = s.data ?? {};
  // En eventos O365 el agent.name es el colector (manager Wazuh), no un endpoint
  // real de la identidad → se omite como entidad host para no ensuciar el grafo.
  const hostName = d.office365 ? undefined : s.agent?.name;
  const raw = [
    ent('ip', d.srcip), ent('ip', d.dstip), ent('ip', d.remip), ent('ip', d.office365?.ClientIP),
    ent('host', hostName),
    ent('user', d.office365?.UserId), ent('user', d.win?.eventdata?.targetUserName), ent('user', d.srcuser),
    ent('domain', d.hostname), ent('domain', d.dstname), ent('domain', d.dns?.question?.name),
  ].filter((x): x is Ent => !!x);
  // users: solo UPN o nombres razonables (evita GUIDs/servicios)
  const seen = new Set<string>();
  const out: Ent[] = [];
  for (const e of raw) { if (!seen.has(e.id)) { seen.add(e.id); out.push(e); } }
  return out;
}

const SOURCE_FIELDS = [
  '@timestamp', 'rule.description', 'rule.level', 'rule.id', 'rule.groups', 'agent.name',
  'data.srcip', 'data.dstip', 'data.remip', 'data.srcuser', 'data.hostname', 'data.dstname',
  'data.office365.UserId', 'data.office365.ClientIP', 'data.win.eventdata.targetUserName', 'data.dns.question.name',
];

async function iocSet(): Promise<Set<string>> {
  try {
    const rows = await query<{ ioc_type: string; value: string }>("SELECT ioc_type, value FROM iocs WHERE enabled = TRUE AND ioc_type IN ('ip','domain')");
    return new Set(rows.map((r) => `${r.ioc_type === 'ip' ? 'ip' : 'domain'}:${r.value.toLowerCase()}`));
  } catch { return new Set(); }
}

// ==========================================================================
// SmartGrouping: grupos de actividad (alertas notables unidas por entidad)
// ==========================================================================
export interface ActivityGroup {
  id: string; alertas: number; reglas: number; maxLevel: number;
  desde: string; hasta: string;
  entidades: { type: EntType; label: string; ioc: boolean }[];
  tipos: EntType[];
  topReglas: { desc: string; count: number }[];
}

export async function getGroups(rangeIn = '24h', minLevel = 8): Promise<ActivityGroup[]> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const { data } = await client().post<{ hits: { hits: { _source: Src }[] } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 2500,
    query: { bool: { filter: [{ range: { '@timestamp': { gte: RANGE[range] } } }, { range: { 'rule.level': { gte: minLevel } } }] } },
    sort: [{ '@timestamp': { order: 'desc' } }],
    _source: SOURCE_FIELDS,
  });
  const hits = data.hits.hits.map((h) => h._source);

  // union-find sobre entidades
  const parent = new Map<string, string>();
  const find = (x: string): string => { let r = x; while (parent.get(r) && parent.get(r) !== r) r = parent.get(r)!; parent.set(x, r); return r; };
  const union = (a: string, b: string): void => { parent.set(find(a), find(b)); };
  const ensure = (x: string): void => { if (!parent.has(x)) parent.set(x, x); };

  interface AlertRec { ts: string; rule: string; level: number; ents: Ent[]; root?: string }
  const recs: AlertRec[] = [];
  for (const s of hits) {
    const ents = entitiesOf(s);
    if (!ents.length) continue;
    for (const e of ents) ensure(e.id);
    for (let i = 1; i < ents.length; i++) union(ents[0].id, ents[i].id);
    recs.push({ ts: s['@timestamp'] ?? '', rule: s.rule?.description ?? '', level: s.rule?.level ?? 0, ents });
  }
  // agrupa alertas por componente (raíz de su primera entidad)
  const groups = new Map<string, AlertRec[]>();
  for (const r of recs) { const root = find(r.ents[0].id); (groups.get(root) ?? groups.set(root, []).get(root)!).push(r); }

  const iocs = await iocSet();
  const out: ActivityGroup[] = [];
  for (const [root, members] of groups) {
    if (members.length < 2) continue; // un solo evento no es un "grupo"
    const entMap = new Map<string, { type: EntType; label: string; ioc: boolean }>();
    const ruleCount = new Map<string, number>();
    let maxLevel = 0; let desde = members[0].ts; let hasta = members[0].ts;
    for (const m of members) {
      maxLevel = Math.max(maxLevel, m.level);
      if (m.ts < desde) desde = m.ts; if (m.ts > hasta) hasta = m.ts;
      ruleCount.set(m.rule, (ruleCount.get(m.rule) ?? 0) + 1);
      for (const e of m.ents) if (!entMap.has(e.id)) entMap.set(e.id, { type: e.type, label: e.label, ioc: iocs.has(e.id) });
    }
    const entidades = [...entMap.values()];
    const tipos = [...new Set(entidades.map((e) => e.type))];
    // un grupo interesante cruza dominios o varias reglas
    if (tipos.length < 2 && ruleCount.size < 2) continue;
    out.push({
      id: root, alertas: members.length, reglas: ruleCount.size, maxLevel, desde, hasta,
      entidades: entidades.sort((a, b) => Number(b.ioc) - Number(a.ioc)).slice(0, 12),
      tipos,
      topReglas: [...ruleCount.entries()].map(([desc, count]) => ({ desc, count })).sort((a, b) => b.count - a.count).slice(0, 4),
    });
  }
  return out.sort((a, b) => b.maxLevel - a.maxLevel || b.alertas - a.alertas).slice(0, 30);
}

// ==========================================================================
// Grafo pivotable por entidad
// ==========================================================================
export interface GraphNode { id: string; type: EntType; label: string; alertas: number; maxLevel: number; ioc: boolean; seed: boolean }
export interface GraphEdge { from: string; to: string; weight: number }
export interface TimelineItem { ts: string; rule: string; level: number; entidades: string[] }
export interface ActivityGraph { seed: { type: EntType; value: string }; nodes: GraphNode[]; edges: GraphEdge[]; timeline: TimelineItem[]; stats: { alertas: number; byType: Record<string, number> } }

const SEED_FIELDS: Record<EntType, string[]> = {
  ip: ['data.srcip', 'data.dstip', 'data.remip', 'data.office365.ClientIP'],
  host: ['agent.name'],
  user: ['data.office365.UserId', 'data.win.eventdata.targetUserName', 'data.srcuser'],
  domain: ['data.hostname', 'data.dstname', 'data.dns.question.name'],
};

export async function getGraph(type: EntType, value: string, rangeIn = '7d'): Promise<ActivityGraph> {
  if (!SEED_FIELDS[type]) throw new HttpError(400, 'Tipo de entidad inválido');
  const v = String(value || '').trim();
  if (!v) throw new HttpError(400, 'Valor requerido');
  const range = RANGE[rangeIn] ? rangeIn : '7d';
  const should = SEED_FIELDS[type].map((f) => ({ term: { [f]: v } }));
  const { data } = await client().post<{ hits: { total: { value: number } | number; hits: { _source: Src }[] } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 1500,
    query: { bool: { filter: [{ range: { '@timestamp': { gte: RANGE[range] } } }], should, minimum_should_match: 1 } },
    sort: [{ '@timestamp': { order: 'desc' } }],
    _source: SOURCE_FIELDS,
  });
  const hits = data.hits.hits.map((h) => h._source);
  const seedId = `${type}:${v.toLowerCase()}`;

  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const timeline: TimelineItem[] = [];
  const iocs = await iocSet();

  for (const s of hits) {
    const ents = entitiesOf(s);
    if (!ents.some((e) => e.id === seedId)) {
      // el seed puede no re-extraerse si vino por un campo no mapeado; se fuerza
      ents.push({ id: seedId, type, label: v });
    }
    const level = s.rule?.level ?? 0;
    for (const e of ents) {
      const n = nodes.get(e.id);
      if (n) { n.alertas++; n.maxLevel = Math.max(n.maxLevel, level); }
      else nodes.set(e.id, { id: e.id, type: e.type, label: e.label, alertas: 1, maxLevel: level, ioc: iocs.has(e.id), seed: e.id === seedId });
    }
    // aristas entre entidades co-ocurrentes
    for (let i = 0; i < ents.length; i++) for (let j = i + 1; j < ents.length; j++) {
      const a = ents[i].id, b = ents[j].id;
      const key = a < b ? `${a}|${b}` : `${b}|${a}`;
      const e = edges.get(key);
      if (e) e.weight++; else edges.set(key, { from: a < b ? a : b, to: a < b ? b : a, weight: 1 });
    }
    if (timeline.length < 60) timeline.push({ ts: s['@timestamp'] ?? '', rule: s.rule?.description ?? '', level, entidades: ents.map((e) => e.label) });
  }

  // recorta a los nodos más relevantes (mantiene el seed) para legibilidad
  const TOP = 40;
  const kept = [...nodes.values()].sort((a, b) => Number(b.seed) - Number(a.seed) || b.alertas - a.alertas).slice(0, TOP);
  const keptIds = new Set(kept.map((n) => n.id));
  const keptEdges = [...edges.values()].filter((e) => keptIds.has(e.from) && keptIds.has(e.to)).sort((a, b) => b.weight - a.weight).slice(0, 200);
  const total = typeof data.hits.total === 'number' ? data.hits.total : data.hits.total.value;
  const byType: Record<string, number> = { ip: 0, host: 0, user: 0, domain: 0 };
  for (const n of kept) byType[n.type]++;
  return { seed: { type, value: v }, nodes: kept, edges: keptEdges, timeline, stats: { alertas: total, byType } };
}
