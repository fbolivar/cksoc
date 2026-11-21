/**
 * Dossier de Incidente con IA — convierte un grupo de actividad (entidad semilla
 * o incidente) en un expediente auto-escrito: narrativa forense, causa raiz,
 * linea de tiempo REAL, MITRE y acciones recomendadas con 1-clic.
 *
 * Combina DATOS REALES (grafo XDR cross-dominio: entidades, timeline, IOCs, geo)
 * con la SINTESIS de Claude (historia, causa raiz, confianza, MITRE, acciones).
 * No se inventan entidades ni tiempos: el timeline y las entidades salen del grafo.
 */
import { randomUUID } from 'node:crypto';
import { query } from '../../config/db';
import { getGraph, type EntType, type ActivityGraph } from '../xdr/xdr.service';
import { getIncident } from '../incidents/incidents.service';
import { completarPrompt, isConfigured } from '../copilot/copilot.service';
import { geolocate, isPublicIP, type GeoLocation } from '../geo/geoip.service';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';

export type ActionType = 'block_ip' | 'isolate_host' | 'force_mfa' | 'suppress_rule' | 'create_incident' | 'investigate';
export interface DossierAction { tipo: ActionType; objetivo: string; motivo: string; prioridad: number }
export interface DossierEntity { tipo: EntType; valor: string; rol: string; ioc: boolean }
export interface DossierTimeline { ts: string; evento: string; nivel: number; entidades: string[] }
export type Sev = 'critica' | 'alta' | 'media' | 'baja';
export type Conf = 'alta' | 'media' | 'baja';

export interface Dossier {
  id: string;
  generadoEn: string;
  seed: { type: EntType; value: string };
  incidentId: string | null;
  titulo: string;
  resumen: string;
  historia: string;
  severidad: Sev;
  confianza: Conf;
  causaRaiz: string;
  mitre: { id: string; nombre?: string }[];
  entidades: DossierEntity[];
  lineaTiempo: DossierTimeline[];
  acciones: DossierAction[];
  stats: { alertas: number; byType: Record<string, number> };
  geo: { ip: string; pais: string; ciudad: string } | null;
  modelo: string;
}

let schemaReady = false;
export async function ensureDossierSchema(): Promise<void> {
  if (schemaReady) return;
  await query(`CREATE TABLE IF NOT EXISTS incident_dossiers (
    id uuid PRIMARY KEY,
    seed_type text NOT NULL,
    seed_value text NOT NULL,
    incident_id text,
    data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await query(`CREATE INDEX IF NOT EXISTS idx_dossier_seed ON incident_dossiers (seed_type, seed_value, created_at DESC)`);
  schemaReady = true;
}

const VALID_TYPES: EntType[] = ['ip', 'host', 'user', 'domain'];
const ACTIONS: ActionType[] = ['block_ip', 'isolate_host', 'force_mfa', 'suppress_rule', 'create_incident', 'investigate'];
const CACHE_MIN = 30;

type AnyObj = Record<string, unknown>;
function asArr(v: unknown): AnyObj[] { return Array.isArray(v) ? (v as AnyObj[]) : []; }
function str(v: unknown, fallback = ''): string { return v == null ? fallback : String(v); }

function parseJson(raw: string): AnyObj | null {
  let t = raw.trim().replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
  const a = t.indexOf('{'); const b = t.lastIndexOf('}');
  if (a < 0 || b <= a) return null;
  try { return JSON.parse(t.slice(a, b + 1)) as AnyObj; } catch { return null; }
}

const SYSTEM = `Eres el analista forense senior de HexWatch (SOC on-premise: Wazuh + SonicWall + Velociraptor + O365). A partir del CONTEXTO REAL (grafo de actividad cross-dominio con entidades, IOCs y linea de tiempo) construyes un DOSSIER DE INCIDENTE para un analista.

Reglas:
- NO inventes IPs, hosts, usuarios, dominios ni reglas: usa SOLO lo que aparece en el contexto.
- Responde UNICAMENTE con un objeto JSON valido, sin markdown ni texto fuera del JSON.
- Si el contexto parece ruido benigno, dilo en "resumen", pon severidad "baja" y pocas acciones.

Forma EXACTA del JSON:
{
 "titulo": "titular corto del incidente",
 "resumen": "2-3 frases: que paso y por que importa",
 "historia": "narrativa forense en markdown (como se desarrollo, que conecta a las entidades, impacto potencial)",
 "severidad": "critica|alta|media|baja",
 "confianza": "alta|media|baja",
 "causaRaiz": "1-2 frases",
 "mitre": [{"id":"Txxxx","nombre":"tecnica"}],
 "entidades": [{"valor":"<entidad del contexto>","tipo":"ip|host|user|domain","rol":"atacante|victima|pivote|afectado"}],
 "acciones": [{"tipo":"block_ip|isolate_host|force_mfa|suppress_rule|create_incident|investigate","objetivo":"<entidad del contexto>","motivo":"por que","prioridad":1}]
}
Acciones: prioriza contencion; usa SOLO esos tipos; "objetivo" debe ser una entidad del contexto (IP para block_ip, host para isolate_host, usuario para force_mfa).`;

function buildContext(graph: ActivityGraph, geo: GeoLocation | null): string {
  const ents = graph.nodes
    .map((n) => `- ${n.type}:${n.label}${n.ioc ? ' [IOC conocido]' : ''}${n.seed ? ' [semilla]' : ''} -> ${n.alertas} alerta(s), nivel max ${n.maxLevel}`)
    .join('\n');
  const tl = graph.timeline.slice(0, 40)
    .map((t) => `- ${t.ts} | nivel ${t.level} | ${t.rule} | [${t.entidades.join(', ')}]`)
    .join('\n');
  const byType = Object.entries(graph.stats.byType).map(([k, v]) => `${k}:${v}`).join(', ');
  return [
    `SEMILLA: ${graph.seed.type} = ${graph.seed.value}`,
    geo ? `GEO de la semilla: ${geo.city ? geo.city + ', ' : ''}${geo.country}` : '',
    `TOTAL alertas en el grupo: ${graph.stats.alertas} (por tipo de entidad: ${byType})`,
    '',
    `ENTIDADES INVOLUCRADAS:\n${ents || '(ninguna)'}`,
    '',
    `LINEA DE TIEMPO (mas reciente arriba):\n${tl || '(sin eventos)'}`,
  ].filter(Boolean).join('\n');
}

export async function generateDossier(
  input: { type: EntType; value: string; range?: string; incidentId?: string | null },
  opts: { force?: boolean } = {},
): Promise<Dossier> {
  const type = input.type;
  if (!VALID_TYPES.includes(type)) throw new HttpError(400, 'Tipo de entidad invalido (ip|host|user|domain).');
  const value = String(input.value || '').trim();
  if (!value) throw new HttpError(400, 'Falta la entidad semilla.');
  await ensureDossierSchema();

  if (!opts.force) {
    const cached = await query<{ data: Dossier }>(
      `SELECT data FROM incident_dossiers WHERE seed_type=$1 AND seed_value=$2 AND created_at > now() - interval '${CACHE_MIN} minutes' ORDER BY created_at DESC LIMIT 1`,
      [type, value],
    ).catch(() => [] as { data: Dossier }[]);
    if (cached[0]?.data) return cached[0].data;
  }

  if (!isConfigured()) throw new HttpError(503, 'El dossier con IA requiere ANTHROPIC_API_KEY (copiloto no configurado).');

  const graph = await getGraph(type, value, input.range ?? '7d');
  const geo = type === 'ip' && isPublicIP(value) ? geolocate(value) : null;
  const ctx = buildContext(graph, geo);

  let ai: AnyObj | null = null;
  try {
    const raw = await completarPrompt(SYSTEM, ctx, 3000);
    ai = parseJson(raw);
    if (!ai) logger.warn('dossier: respuesta de Claude no es JSON parseable');
  } catch (err) {
    if (err instanceof HttpError) throw err;
    logger.warn({ err }, 'dossier: fallo al generar con IA');
    throw new HttpError(502, 'No se pudo generar el dossier con IA.');
  }

  const rolByEnt = new Map<string, string>();
  for (const e of asArr(ai?.entidades)) {
    if (e.valor) rolByEnt.set(str(e.valor).toLowerCase(), str(e.rol));
  }
  const entidades: DossierEntity[] = graph.nodes.slice(0, 20).map((n) => ({
    tipo: n.type,
    valor: n.label,
    ioc: n.ioc,
    rol: rolByEnt.get(n.label.toLowerCase()) || (n.seed ? 'foco' : n.ioc ? 'malicioso' : 'relacionado'),
  }));

  const lineaTiempo: DossierTimeline[] = graph.timeline.slice(0, 50).map((t) => ({
    ts: t.ts, evento: t.rule, nivel: t.level, entidades: t.entidades,
  }));

  const entValid = new Set(entidades.map((e) => e.valor.toLowerCase()));
  const acciones: DossierAction[] = asArr(ai?.acciones)
    .filter((a) => ACTIONS.includes(a.tipo as ActionType))
    .map((a) => ({ tipo: a.tipo as ActionType, objetivo: str(a.objetivo), motivo: str(a.motivo), prioridad: Number(a.prioridad) || 5 }))
    .filter((a) => a.objetivo && (entValid.has(a.objetivo.toLowerCase()) || a.tipo === 'create_incident' || a.tipo === 'investigate'))
    .sort((a, b) => a.prioridad - b.prioridad)
    .slice(0, 8);

  const sev: Sev = (['critica', 'alta', 'media', 'baja'] as Sev[]).includes(ai?.severidad as Sev) ? (ai!.severidad as Sev) : 'media';
  const conf: Conf = (['alta', 'media', 'baja'] as Conf[]).includes(ai?.confianza as Conf) ? (ai!.confianza as Conf) : 'media';
  const mitre = asArr(ai?.mitre).filter((m) => m.id).map((m) => ({ id: str(m.id), nombre: m.nombre ? str(m.nombre) : undefined })).slice(0, 12);

  const dossier: Dossier = {
    id: randomUUID(),
    generadoEn: new Date().toISOString(),
    seed: { type, value },
    incidentId: input.incidentId ?? null,
    titulo: str(ai?.titulo, `Actividad en ${type} ${value}`).slice(0, 160),
    resumen: str(ai?.resumen).slice(0, 1200),
    historia: str(ai?.historia, ai ? '' : '(No se pudo sintetizar la narrativa de IA.)').slice(0, 8000),
    severidad: sev,
    confianza: conf,
    causaRaiz: str(ai?.causaRaiz).slice(0, 1000),
    mitre,
    entidades,
    lineaTiempo,
    acciones,
    stats: graph.stats,
    geo: geo ? { ip: value, pais: geo.country, ciudad: geo.city } : null,
    modelo: env.ANTHROPIC_MODEL,
  };

  await query(
    `INSERT INTO incident_dossiers (id, seed_type, seed_value, incident_id, data) VALUES ($1,$2,$3,$4,$5)`,
    [dossier.id, type, value, dossier.incidentId, JSON.stringify(dossier)],
  ).catch((err) => logger.warn({ err }, 'dossier: no se pudo persistir'));

  return dossier;
}

export async function generateForIncident(incidentId: string, opts: { force?: boolean } = {}): Promise<Dossier> {
  const inc = await getIncident(incidentId);
  if (!inc) throw new HttpError(404, 'Incidente no encontrado.');
  const src = inc.source || {};
  let seed: { type: EntType; value: string } | null = null;
  if (src.ip) seed = { type: 'ip', value: src.ip };
  else if (src.agent) seed = { type: 'host', value: src.agent };
  if (!seed) throw new HttpError(422, 'El incidente no tiene IP ni host de origen para construir el dossier.');
  return generateDossier({ ...seed, incidentId }, opts);
}

export async function listRecentDossiers(limit = 20): Promise<Dossier[]> {
  await ensureDossierSchema();
  const rows = await query<{ data: Dossier }>(
    `SELECT DISTINCT ON (seed_type, seed_value) data FROM incident_dossiers ORDER BY seed_type, seed_value, created_at DESC`,
  ).catch(() => [] as { data: Dossier }[]);
  return rows.map((r) => r.data).sort((a, b) => (b.generadoEn > a.generadoEn ? 1 : -1)).slice(0, limit);
}
