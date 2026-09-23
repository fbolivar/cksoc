/**
 * Copiloto IA — asistente de análisis para HexWatch, sobre la API de Claude
 * (Anthropic). Responde en español, con el tono de un analista SOC senior, y se
 * apoya en un "snapshot" en vivo del SOC (alertas, incidentes, anomalías UEBA)
 * que se inyecta como contexto para que no invente.
 *
 * PRIVACIDAD: al invocar el copiloto se envía ese contexto a la API de Anthropic
 * (nube). Si no hay ANTHROPIC_API_KEY, el módulo no llama afuera y avisa.
 */
import axios from 'axios';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { listAnomalies } from '../ueba/ueba.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';

export interface ChatMessage { role: 'user' | 'assistant'; content: string }

export function isConfigured(): boolean {
  return Boolean(env.ANTHROPIC_API_KEY);
}

const SYSTEM_BASE = `Eres el copiloto de seguridad de HexWatch, una plataforma SOC on-premise construida sobre Wazuh, SonicWall y Velociraptor. Asistes a analistas de un SOC en Colombia.

Reglas:
- Responde SIEMPRE en español, claro y conciso, con tono de analista SOC senior.
- NO inventes IPs, hosts, reglas ni cifras: usa solo los datos que se te entregan.
- Cuando recomiendes acciones, sé concreto y prioriza (contención, investigación, siguiente paso), acorde a las capacidades de HexWatch (bloqueo en SonicWall, aislamiento con Velociraptor, supresión de falsos positivos, crear incidente).
- No ejecutas acciones tú mismo: propones. El analista decide y actúa en la plataforma.
- Formatea con listas y **negritas** cuando ayude a la legibilidad.`;

// Nota que solo se añade en el chat (que sí expone herramientas).
const TOOLS_NOTE = `Tienes HERRAMIENTAS para consultar datos en vivo del SOC (buscar_alertas, top_vulnerabilidades, anomalias_ueba, incidentes_abiertos, reputacion_ip). Úsalas cuando necesites datos concretos en vez de suponer; puedes encadenar varias. Si una herramienta no devuelve datos, dilo.`;

// --- Cliente Anthropic (REST directo, sin SDK) ---
interface ContentBlock { type: string; text?: string; id?: string; name?: string; input?: Record<string, unknown>; }
interface ClaudeResponse { content: ContentBlock[]; stop_reason: string | null; }
type AnyMessage = { role: 'user' | 'assistant'; content: string | unknown[] };

async function callClaudeRaw(system: string, messages: AnyMessage[], tools?: unknown[], maxTokens?: number): Promise<ClaudeResponse> {
  if (!env.ANTHROPIC_API_KEY) {
    throw new HttpError(503, 'El copiloto no está configurado (falta ANTHROPIC_API_KEY).');
  }
  try {
    const body: Record<string, unknown> = {
      model: env.ANTHROPIC_MODEL,
      max_tokens: maxTokens ?? env.COPILOT_MAX_TOKENS,
      system,
      messages,
    };
    if (tools && tools.length) body.tools = tools;
    const { data } = await axios.post(`${env.ANTHROPIC_BASE_URL.replace(/\/$/, '')}/v1/messages`, body, {
      headers: {
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      timeout: 60000,
    });
    return { content: data?.content ?? [], stop_reason: data?.stop_reason ?? null };
  } catch (err) {
    if (axios.isAxiosError(err)) {
      const status = err.response?.status;
      const apiMsg = (err.response?.data as { error?: { message?: string } } | undefined)?.error?.message;
      logger.warn({ status, apiMsg, err: err.message }, 'Copiloto: fallo llamando a Anthropic');
      if (status === 401) throw new HttpError(502, 'La API key de Claude fue rechazada (401). Revisa ANTHROPIC_API_KEY.');
      if (status === 429) throw new HttpError(429, 'Límite de tasa de la API de Claude alcanzado. Intenta de nuevo en un momento.');
      if (status === 400) throw new HttpError(502, `La API de Claude rechazó la solicitud: ${apiMsg ?? 'petición inválida'}.`);
      throw new HttpError(502, `No se pudo contactar la API de Claude: ${apiMsg ?? err.message}.`);
    }
    throw err;
  }
}

function textOf(content: ContentBlock[]): string {
  return content.filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim();
}

/** Llamada simple sin herramientas (explicar, triaje). */
async function callClaude(system: string, messages: ChatMessage[], maxTokens?: number): Promise<string> {
  const res = await callClaudeRaw(system, messages, undefined, maxTokens);
  return textOf(res.content) || '(respuesta vacía del modelo)';
}

// Exclusión de ruido benigno estándar (misma que dashboards/reportes): para que
// el copiloto razone sobre SEÑAL real y no sobre auditoría de comandos, checksums
// FIM ni el tráfico del propio SOC. Se puede desactivar (investigación de FP).
function ruidoMustNot(): unknown[] {
  const envIds = (env.REPORT_EXCLUDE_RULES || '').split(',').map((s) => s.trim()).filter(Boolean);
  const noiseRuleIds = ['81633', '80792', '550', '752', '91578', ...envIds];
  return [
    { terms: { 'rule.id': noiseRuleIds } },
    { terms: { 'rule.groups': ['sca', 'vulnerability-detector'] } },
    {
      bool: {
        filter: [
          { term: { 'rule.id': '100600' } },
          {
            bool: {
              should: [
                { prefix: { 'data.dstip': '192.168.' } },
                { prefix: { 'data.dstip': '10.' } },
                { prefix: { 'data.dstip': '172.' } },
                { terms: { 'data.dstip': ['40.160.225.24', '209.250.254.15'] } },
                { term: { 'data.srcip': '192.168.0.31' } },
              ],
              minimum_should_match: 1,
            },
          },
        ],
      },
    },
  ];
}

// --- Herramientas (tool-use): consultan datos en vivo del SOC ---
const TOOLS = [
  { name: 'buscar_alertas', description: 'Busca alertas recientes en el SIEM. Por defecto EXCLUYE el ruido benigno conocido (auditoría de comandos, checksums FIM, tráfico del propio SOC) para mostrar señal real. Para investigar falsos positivos o ver ese ruido, pasa incluir_ruido=true.', input_schema: { type: 'object', properties: { horas: { type: 'integer', description: 'ventana hacia atrás (default 24)' }, min_nivel: { type: 'integer', description: 'nivel mínimo de regla Wazuh (default 7)' }, texto: { type: 'string', description: 'texto a buscar en descripción/log (opcional)' }, limite: { type: 'integer', description: 'máx. resultados (default 10)' }, incluir_ruido: { type: 'boolean', description: 'incluir el ruido benigno excluido por defecto (para investigar FP). Default false.' } } } },
  { name: 'top_vulnerabilidades', description: 'Vulnerabilidades priorizadas por riesgo real (CVSS + CISA KEV + EPSS).', input_schema: { type: 'object', properties: {} } },
  { name: 'anomalias_ueba', description: 'Anomalías de comportamiento de usuarios abiertas (viaje imposible, host nuevo, fuera de horario, pico de fallos).', input_schema: { type: 'object', properties: {} } },
  { name: 'incidentes_abiertos', description: 'Incidentes/casos abiertos o en curso.', input_schema: { type: 'object', properties: {} } },
  { name: 'reputacion_ip', description: 'Reputación de una IP: si está en la lista de IOCs, geolocalización y cuántas alertas generó en 24h.', input_schema: { type: 'object', properties: { ip: { type: 'string' } }, required: ['ip'] } },
];

async function toolBuscarAlertas(input: Record<string, unknown>): Promise<string> {
  const horas = Math.min(Math.max(Number(input.horas ?? 24), 1), 168);
  const minNivel = Math.min(Math.max(Number(input.min_nivel ?? 7), 1), 16);
  const limite = Math.min(Math.max(Number(input.limite ?? 10), 1), 25);
  const texto = typeof input.texto === 'string' ? input.texto.trim() : '';
  const incluirRuido = input.incluir_ruido === true;
  const filter: unknown[] = [{ range: { '@timestamp': { gte: `now-${horas}h` } } }, { range: { 'rule.level': { gte: minNivel } } }];
  if (texto) filter.push({ multi_match: { query: texto, fields: ['rule.description', 'full_log', 'data.srcip', 'agent.name'] } });
  const boolQuery: Record<string, unknown> = { filter };
  if (!incluirRuido) boolQuery.must_not = ruidoMustNot();
  const client = getIndexerClient();
  const { data } = await client.post<{ hits: { total: { value: number }; hits: { _source: Record<string, unknown> }[] } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    { size: limite, track_total_hits: true, sort: [{ 'rule.level': { order: 'desc' } }, { '@timestamp': { order: 'desc' } }], _source: ['@timestamp', 'rule.id', 'rule.level', 'rule.description', 'agent.name', 'data.srcip'], query: { bool: boolQuery } }
  );
  const hits = data.hits.hits.map((h) => {
    const s = h._source as { '@timestamp'?: string; rule?: { id?: string; level?: number; description?: string }; agent?: { name?: string }; data?: { srcip?: string } };
    return { ts: s['@timestamp'], nivel: s.rule?.level, regla: s.rule?.id, desc: s.rule?.description, agente: s.agent?.name, srcip: s.data?.srcip };
  });
  return JSON.stringify({ total: data.hits.total.value, ruido_excluido: !incluirRuido, mostrando: hits.length, alertas: hits });
}

async function toolTopVulns(): Promise<string> {
  const v = await getVulnerabilities();
  return JSON.stringify({ enKev: v.resumen.kev, criticas: v.resumen.critical, priorizadas: v.priorizadas.slice(0, 10).map((p) => ({ cve: p.cve, prioridad: p.priority, cvss: p.score, kev: p.inKev, epss: p.epss, activos: p.agentes || p.instancias, desc: p.description?.slice(0, 120) })) });
}

async function toolUeba(): Promise<string> {
  const rows = await listAnomalies({ status: 'open', days: 30 });
  return JSON.stringify({ total: rows.length, anomalias: rows.slice(0, 15).map((a) => ({ tipo: a.detector, usuario: a.entity, severidad: a.severity, titulo: a.title })) });
}

async function toolIncidentes(): Promise<string> {
  const rows = await query<{ id: string; title: string; severity: string; status: string; created_at: string }>(
    "SELECT id, title, severity, status, created_at FROM incidents WHERE status IN ('abierto','en_curso') ORDER BY created_at DESC LIMIT 20"
  ).catch(() => []);
  return JSON.stringify({ total: rows.length, incidentes: rows.map((r) => ({ id: r.id, titulo: r.title, severidad: r.severity, estado: r.status, creado: r.created_at })) });
}

async function toolReputacionIp(input: Record<string, unknown>): Promise<string> {
  const ip = String(input.ip ?? '').trim();
  if (!ip) return JSON.stringify({ error: 'IP no indicada' });
  const ioc = await query<{ source: string; description: string | null }>("SELECT source, description FROM iocs WHERE ioc_type='ip' AND value=$1 AND enabled=TRUE LIMIT 1", [ip]).catch(() => []);
  const geo = isPublicIP(ip) ? geolocate(ip) : null;
  let alertas24h = 0;
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{ count: number }>(`/${env.WAZUH_ALERTS_INDEX}/_count`, { query: { bool: { filter: [{ term: { 'data.srcip': ip } }, { range: { '@timestamp': { gte: 'now-24h' } } }] } } });
    alertas24h = data.count ?? 0;
  } catch { /* noop */ }
  return JSON.stringify({ ip, publica: isPublicIP(ip), en_ioc: ioc.length > 0, ioc_fuente: ioc[0]?.source ?? null, pais: geo?.country ?? null, ciudad: geo?.city ?? null, alertas_24h: alertas24h });
}

const TOOL_HANDLERS: Record<string, (input: Record<string, unknown>) => Promise<string>> = {
  buscar_alertas: toolBuscarAlertas,
  top_vulnerabilidades: () => toolTopVulns(),
  anomalias_ueba: () => toolUeba(),
  incidentes_abiertos: () => toolIncidentes(),
  reputacion_ip: toolReputacionIp,
};

/** Bucle agéntico: deja que el modelo use herramientas hasta dar la respuesta. */
async function runAgentic(system: string, initial: AnyMessage[], maxRounds = 5): Promise<{ reply: string; toolsUsed: string[] }> {
  const messages: AnyMessage[] = [...initial];
  const toolsUsed: string[] = [];
  for (let round = 0; round < maxRounds; round++) {
    const res = await callClaudeRaw(system, messages, TOOLS);
    if (res.stop_reason !== 'tool_use') {
      return { reply: textOf(res.content) || '(sin respuesta)', toolsUsed };
    }
    messages.push({ role: 'assistant', content: res.content });
    const results: unknown[] = [];
    for (const block of res.content) {
      if (block.type !== 'tool_use' || !block.name) continue;
      toolsUsed.push(block.name);
      const handler = TOOL_HANDLERS[block.name];
      let out: string;
      try { out = handler ? await handler(block.input ?? {}) : JSON.stringify({ error: 'herramienta desconocida' }); }
      catch (e) { out = JSON.stringify({ error: e instanceof Error ? e.message : 'fallo en la herramienta' }); }
      results.push({ type: 'tool_result', tool_use_id: block.id, content: out.slice(0, 6000) });
    }
    messages.push({ role: 'user', content: results });
  }
  // Se agotaron las rondas: pide una respuesta final sin herramientas.
  const res = await callClaudeRaw(system, messages);
  return { reply: textOf(res.content) || '(sin respuesta tras varias consultas)', toolsUsed };
}

// --- Snapshot en vivo del SOC (contexto) ---
interface RuleBucket { key: string; doc_count: number; lvl: { value: number | null }; desc: { hits: { hits: { _source: { rule?: { description?: string } } }[] } } }

async function alertsSnapshot(): Promise<string> {
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{
      hits: { total: { value: number } };
      aggregations?: { crit: { doc_count: number }; alta: { doc_count: number }; media: { doc_count: number }; rules: { buckets: RuleBucket[] } };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      track_total_hits: true,
      // Señal real: se excluye el ruido benigno (mismo criterio que los dashboards)
      // para que el contexto del copiloto no esté dominado por auditoría/FIM.
      query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }], must_not: ruidoMustNot() } },
      aggs: {
        crit: { filter: { range: { 'rule.level': { gte: 12 } } } },
        alta: { filter: { range: { 'rule.level': { gte: 8, lt: 12 } } } },
        media: { filter: { range: { 'rule.level': { gte: 5, lt: 8 } } } },
        rules: {
          terms: { field: 'rule.id', size: 6, order: { _count: 'desc' } },
          aggs: { lvl: { max: { field: 'rule.level' } }, desc: { top_hits: { size: 1, _source: ['rule.description'] } } },
        },
      },
    });
    const a = data.aggregations;
    const total = data.hits?.total?.value ?? 0;
    const lines = [`Alertas de seguridad últimas 24h (excluyendo ruido benigno): ${total} (críticas ≥12: ${a?.crit.doc_count ?? 0}, altas 8-11: ${a?.alta.doc_count ?? 0}, medias 5-7: ${a?.media.doc_count ?? 0}).`];
    const rules = a?.rules.buckets ?? [];
    if (rules.length) {
      lines.push('Reglas más frecuentes:');
      for (const r of rules) {
        const desc = r.desc.hits.hits[0]?._source?.rule?.description ?? '(sin descripción)';
        lines.push(`  - [${r.key} nivel ${Math.round(r.lvl.value ?? 0)}] ${desc} — ${r.doc_count} alertas`);
      }
    }
    return lines.join('\n');
  } catch (err) {
    logger.warn({ err: err instanceof Error ? err.message : err }, 'Copiloto: snapshot de alertas falló');
    return 'Alertas: no disponible (no se pudo consultar el Indexer).';
  }
}

async function incidentsSnapshot(): Promise<string> {
  const rows = await query<{ title: string; severity: string; status: string }>(
    "SELECT title, severity, status FROM incidents WHERE status IN ('abierto','en_curso') ORDER BY created_at DESC LIMIT 15"
  ).catch(() => []);
  if (!rows.length) return 'Incidentes abiertos: ninguno.';
  return 'Incidentes abiertos:\n' + rows.map((r) => `  - [${r.severity}/${r.status}] ${r.title}`).join('\n');
}

async function uebaSnapshot(): Promise<string> {
  const rows = await query<{ detector: string; entity: string; severity: string; title: string }>(
    "SELECT detector, entity, severity, title FROM ueba_anomalies WHERE status = 'open' ORDER BY score DESC, last_seen DESC LIMIT 12"
  ).catch(() => []);
  if (!rows.length) return 'Anomalías UEBA abiertas: ninguna.';
  return 'Anomalías de comportamiento (UEBA) abiertas:\n' + rows.map((r) => `  - [${r.severity}/${r.detector}] ${r.title}`).join('\n');
}

export async function buildSnapshot(): Promise<string> {
  const [alerts, incidents, ueba] = await Promise.all([alertsSnapshot(), incidentsSnapshot(), uebaSnapshot()]);
  const now = new Date().toISOString();
  return `CONTEXTO DEL SOC (generado ${now}):\n\n${alerts}\n\n${incidents}\n\n${ueba}`;
}

// --- Operaciones expuestas ---

const MAX_HISTORY = 10;
const MAX_INPUT = 4000;

export async function chat(history: ChatMessage[], message: string): Promise<{ reply: string; toolsUsed: string[] }> {
  const msg = String(message ?? '').trim().slice(0, MAX_INPUT);
  if (!msg) throw new HttpError(400, 'Mensaje vacío.');
  const snapshot = await buildSnapshot();
  const system = `${SYSTEM_BASE}\n\n${TOOLS_NOTE}\n\n---\n${snapshot}`;
  const hist: AnyMessage[] = (Array.isArray(history) ? history : [])
    .filter((m) => (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
    .slice(-MAX_HISTORY)
    .map((m) => ({ role: m.role, content: String(m.content).slice(0, MAX_INPUT) }));
  return runAgentic(system, [...hist, { role: 'user', content: msg }]);
}

/** Ejecuta un prompt puntual (system + user) y devuelve el texto. Reutilizable por
 *  otros módulos que necesitan análisis de Claude (p.ej. postura del firewall). */
export async function completarPrompt(system: string, user: string, maxTokens = 2500): Promise<string> {
  return callClaude(system, [{ role: 'user', content: user }], maxTokens);
}

export async function triageAlert(text: string): Promise<{ reply: string }> {
  const t = String(text ?? '').trim().slice(0, MAX_INPUT);
  if (!t) throw new HttpError(400, 'Falta la alerta a triar.');
  const system = `${SYSTEM_BASE}\n\nTarea: haz el TRIAJE de esta alerta como un analista de nivel 1. Responde SOLO con esta estructura breve:\n**Veredicto**: (Verdadero positivo probable / Falso positivo probable / Requiere investigación)\n**Por qué**: 1-2 frases.\n**Severidad real**: (crítica/alta/media/baja) y si difiere del nivel de la regla, dilo.\n**Acción recomendada**: el siguiente paso concreto en HexWatch.`;
  // 1500, no 500: claude-sonnet-5 emite bloques de "thinking" por defecto que
  // consumen presupuesto antes del texto visible; con 500 + el system prompt largo
  // el razonamiento se comía todo y la respuesta salía vacía. El triaje real usa ~450.
  const reply = await callClaude(system, [{ role: 'user', content: t }], 1500);
  return { reply };
}

export async function explain(text: string): Promise<{ reply: string }> {
  const t = String(text ?? '').trim().slice(0, MAX_INPUT);
  if (!t) throw new HttpError(400, 'Falta el texto de la alerta a explicar.');
  const system = `${SYSTEM_BASE}\n\nTarea: explica en lenguaje claro la siguiente alerta/regla de Wazuh: qué significa, qué la dispara, qué tan grave es, posibles falsos positivos y qué debería hacer el analista. Sé breve y accionable.`;
  const reply = await callClaude(system, [{ role: 'user', content: t }]);
  return { reply };
}

export async function summarizeIncident(id: string): Promise<{ reply: string }> {
  const inc = (await query<{ title: string; description: string | null; severity: string; status: string; source: unknown; created_at: string }>(
    'SELECT title, description, severity, status, source, created_at FROM incidents WHERE id = $1', [id]
  ))[0];
  if (!inc) throw new HttpError(404, 'Incidente no encontrado.');
  const notes = await query<{ author_name: string | null; kind: string; note: string; created_at: string }>(
    'SELECT author_name, kind, note, created_at FROM incident_notes WHERE incident_id = $1 ORDER BY created_at ASC LIMIT 40', [id]
  ).catch(() => []);
  const ctx = [
    `Incidente: ${inc.title}`,
    `Severidad: ${inc.severity} · Estado: ${inc.status} · Creado: ${inc.created_at}`,
    inc.description ? `Descripción: ${inc.description}` : '',
    `Origen: ${JSON.stringify(inc.source)}`,
    notes.length ? 'Bitácora:\n' + notes.map((n) => `  - (${n.kind}) ${n.author_name ?? 'sistema'}: ${n.note}`).join('\n') : 'Bitácora: (sin notas)',
  ].filter(Boolean).join('\n');
  const system = `${SYSTEM_BASE}\n\nTarea: resume este incidente para un traspaso de turno y propón los próximos pasos concretos. Estructura: **Qué pasó**, **Estado actual**, **Riesgo**, **Próximos pasos**.`;
  const reply = await callClaude(system, [{ role: 'user', content: ctx }]);
  return { reply };
}
