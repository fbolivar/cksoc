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
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';

export interface ChatMessage { role: 'user' | 'assistant'; content: string }

export function isConfigured(): boolean {
  return Boolean(env.ANTHROPIC_API_KEY);
}

const SYSTEM_BASE = `Eres el copiloto de seguridad de HexWatch, una plataforma SOC on-premise construida sobre Wazuh, FortiGate y Velociraptor. Asistes a analistas de un SOC en Colombia.

Reglas:
- Responde SIEMPRE en español, claro y conciso, con tono de analista SOC senior.
- Apóyate en el CONTEXTO DEL SOC que se te entrega. Si el contexto no alcanza para responder, dilo y sugiere qué revisar o qué dato falta; NO inventes IPs, hosts, reglas ni cifras.
- Cuando recomiendes acciones, sé concreto y prioriza (contención, investigación, siguiente paso), acorde a las capacidades de HexWatch (bloqueo en FortiGate, aislamiento con Velociraptor, supresión de falsos positivos, crear incidente).
- No ejecutas acciones tú mismo: propones. El analista decide y actúa en la plataforma.
- Formatea con listas y **negritas** cuando ayude a la legibilidad.`;

// --- Cliente Anthropic (REST directo, sin SDK) ---
async function callClaude(system: string, messages: ChatMessage[], maxTokens?: number): Promise<string> {
  if (!env.ANTHROPIC_API_KEY) {
    throw new HttpError(503, 'El copiloto no está configurado (falta ANTHROPIC_API_KEY).');
  }
  try {
    const { data } = await axios.post(
      `${env.ANTHROPIC_BASE_URL.replace(/\/$/, '')}/v1/messages`,
      {
        model: env.ANTHROPIC_MODEL,
        max_tokens: maxTokens ?? env.COPILOT_MAX_TOKENS,
        system,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
      },
      {
        headers: {
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        timeout: 60000,
      }
    );
    const blocks: Array<{ type: string; text?: string }> = data?.content ?? [];
    const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim();
    return text || '(respuesta vacía del modelo)';
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
      query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-24h' } } }] } },
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
    const lines = [`Alertas últimas 24h: ${total} (críticas ≥12: ${a?.crit.doc_count ?? 0}, altas 8-11: ${a?.alta.doc_count ?? 0}, medias 5-7: ${a?.media.doc_count ?? 0}).`];
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

export async function chat(history: ChatMessage[], message: string): Promise<{ reply: string }> {
  const msg = String(message ?? '').trim().slice(0, MAX_INPUT);
  if (!msg) throw new HttpError(400, 'Mensaje vacío.');
  const snapshot = await buildSnapshot();
  const system = `${SYSTEM_BASE}\n\n---\n${snapshot}`;
  const hist = (Array.isArray(history) ? history : [])
    .filter((m) => (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
    .slice(-MAX_HISTORY)
    .map((m) => ({ role: m.role, content: String(m.content).slice(0, MAX_INPUT) }));
  const reply = await callClaude(system, [...hist, { role: 'user', content: msg }]);
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
