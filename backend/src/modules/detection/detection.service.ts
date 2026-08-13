/**
 * Gestión de detecciones: reglas más ruidosas (desde el Indexer) y supresión de
 * falsos positivos sin editar XML a mano. Las supresiones son reglas hijas de
 * nivel 1 (por debajo del umbral de alerta) que Wazuh evalúa con prioridad y que
 * viven en un bloque gestionado dentro de local_rules.xml.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { wazuhApiGet, wazuhApiGetRaw, wazuhApiPutFile, wazuhApiRestart } from '../wazuh/wazuh.api.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

const RULES_FILE = 'local_rules.xml';
const RULES_PATH = `/rules/files/${RULES_FILE}`;
const START = '<!-- HEXWATCH-FP-SUPPRESSIONS:START -->';
const END = '<!-- HEXWATCH-FP-SUPPRESSIONS:END -->';
const ID_MIN = 100900;
const ID_MAX = 100989;

// Campos por los que se permite suprimir (whitelist; evita romper el ruleset).
// OJO: srcip/dstip son campos ESTÁTICOS de Wazuh y usan su elemento dedicado
// (<srcip>), NO <field name=> (que es solo para campos dinámicos data.*).
export const ALLOWED_FIELDS = [
  'srcip', 'dstip', 'full_log', 'data.srcip', 'data.dstip',
  'data.win.eventdata.objectName', 'data.win.eventdata.subjectUserName',
  'data.win.eventdata.targetUserName', 'data.win.system.computer', 'data.id',
];
const STATIC_IP_FIELDS = new Set(['srcip', 'dstip']);

export interface NoisyRule {
  ruleId: string;
  description: string;
  level: number;
  count: number;
  groups: string[];
}

export interface Suppression {
  id: number;
  targetRuleId: string;
  field: string;
  value: string;
  comment: string;
}

/** Top de reglas que más disparan en el rango (candidatas a falso positivo). */
export async function getNoisyRules(range: string): Promise<NoisyRule[]> {
  const client = getIndexerClient();
  const gte = /^\d+[hd]$/.test(range) ? `now-${range}` : 'now-24h';
  const { data } = await client.post<{
    aggregations?: { r: { buckets: { key: string; doc_count: number; d: { hits: { hits: { _source: { rule?: { description?: string; level?: number; groups?: string[] } } }[] } } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { range: { '@timestamp': { gte } } },
    aggs: {
      r: {
        terms: { field: 'rule.id', size: 25 },
        aggs: { d: { top_hits: { size: 1, _source: ['rule.description', 'rule.level', 'rule.groups'] } } },
      },
    },
  });
  return (data.aggregations?.r?.buckets ?? []).map((b) => {
    const src = b.d.hits.hits[0]?._source?.rule ?? {};
    return {
      ruleId: b.key,
      description: src.description ?? '(sin descripción)',
      level: src.level ?? 0,
      count: b.doc_count,
      groups: src.groups ?? [],
    };
  });
}

/** Reglas personalizadas cargadas (local_rules.xml). */
export async function getCustomRules(): Promise<{ id: number; level: number; description: string; groups: string[] }[]> {
  const d = await wazuhApiGet<{ affected_items?: Array<{ id: number; level: number; description: string; groups?: string[] }> }>(
    '/rules', { filename: RULES_FILE, limit: 500 }
  );
  return (d.affected_items ?? []).map((r) => ({ id: r.id, level: r.level, description: r.description, groups: r.groups ?? [] }));
}

// --- Supresiones (bloque gestionado en local_rules.xml) ---

// OS_XML (el parser de Wazuh) SOLO entiende &amp; &lt; &gt; — NO &quot; ni &apos;
// (rompen la carga con "XML syntax error"). En texto de elemento las comillas van
// literales; solo se escapan & < >.
function xmlText(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function xmlUnescape(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}
// Patrón pcre2 SIN backslashes (OS_XML también los rechaza) y sin metacaracteres
// regex activos: cada carácter que no sea [A-Za-z0-9 _-] se vuelve '.', que casa
// cualquier carácter (incluye el separador \ de rutas Windows y el . del valor).
// Es una coincidencia "contiene" difusa, suficiente para suprimir un FP concreto.
function toSafePattern(value: string): string {
  return `(?i)${value.replace(/[^A-Za-z0-9 _-]/g, '.')}`;
}

async function readRulesFile(): Promise<string> {
  return wazuhApiGetRaw(`${RULES_PATH}?raw=true`);
}

function extractBlock(file: string): string {
  const i = file.indexOf(START);
  const j = file.indexOf(END);
  if (i === -1 || j === -1 || j < i) return '';
  return file.slice(i + START.length, j);
}

/** El matcher XML apropiado según el tipo de campo. */
function renderMatcher(field: string, value: string): string {
  if (STATIC_IP_FIELDS.has(field)) {
    // Elemento dedicado; valor = IP o CIDR literal (Wazuh lo compara como IP).
    return `    <${field}>${xmlText(value)}</${field}>\n`;
  }
  if (field === 'full_log') {
    // Substring en el log crudo (OS_Match), sin backslashes.
    return `    <match>${xmlText(value.replace(/\\/g, '.'))}</match>\n`;
  }
  // Campo dinámico (data.*) → pcre2 sin backslashes.
  return `    <field name="${field}" type="pcre2">${xmlText(toSafePattern(value))}</field>\n`;
}

/** Reconstruye el XML de una regla de supresión a partir de sus datos legibles. */
function renderRule(s: Suppression): string {
  const descr = xmlText(`HexWatch supresion FP: regla ${s.targetRuleId} cuando ${s.field} contiene "${s.value}" (${s.comment || 'sin nota'})`);
  return (
    `  <rule id="${s.id}" level="1">\n` +
    `    <if_sid>${s.targetRuleId}</if_sid>\n` +
    renderMatcher(s.field, s.value) +
    `    <options>no_full_log</options>\n` +
    `    <description>${descr}</description>\n` +
    `    <group>hexwatch,fp_suppression,</group>\n` +
    `  </rule>\n`
  );
}

/** Lee campo/valor/comentario legibles de la descripción (agnóstico al matcher). */
function parseSuppressions(block: string): Suppression[] {
  const out: Suppression[] = [];
  const ruleRe = /<rule id="(\d+)"[^>]*>([\s\S]*?)<\/rule>/g;
  let m: RegExpExecArray | null;
  while ((m = ruleRe.exec(block)) !== null) {
    const id = Number(m[1]);
    const body = m[2];
    const targetRuleId = /<if_sid>(\d+)<\/if_sid>/.exec(body)?.[1] ?? '';
    const desc = xmlUnescape(/<description>([\s\S]*?)<\/description>/.exec(body)?.[1] ?? '');
    const field = /cuando (\S+) contiene/.exec(desc)?.[1] ?? '';
    const value = /contiene "([\s\S]*?)"\s*\(/.exec(desc)?.[1] ?? '';
    const comment = /\(([^)]*)\)\s*$/.exec(desc)?.[1] ?? '';
    out.push({ id, targetRuleId, field, value, comment: comment === 'sin nota' ? '' : comment });
  }
  return out;
}

function renderBlock(items: Suppression[]): string {
  const rules = items.map(renderRule).join('');
  return `\n${START}\n<group name="hexwatch,fp_suppression,">\n${rules}</group>\n${END}\n`;
}

function spliceBlock(file: string, block: string): string {
  const i = file.indexOf(START);
  const j = file.indexOf(END);
  if (i !== -1 && j !== -1 && j > i) {
    return file.slice(0, i).replace(/\s*$/, '') + '\n' + block.trim() + '\n' + file.slice(j + END.length).replace(/^\s*/, '');
  }
  return file.replace(/\s*$/, '') + '\n' + block;
}

function removeBlockFromFile(file: string): string {
  const i = file.indexOf(START);
  const j = file.indexOf(END);
  if (i === -1 || j === -1 || j < i) return file;
  return (file.slice(0, i).replace(/\s*$/, '') + '\n' + file.slice(j + END.length).replace(/^\s*/, '')).replace(/\n{3,}/g, '\n\n');
}

async function writeAndReload(newFile: string): Promise<void> {
  const resp = await wazuhApiPutFile(`${RULES_PATH}?overwrite=true`, newFile);
  if (resp.error && resp.error !== 0) {
    throw new HttpError(400, `El manager rechazó el ruleset: ${resp.message ?? 'error de sintaxis'}`);
  }
  await wazuhApiRestart();
}

export async function listSuppressions(): Promise<Suppression[]> {
  const file = await readRulesFile();
  return parseSuppressions(extractBlock(file));
}

export async function addSuppression(input: { targetRuleId: string; field: string; value: string; comment: string }): Promise<Suppression> {
  const targetRuleId = String(input.targetRuleId).trim();
  const field = String(input.field).trim();
  const value = String(input.value).trim();
  const comment = String(input.comment || '').trim().slice(0, 120);

  if (!/^\d{3,7}$/.test(targetRuleId)) throw new HttpError(400, 'ID de regla objetivo inválido');
  if (!ALLOWED_FIELDS.includes(field)) throw new HttpError(400, `Campo no permitido. Usa uno de: ${ALLOWED_FIELDS.join(', ')}`);
  if (value.length < 1 || value.length > 200) throw new HttpError(400, 'Valor inválido (1-200 caracteres)');
  // srcip/dstip se comparan como IP/CIDR: exige ese formato (evita romper el matcher).
  if (STATIC_IP_FIELDS.has(field) && !/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(value)) {
    throw new HttpError(400, `Para ${field} el valor debe ser una IP o CIDR (p. ej. 203.0.113.7 o 203.0.113.0/24)`);
  }

  const file = await readRulesFile();
  const existing = parseSuppressions(extractBlock(file));
  if (existing.some((s) => s.targetRuleId === targetRuleId && s.field === field && s.value === value)) {
    throw new HttpError(409, 'Ya existe una supresión idéntica');
  }
  const used = new Set(existing.map((s) => s.id));
  let id = ID_MIN;
  while (used.has(id) && id <= ID_MAX) id++;
  if (id > ID_MAX) throw new HttpError(400, 'Límite de supresiones alcanzado; elimina alguna antes de crear otra');

  const nueva: Suppression = { id, targetRuleId, field, value, comment };
  const newFile = spliceBlock(file, renderBlock([...existing, nueva]));
  await writeAndReload(newFile);
  return nueva;
}

export async function removeSuppression(id: number): Promise<void> {
  if (!Number.isInteger(id) || id < ID_MIN || id > ID_MAX) throw new HttpError(400, 'ID de supresión inválido');
  const file = await readRulesFile();
  const existing = parseSuppressions(extractBlock(file));
  if (!existing.some((s) => s.id === id)) throw new HttpError(404, 'Supresión no encontrada');
  const remaining = existing.filter((s) => s.id !== id);
  const newFile = remaining.length === 0 ? removeBlockFromFile(file) : spliceBlock(file, renderBlock(remaining));
  await writeAndReload(newFile);
}
