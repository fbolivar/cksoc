/**
 * SOAR: reglas de respuesta automatizada. Un motor evalúa periódicamente las
 * alertas recientes; cuando una regla coincide, ejecuta la acción (modo auto) o
 * la deja pendiente de aprobación de un admin. Salvaguardas: cooldown por
 * regla+entidad, modo dry-run, la lista blanca del bloqueo, y aislar/bloquear
 * solo actúan sobre entidades válidas.
 */
import { query } from '../../config/db';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { isPublicIP } from '../geo/geoip.service';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { block } from '../response/response.service';
import { isWhitelisted } from '../response/whitelist';
import { createIncident } from '../incidents/incidents.service';
import { runHelper } from '../velociraptor/velociraptor.helper';
import { disableAdUser, disableM365User } from '../identity/identity.service';
import { sendTelegram, isTelegramConfigured } from '../notifications/telegram.service';
import { logger } from '../../config/logger';

export type TriggerType = 'ioc_ip_match' | 'rule_level' | 'rule_id';
export type ActionType = 'block_ip' | 'isolate_host' | 'create_incident' | 'disable_ad_user' | 'disable_m365_user';
export type Mode = 'auto' | 'approval';

export interface AutomationRule {
  id: string;
  name: string;
  enabled: boolean;
  trigger_type: TriggerType;
  trigger_config: { minLevel?: number; group?: string; ruleId?: string; excludeGroups?: string[] };
  action: ActionType;
  mode: Mode;
  dry_run: boolean;
  cooldown_min: number;
  created_by: string | null;
  last_triggered_at: string | null;
  trigger_count: number;
  created_at: string;
}

const TRIGGERS: TriggerType[] = ['ioc_ip_match', 'rule_level', 'rule_id'];
const ACTIONS: ActionType[] = ['block_ip', 'isolate_host', 'create_incident', 'disable_ad_user', 'disable_m365_user'];
const USER_ACTIONS: ActionType[] = ['disable_ad_user', 'disable_m365_user'];

// Campo del Indexer por el que se agrupan las entidades según la acción.
function entityField(action: ActionType): string {
  if (action === 'isolate_host') return 'agent.name';
  if (USER_ACTIONS.includes(action)) return 'data.srcuser'; // acciones sobre usuario
  return 'data.srcip';
}

// --- CRUD de reglas ---

export async function listRules(): Promise<AutomationRule[]> {
  return query<AutomationRule>('SELECT * FROM automation_rules ORDER BY created_at DESC');
}

export async function createRule(input: Partial<AutomationRule>, userId: string): Promise<AutomationRule> {
  const name = String(input.name || '').trim().slice(0, 160);
  const trigger_type = input.trigger_type as TriggerType;
  const action = input.action as ActionType;
  const mode = (input.mode === 'auto' ? 'auto' : 'approval') as Mode;
  if (!name) throw new HttpError(400, 'Nombre requerido');
  if (!TRIGGERS.includes(trigger_type)) throw new HttpError(400, 'Disparador inválido');
  if (!ACTIONS.includes(action)) throw new HttpError(400, 'Acción inválida');
  const cfg = sanitizeConfig(trigger_type, input.trigger_config ?? {});
  const cooldown = Math.min(Math.max(Number(input.cooldown_min ?? 60), 5), 1440);
  const dry = Boolean(input.dry_run);
  const rows = await query<AutomationRule>(
    `INSERT INTO automation_rules (name, enabled, trigger_type, trigger_config, action, mode, dry_run, cooldown_min, created_by)
     VALUES ($1, TRUE, $2, $3::jsonb, $4, $5, $6, $7, $8) RETURNING *`,
    [name, trigger_type, JSON.stringify(cfg), action, mode, dry, cooldown, userId]
  );
  return rows[0];
}

export async function updateRule(id: string, input: Partial<AutomationRule>): Promise<AutomationRule> {
  const cur = (await query<AutomationRule>('SELECT * FROM automation_rules WHERE id = $1', [id]))[0];
  if (!cur) throw new HttpError(404, 'Regla no encontrada');
  const enabled = input.enabled ?? cur.enabled;
  const mode = (input.mode ?? cur.mode) === 'auto' ? 'auto' : 'approval';
  const dry = input.dry_run ?? cur.dry_run;
  const cooldown = input.cooldown_min != null ? Math.min(Math.max(Number(input.cooldown_min), 5), 1440) : cur.cooldown_min;
  const rows = await query<AutomationRule>(
    `UPDATE automation_rules SET enabled = $2, mode = $3, dry_run = $4, cooldown_min = $5 WHERE id = $1 RETURNING *`,
    [id, enabled, mode, dry, cooldown]
  );
  return rows[0];
}

export async function removeRule(id: string): Promise<void> {
  const rows = await query('DELETE FROM automation_rules WHERE id = $1 RETURNING id', [id]);
  if (rows.length === 0) throw new HttpError(404, 'Regla no encontrada');
}

function sanitizeConfig(type: TriggerType, cfg: Record<string, unknown>): AutomationRule['trigger_config'] {
  if (type === 'rule_level') return {
    minLevel: Math.min(Math.max(Number(cfg.minLevel ?? 8), 1), 16),
    group: cfg.group ? String(cfg.group).slice(0, 60) : undefined,
    // Grupos de regla a EXCLUIR del disparo (p.ej. 'vulnerability-detector':
    // las deteccion de CVE llegan a nivel 13 pero NO son un ataque, no deben
    // proponer aislamiento). Hasta 10 grupos.
    excludeGroups: Array.isArray(cfg.excludeGroups)
      ? cfg.excludeGroups.map((g) => String(g).slice(0, 60)).filter(Boolean).slice(0, 10)
      : undefined,
  };
  if (type === 'rule_id') {
    const ruleId = String(cfg.ruleId ?? '').trim();
    if (!/^\d{3,7}$/.test(ruleId)) throw new HttpError(400, 'ruleId inválido');
    return { ruleId };
  }
  return {};
}

// --- Eventos / cola de aprobación ---

export interface AutomationEvent {
  id: string; rule_id: string | null; rule_name: string | null; entity: string;
  action: ActionType; status: string; detail: Record<string, unknown>;
  created_at: string; resolved_by: string | null; resolved_at: string | null;
}

export async function listEvents(limit = 100): Promise<AutomationEvent[]> {
  return query<AutomationEvent>('SELECT * FROM automation_events ORDER BY created_at DESC LIMIT $1', [Math.min(limit, 300)]);
}

export async function pendingCount(): Promise<number> {
  const r = await query<{ n: string }>("SELECT COUNT(*)::int AS n FROM automation_events WHERE status = 'pending'");
  return Number(r[0]?.n ?? 0);
}

export async function resolveEvent(id: string, decision: 'approve' | 'reject', userId: string): Promise<AutomationEvent> {
  const ev = (await query<AutomationEvent>('SELECT * FROM automation_events WHERE id = $1', [id]))[0];
  if (!ev) throw new HttpError(404, 'Evento no encontrado');
  if (ev.status !== 'pending') throw new HttpError(409, 'El evento ya fue resuelto');
  if (decision === 'reject') {
    return updateEvent(id, 'rejected', { ...ev.detail, resolution: 'rechazado' }, userId);
  }
  const rule = (await query<AutomationRule>('SELECT * FROM automation_rules WHERE id = $1', [ev.rule_id]))[0];
  const res = await executeAction(ev.action, ev.entity, rule);
  return updateEvent(id, res.ok ? 'executed' : 'failed', { ...ev.detail, ...res.detail }, userId);
}

async function updateEvent(id: string, status: string, detail: Record<string, unknown>, userId?: string): Promise<AutomationEvent> {
  const rows = await query<AutomationEvent>(
    `UPDATE automation_events SET status = $2, detail = $3::jsonb, resolved_by = COALESCE($4, resolved_by), resolved_at = now() WHERE id = $1 RETURNING *`,
    [id, status, JSON.stringify(detail), userId ?? null]
  );
  return rows[0];
}

// --- Ejecución de acciones ---

async function executeAction(action: ActionType, entity: string, rule?: AutomationRule): Promise<{ ok: boolean; detail: Record<string, unknown> }> {
  try {
    const actorId = rule?.created_by ?? null;
    if (action === 'block_ip') {
      if (!actorId) return { ok: false, detail: { error: 'La regla no tiene autor válido' } };
      await block({ ip: entity, motivo: `SOAR: ${rule?.name ?? 'automatización'}`, user: { id: actorId, email: 'soar-automation' } });
      return { ok: true, detail: { executed: 'block_ip' } };
    }
    if (action === 'isolate_host') {
      const r = await runHelper(['action', entity, 'isolate']);
      if (r?.error) return { ok: false, detail: { error: String(r.error) } };
      return { ok: true, detail: { executed: 'isolate_host', flow_id: r.flow_id } };
    }
    if (action === 'create_incident') {
      if (!actorId) return { ok: false, detail: { error: 'La regla no tiene autor válido' } };
      const inc = await createIncident({
        title: `[SOAR] ${rule?.name ?? 'Automatización'} — ${entity}`.slice(0, 180),
        description: `Incidente creado automáticamente por la regla SOAR "${rule?.name}" sobre ${entity}.`,
        severity: 'alta',
        source: { ip: entity },
        // Firma para deduplicar: misma regla SOAR sobre la misma entidad = un solo caso.
        dedupKey: `soar:${rule?.id ?? rule?.name ?? 'rule'}:${entity}`,
      }, actorId);
      return { ok: true, detail: { executed: 'create_incident', incident_id: inc.id } };
    }
    if (action === 'disable_ad_user') {
      const r = await disableAdUser(entity);
      return { ok: true, detail: { executed: 'disable_ad_user', dn: r.dn } };
    }
    if (action === 'disable_m365_user') {
      const r = await disableM365User(entity);
      return { ok: true, detail: { executed: 'disable_m365_user', revoked: r.revoked } };
    }
    return { ok: false, detail: { error: 'acción desconocida' } };
  } catch (err) {
    return { ok: false, detail: { error: err instanceof HttpError ? err.message : (err instanceof Error ? err.message : 'error') } };
  }
}

// --- Motor de evaluación ---

interface Agg { key: string; doc_count: number }

// Ruido de alto nivel que NUNCA debe disparar una acción automática (base, además
// del excludeGroups configurable por regla). vulnerability-detector = CVEs (no accionables
// por bloqueo/aislamiento); sca = auditoría CIS.
const SOAR_NOISE_GROUPS = ['sca', 'vulnerability-detector'];
// Infraestructura de seguridad/SOC que jamás debe aislarse (cortarla es catastrófico).
const CRITICAL_HOSTS_RE = /(soc-app|soc-wazuh|soc-velo|velociraptor|wazuh|pmx-soc|-soc-)/i;

async function matchEntities(rule: AutomationRule): Promise<Agg[]> {
  const client = getIndexerClient();
  const field = entityField(rule.action);
  const filter: unknown[] = [
    { range: { '@timestamp': { gte: 'now-15m' } } },
    { exists: { field } },
  ];
  if (rule.trigger_type === 'rule_level') {
    filter.push({ range: { 'rule.level': { gte: rule.trigger_config.minLevel ?? 8 } } });
    if (rule.trigger_config.group) filter.push({ match: { 'rule.groups': rule.trigger_config.group } });
    // Excluir grupos de ruido conocido (CVE de vulnerability-detector, etc.)
    for (const g of rule.trigger_config.excludeGroups ?? []) {
      filter.push({ bool: { must_not: [{ match: { 'rule.groups': g } }] } });
    }
    // Exclusión BASE de ruido (además del excludeGroups por regla): que el motor
    // nunca dispare una acción sobre falsos positivos conocidos.
    for (const g of SOAR_NOISE_GROUPS) filter.push({ bool: { must_not: [{ match: { 'rule.groups': g } }] } });
    // Conectividad benigna (VPN/login de usuarios) nunca es base para bloquear/aislar.
    filter.push({ bool: { must_not: [{ wildcard: { 'rule.description': { value: '*vpn user*', case_insensitive: true } } }] } });
  } else if (rule.trigger_type === 'rule_id') {
    filter.push({ term: { 'rule.id': rule.trigger_config.ruleId } });
  }
  const { data } = await client.post<{ aggregations?: { e: { buckets: Agg[] } } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    { size: 0, query: { bool: { filter } }, aggs: { e: { terms: { field, size: 50 } } } }
  );
  let buckets = data.aggregations?.e?.buckets ?? [];

  // ioc_ip_match: la entidad (srcip) debe estar en la lista de IOCs de IP.
  if (rule.trigger_type === 'ioc_ip_match') {
    const iocs = await query<{ value: string }>("SELECT value FROM iocs WHERE ioc_type = 'ip' AND enabled = TRUE");
    const set = new Set(iocs.map((i) => i.value));
    buckets = buckets.filter((b) => set.has(b.key));
  }
  // Descarta IPv6 link-local/multicast/loopback como entidad IP (ruido).
  if (field === 'data.srcip') buckets = buckets.filter((b) => !/^(fe80|ff0|::1|fec0)/i.test(b.key));
  // block_ip: solo IPs públicas y NUNCA la lista blanca (infra crítica de GVM).
  // Se excluye aquí para no generar siquiera un evento (defensa en profundidad
  // sobre la guarda canBlock, que también lo rechazaría al ejecutar).
  if (rule.action === 'block_ip') buckets = buckets.filter((b) => isPublicIP(b.key) && !isWhitelisted(b.key));
  // isolate_host: nunca aislar la infraestructura de seguridad/SOC (sería catastrófico).
  if (rule.action === 'isolate_host') buckets = buckets.filter((b) => !CRITICAL_HOSTS_RE.test(b.key));
  return buckets;
}

async function onCooldown(ruleId: string, entity: string, cooldownMin: number): Promise<boolean> {
  const r = await query(
    `SELECT 1 FROM automation_events WHERE rule_id = $1 AND entity = $2 AND created_at > now() - ($3 || ' minutes')::interval LIMIT 1`,
    [ruleId, entity, String(cooldownMin)]
  );
  return r.length > 0;
}

const ACTION_ES: Record<ActionType, string> = {
  block_ip: 'bloqueó IP', isolate_host: 'aisló host', create_incident: 'creó incidente',
  disable_ad_user: 'deshabilitó cuenta AD', disable_m365_user: 'deshabilitó cuenta M365',
};

/** Aviso por Telegram del resultado de una corrida del motor (si hay novedades). */
async function notifySoarRun(autoDone: string[], pending: number): Promise<void> {
  if (!isTelegramConfigured() || !env.TELEGRAM_CHAT_ID) return;
  if (autoDone.length === 0 && pending === 0) return;
  const lines = ['🤖 *HexWatch · SOAR*'];
  if (autoDone.length) { lines.push(`🔒 Acciones automáticas (${autoDone.length}):`); for (const a of autoDone.slice(0, 8)) lines.push(`  • ${a}`); }
  if (pending) lines.push(`🙋 ${pending} acción(es) esperan tu aprobación en el *Centro de Acción*.`);
  try { await sendTelegram([env.TELEGRAM_CHAT_ID], lines.join('\n')); }
  catch (err) { logger.warn({ err: err instanceof Error ? err.message : err }, 'SOAR: fallo notificando por Telegram'); }
}

/** Evalúa todas las reglas habilitadas y crea/ejecuta eventos. */
export async function runEngine(): Promise<{ evaluated: number; created: number }> {
  const rules = await query<AutomationRule>('SELECT * FROM automation_rules WHERE enabled = TRUE');
  let created = 0;
  const autoDone: string[] = [];
  let pending = 0;
  for (const rule of rules) {
    let entities: Agg[];
    try { entities = await matchEntities(rule); }
    catch (err) { logger.warn({ err: err instanceof Error ? err.message : err, rule: rule.name }, 'SOAR: fallo evaluando regla'); continue; }

    for (const e of entities) {
      if (await onCooldown(rule.id, e.key, rule.cooldown_min)) continue;

      let status: string;
      let detail: Record<string, unknown> = { count: e.doc_count };
      if (rule.dry_run) {
        status = 'skipped';
        detail.reason = 'dry_run';
      } else if (rule.mode === 'auto') {
        const res = await executeAction(rule.action, e.key, rule);
        status = res.ok ? 'executed' : 'failed';
        detail = { ...detail, ...res.detail };
        if (res.ok) autoDone.push(`${ACTION_ES[rule.action]}: ${e.key}`);
      } else {
        status = 'pending';
        pending++;
      }
      await query(
        `INSERT INTO automation_events (rule_id, rule_name, entity, action, status, detail)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [rule.id, rule.name, e.key, rule.action, status, JSON.stringify(detail)]
      );
      created++;
    }
    if (entities.length) {
      await query('UPDATE automation_rules SET last_triggered_at = now(), trigger_count = trigger_count + $2 WHERE id = $1', [rule.id, entities.length]).catch(() => undefined);
    }
  }
  await notifySoarRun(autoDone, pending);
  return { evaluated: rules.length, created };
}
