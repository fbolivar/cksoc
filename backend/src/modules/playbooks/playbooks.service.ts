/**
 * SOAR / Playbooks: respuesta automatizada ante patrones de alerta.
 *
 * Seguridad por diseno:
 *  - enabled=false por defecto; el motor solo evalua los habilitados.
 *  - mode 'simulacion' (por defecto) registra lo que HARIA sin ejecutar;
 *    'activo' ejecuta. Asi se valida un playbook antes de darle poder real.
 *  - cooldown por objetivo (ip/agente) para no inundar ni re-bloquear.
 *  - la accion block_ip pasa por response.block, que valida la LISTA BLANCA.
 */
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { block } from '../response/response.service';
import { createIncident, type Severity } from '../incidents/incidents.service';
import { logNotification } from '../notifications/notify.engine';
import { recordAudit } from '../audit/audit.service';

export type Mode = 'simulacion' | 'activo';
export type ActionType = 'block_ip' | 'create_incident' | 'notify';

export interface PlaybookConditions {
  minLevel?: number;
  ruleIds?: string[];
  mitre?: string[];
  agents?: string[];
  groups?: string[];
}
export interface PlaybookAction { type: ActionType }

export interface Playbook {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  mode: Mode;
  conditions: PlaybookConditions;
  actions: PlaybookAction[];
  cooldownMin: number;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AlertContext {
  alertId: string;
  level: number;
  ruleId: string;
  description: string;
  agent: string;
  ip: string | null;
  mitre: string[];
  groups: string[];
  timestamp: string;
}

interface Row {
  id: string; name: string; description: string | null; enabled: boolean; mode: Mode;
  conditions: PlaybookConditions; actions: PlaybookAction[]; cooldown_min: number;
  created_by: string | null; created_at: string; updated_at: string;
}

function toPlaybook(r: Row): Playbook {
  return {
    id: r.id, name: r.name, description: r.description, enabled: r.enabled, mode: r.mode,
    conditions: r.conditions ?? {}, actions: r.actions ?? [], cooldownMin: r.cooldown_min,
    createdBy: r.created_by, createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

export async function listPlaybooks(): Promise<Playbook[]> {
  const rows = await query<Row>('SELECT * FROM playbooks ORDER BY created_at DESC');
  return rows.map(toPlaybook);
}

export async function getPlaybook(id: string): Promise<Playbook | null> {
  const rows = await query<Row>('SELECT * FROM playbooks WHERE id = $1', [id]);
  return rows[0] ? toPlaybook(rows[0]) : null;
}

export async function createPlaybook(data: {
  name: string; description?: string; mode?: Mode; conditions: PlaybookConditions;
  actions: PlaybookAction[]; cooldownMin?: number; enabled?: boolean; createdBy: string;
}): Promise<Playbook> {
  const rows = await query<Row>(
    `INSERT INTO playbooks (name, description, enabled, mode, conditions, actions, cooldown_min, created_by)
     VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8) RETURNING *`,
    [data.name, data.description ?? null, data.enabled ?? false, data.mode ?? 'simulacion',
     JSON.stringify(data.conditions), JSON.stringify(data.actions), data.cooldownMin ?? 30, data.createdBy]
  );
  return toPlaybook(rows[0]);
}

export async function updatePlaybook(id: string, data: Partial<{
  name: string; description: string; enabled: boolean; mode: Mode;
  conditions: PlaybookConditions; actions: PlaybookAction[]; cooldownMin: number;
}>): Promise<Playbook | null> {
  const rows = await query<Row>(
    `UPDATE playbooks SET
       name = COALESCE($2, name),
       description = COALESCE($3, description),
       enabled = COALESCE($4, enabled),
       mode = COALESCE($5, mode),
       conditions = COALESCE($6::jsonb, conditions),
       actions = COALESCE($7::jsonb, actions),
       cooldown_min = COALESCE($8, cooldown_min),
       updated_at = now()
     WHERE id = $1 RETURNING *`,
    [id, data.name ?? null, data.description ?? null, data.enabled ?? null, data.mode ?? null,
     data.conditions ? JSON.stringify(data.conditions) : null,
     data.actions ? JSON.stringify(data.actions) : null, data.cooldownMin ?? null]
  );
  return rows[0] ? toPlaybook(rows[0]) : null;
}

export async function deletePlaybook(id: string): Promise<boolean> {
  const rows = await query<{ id: string }>('DELETE FROM playbooks WHERE id = $1 RETURNING id', [id]);
  return rows.length > 0;
}

export async function listRuns(playbookId?: string, limit = 100): Promise<unknown[]> {
  if (playbookId) {
    return query(
      `SELECT id, playbook_id, playbook_name, target, matched, actions, mode, created_at
         FROM playbook_runs WHERE playbook_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [playbookId, limit]
    );
  }
  return query(
    `SELECT id, playbook_id, playbook_name, target, matched, actions, mode, created_at
       FROM playbook_runs ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );
}

// -------------------- Motor --------------------

let cache: { at: number; items: Playbook[] } | null = null;
const CACHE_TTL = 30_000;

async function enabledPlaybooks(): Promise<Playbook[]> {
  if (cache && Date.now() - cache.at < CACHE_TTL) return cache.items;
  const rows = await query<Row>('SELECT * FROM playbooks WHERE enabled = TRUE');
  const items = rows.map(toPlaybook);
  cache = { at: Date.now(), items };
  return items;
}

function severityFromLevel(level: number): Severity {
  if (level >= 12) return 'critica';
  if (level >= 8) return 'alta';
  if (level >= 5) return 'media';
  return 'baja';
}

function matches(c: PlaybookConditions, a: AlertContext): boolean {
  if (typeof c.minLevel === 'number' && a.level < c.minLevel) return false;
  if (c.ruleIds?.length && !c.ruleIds.includes(a.ruleId)) return false;
  if (c.agents?.length && !c.agents.includes(a.agent)) return false;
  if (c.mitre?.length && !c.mitre.some((m) => a.mitre.includes(m))) return false;
  if (c.groups?.length && !c.groups.some((g) => a.groups.includes(g))) return false;
  return true;
}

/** ¿Ya actuo este playbook sobre este objetivo dentro del cooldown? */
async function inCooldown(playbookId: string, target: string, cooldownMin: number): Promise<boolean> {
  const rows = await query<{ id: string }>(
    `SELECT id FROM playbook_runs
      WHERE playbook_id = $1 AND target = $2
        AND created_at > now() - ($3 || ' minutes')::interval
      LIMIT 1`,
    [playbookId, target, String(cooldownMin)]
  );
  return rows.length > 0;
}

interface ActionResult { type: ActionType; status: 'ejecutado' | 'simulado' | 'omitido' | 'error'; detail?: string }

async function runAction(pb: Playbook, act: PlaybookAction, a: AlertContext): Promise<ActionResult> {
  const sim = pb.mode === 'simulacion';
  try {
    if (act.type === 'block_ip') {
      if (!a.ip) return { type: act.type, status: 'omitido', detail: 'la alerta no tiene IP de origen' };
      if (sim) return { type: act.type, status: 'simulado', detail: `bloquearia ${a.ip}` };
      await block({
        ip: a.ip,
        motivo: `Playbook: ${pb.name} (regla ${a.ruleId}, nivel ${a.level})`,
        user: { id: pb.createdBy ?? '', email: `playbook:${pb.name}` },
        alertaOrigenId: a.alertId,
      });
      return { type: act.type, status: 'ejecutado', detail: `IP ${a.ip} bloqueada` };
    }
    if (act.type === 'create_incident') {
      if (sim) return { type: act.type, status: 'simulado', detail: 'crearia incidente' };
      const inc = await createIncident(
        {
          title: `[Auto] ${a.description || `Alerta ${a.ruleId}`}`.slice(0, 180),
          severity: severityFromLevel(a.level),
          description: `Incidente creado automaticamente por el playbook "${pb.name}".`,
          source: { alertId: a.alertId, ip: a.ip ?? undefined, agent: a.agent, ruleId: a.ruleId, description: a.description, alertTime: a.timestamp },
          // Idempotencia: la misma alerta (alertId) no debe abrir 2 casos. Fallback: regla+host.
          dedupKey: a.alertId ? `alert:${a.alertId}` : `rule:${a.ruleId}:${a.agent ?? ''}`,
        },
        pb.createdBy ?? (null as unknown as string)
      );
      return { type: act.type, status: 'ejecutado', detail: `incidente ${inc.id}` };
    }
    if (act.type === 'notify') {
      if (sim) return { type: act.type, status: 'simulado', detail: 'notificaria' };
      await logNotification({
        tipo: 'immediate', ruleId: a.ruleId, ruleName: `[Playbook ${pb.name}] ${a.description}`,
        origen: a.ip ?? a.agent, recipients: [], status: 'sent',
      });
      return { type: act.type, status: 'ejecutado', detail: 'notificacion in-app emitida' };
    }
    return { type: act.type, status: 'omitido', detail: 'tipo desconocido' };
  } catch (err) {
    return { type: act.type, status: 'error', detail: err instanceof Error ? err.message : 'error' };
  }
}

/** Evalua UN playbook contra una alerta. Devuelve las acciones si actuo, o null
 *  si no hubo match o estaba en cooldown. Nunca lanza. */
export async function evaluatePlaybook(
  pb: Playbook, a: AlertContext, opts: { ignoreCooldown?: boolean } = {}
): Promise<ActionResult[] | null> {
  try {
    if (!matches(pb.conditions, a)) return null;
    const target = a.ip ?? a.agent ?? 'n/d';
    if (!opts.ignoreCooldown && (await inCooldown(pb.id, target, pb.cooldownMin))) return null;

    const results: ActionResult[] = [];
    for (const act of pb.actions) results.push(await runAction(pb, act, a));

    await query(
      `INSERT INTO playbook_runs (playbook_id, playbook_name, target, matched, actions, mode)
       VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6)`,
      [pb.id, pb.name, target,
       JSON.stringify({ level: a.level, ruleId: a.ruleId, ip: a.ip, agent: a.agent, description: a.description }),
       JSON.stringify(results), pb.mode]
    );
    void recordAudit({
      actorEmail: `playbook:${pb.name}`, action: 'playbook_run',
      target, result: results.some((r) => r.status === 'error') ? 'fail' : 'ok',
      detail: { mode: pb.mode, ruleId: a.ruleId, actions: results },
    });
    logger.info({ playbook: pb.name, mode: pb.mode, target, results }, 'Playbook ejecutado');
    return results;
  } catch (err) {
    logger.error({ err, playbook: pb.name }, 'Fallo evaluando playbook');
    return null;
  }
}

/**
 * Evalua una alerta contra los playbooks habilitados y ejecuta/simula.
 * Se llama por cada alerta del vigilante. Nunca lanza.
 */
export async function runPlaybooksForAlert(a: AlertContext): Promise<void> {
  let pbs: Playbook[];
  try {
    pbs = await enabledPlaybooks();
  } catch {
    return;
  }
  for (const pb of pbs) await evaluatePlaybook(pb, a);
}
