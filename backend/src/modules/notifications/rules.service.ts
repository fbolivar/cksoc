/**
 * CRUD de reglas de notificacion (tabla alert_configs).
 */
import { query } from '../../config/db';
import { HttpError } from '../auth/auth.service';

export type Channel = 'email' | 'telegram';

export interface AlertRule {
  id: string;
  name: string;
  description: string | null;
  minLevel: number;
  ruleGroups: string[];
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  channels: Channel[];
  emailRecipients: string[];
  telegramChatIds: string[];
  enabled: boolean;
  lastCheckedAt: string | null;
  lastTriggeredAt: string | null;
  createdAt: string;
}

export interface RuleInput {
  name: string;
  description?: string;
  minLevel: number;
  ruleGroups: string[];
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  channels: Channel[];
  emailRecipients: string[];
  telegramChatIds: string[];
  enabled: boolean;
}

interface RuleRow {
  id: string;
  name: string;
  description: string | null;
  min_level: number;
  rule_groups: string[];
  threshold: number;
  window_minutes: number;
  cooldown_minutes: number;
  channels: Channel[];
  email_recipients: string[];
  telegram_chat_ids: string[];
  enabled: boolean;
  last_checked_at: string | null;
  last_triggered_at: string | null;
  created_at: string;
}

function toRule(r: RuleRow): AlertRule {
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    minLevel: r.min_level,
    ruleGroups: r.rule_groups,
    threshold: r.threshold,
    windowMinutes: r.window_minutes,
    cooldownMinutes: r.cooldown_minutes,
    channels: r.channels ?? [],
    emailRecipients: r.email_recipients,
    telegramChatIds: r.telegram_chat_ids,
    enabled: r.enabled,
    lastCheckedAt: r.last_checked_at,
    lastTriggeredAt: r.last_triggered_at,
    createdAt: r.created_at,
  };
}

const SELECT = `
  id, name, description, min_level, rule_groups, threshold, window_minutes,
  cooldown_minutes, channels, email_recipients, telegram_chat_ids, enabled,
  last_checked_at, last_triggered_at, created_at
  FROM alert_configs`;

export async function listRules(): Promise<AlertRule[]> {
  const rows = await query<RuleRow>(`SELECT ${SELECT} ORDER BY created_at DESC`);
  return rows.map(toRule);
}

export async function getRule(id: string): Promise<AlertRule> {
  const rows = await query<RuleRow>(`SELECT ${SELECT} WHERE id = $1`, [id]);
  if (rows.length === 0) throw new HttpError(404, 'Regla no encontrada');
  return toRule(rows[0]);
}

export async function createRule(input: RuleInput, createdBy: string): Promise<AlertRule> {
  const rows = await query<RuleRow>(
    `INSERT INTO alert_configs
      (name, description, min_level, rule_groups, threshold, window_minutes,
       cooldown_minutes, channels, email_recipients, telegram_chat_ids, enabled, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12)
     RETURNING ${SELECT.replace('FROM alert_configs', '')}`,
    [
      input.name,
      input.description ?? null,
      input.minLevel,
      input.ruleGroups,
      input.threshold,
      input.windowMinutes,
      input.cooldownMinutes,
      JSON.stringify(input.channels),
      input.emailRecipients,
      input.telegramChatIds,
      input.enabled,
      createdBy,
    ]
  );
  return toRule(rows[0]);
}

export async function updateRule(id: string, input: RuleInput): Promise<AlertRule> {
  const rows = await query<RuleRow>(
    `UPDATE alert_configs SET
       name=$2, description=$3, min_level=$4, rule_groups=$5, threshold=$6,
       window_minutes=$7, cooldown_minutes=$8, channels=$9::jsonb,
       email_recipients=$10, telegram_chat_ids=$11, enabled=$12, updated_at=now()
     WHERE id=$1
     RETURNING ${SELECT.replace('FROM alert_configs', '')}`,
    [
      id,
      input.name,
      input.description ?? null,
      input.minLevel,
      input.ruleGroups,
      input.threshold,
      input.windowMinutes,
      input.cooldownMinutes,
      JSON.stringify(input.channels),
      input.emailRecipients,
      input.telegramChatIds,
      input.enabled,
    ]
  );
  if (rows.length === 0) throw new HttpError(404, 'Regla no encontrada');
  return toRule(rows[0]);
}

export async function deleteRule(id: string): Promise<void> {
  const rows = await query<{ id: string }>(
    'DELETE FROM alert_configs WHERE id = $1 RETURNING id',
    [id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Regla no encontrada');
}

/** Marca cuando se evaluo / disparo una regla (usado por el evaluador). */
export async function markEvaluated(id: string, triggered: boolean): Promise<void> {
  await query(
    `UPDATE alert_configs
       SET last_checked_at = now()${triggered ? ', last_triggered_at = now()' : ''}
     WHERE id = $1`,
    [id]
  );
}
