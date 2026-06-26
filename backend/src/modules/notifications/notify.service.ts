/**
 * Despacho de notificaciones a los canales configurados y registro en BD.
 */
import { query } from '../../config/db';
import type { AlertRule } from './rules.service';
import { sendEmail, isEmailConfigured } from './email.service';
import { sendTelegram, isTelegramConfigured } from './telegram.service';

export interface ChannelStatus {
  email: { configured: boolean };
  telegram: { configured: boolean };
}

export function channelStatus(): ChannelStatus {
  return {
    email: { configured: isEmailConfigured() },
    telegram: { configured: isTelegramConfigured() },
  };
}

/** Registra un envio (exitoso o fallido) en notification_log. */
async function log(
  ruleId: string | null,
  ruleName: string,
  channel: string,
  recipients: string[],
  matchedCount: number | null,
  status: 'sent' | 'failed',
  error?: string
): Promise<void> {
  await query(
    `INSERT INTO notification_log
       (rule_id, rule_name, channel, recipients, matched_count, status, error)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [ruleId, ruleName, channel, recipients, matchedCount, status, error ?? null]
  );
}

/** Construye el contenido del mensaje para una regla disparada. */
function buildMessages(rule: AlertRule, matchedCount: number) {
  const now = new Date().toLocaleString('es-CO');
  const subject = `🚨 SOC PNNC · ${rule.name}`;
  const lines = [
    `*🚨 ALERTA DE SEGURIDAD · SOC PNNC*`,
    ``,
    `*Regla:* ${rule.name}`,
    rule.description ? `${rule.description}` : '',
    ``,
    `*${matchedCount}* alertas con nivel ≥ *${rule.minLevel}* en los últimos *${rule.windowMinutes} min*`,
    rule.ruleGroups.length ? `*Grupos:* ${rule.ruleGroups.join(', ')}` : '',
    ``,
    `_${now}_`,
    `Parques Nacionales Naturales de Colombia`,
  ].filter(Boolean);
  const text = lines.join('\n').replace(/\*/g, '').replace(/_/g, '');

  const html = `
  <div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:auto;background:#0f1613;color:#e6f2ec;border-radius:12px;overflow:hidden;border:1px solid #1d2b25">
    <div style="background:#0f3d24;padding:18px 24px;border-bottom:3px solid #85b425">
      <h2 style="margin:0;font-size:16px;color:#fff">Centro de Operaciones de Seguridad · PNNC</h2>
    </div>
    <div style="padding:24px">
      <p style="color:#f97316;font-weight:700;font-size:18px;margin:0 0 12px">🚨 ${rule.name}</p>
      ${rule.description ? `<p style="color:#9fb3aa;margin:0 0 16px">${rule.description}</p>` : ''}
      <div style="background:#16a34a1a;border:1px solid #16a34a55;border-radius:8px;padding:16px;margin-bottom:16px">
        <span style="font-size:32px;font-weight:800;color:#34d399">${matchedCount}</span>
        <span style="color:#9fb3aa"> alertas con nivel ≥ ${rule.minLevel} en los últimos ${rule.windowMinutes} min</span>
      </div>
      ${rule.ruleGroups.length ? `<p style="color:#9fb3aa;font-size:13px">Grupos: ${rule.ruleGroups.join(', ')}</p>` : ''}
      <p style="color:#6b7c74;font-size:12px;margin-top:20px">${now} · Parques Nacionales Naturales de Colombia</p>
    </div>
  </div>`;

  return { subject, html, text, telegramText: lines.join('\n') };
}

/** Envia las notificaciones de una regla disparada por todos sus canales. */
export async function notifyForRule(rule: AlertRule, matchedCount: number): Promise<void> {
  const { subject, html, text, telegramText } = buildMessages(rule, matchedCount);

  if (rule.channels.includes('email') && rule.emailRecipients.length > 0) {
    try {
      await sendEmail(rule.emailRecipients, subject, html, text);
      await log(rule.id, rule.name, 'email', rule.emailRecipients, matchedCount, 'sent');
    } catch (err) {
      await log(rule.id, rule.name, 'email', rule.emailRecipients, matchedCount, 'failed', errMsg(err));
    }
  }

  if (rule.channels.includes('telegram') && rule.telegramChatIds.length > 0) {
    try {
      await sendTelegram(rule.telegramChatIds, telegramText);
      await log(rule.id, rule.name, 'telegram', rule.telegramChatIds, matchedCount, 'sent');
    } catch (err) {
      await log(rule.id, rule.name, 'telegram', rule.telegramChatIds, matchedCount, 'failed', errMsg(err));
    }
  }
}

/** Envia un mensaje de prueba por un canal concreto. */
export async function testSend(channel: 'email' | 'telegram', target: string): Promise<void> {
  const subject = '✅ SOC PNNC · Mensaje de prueba';
  const text = 'Mensaje de prueba del Centro de Operaciones de Seguridad de PNNC. Si lo recibes, el canal funciona correctamente.';
  if (channel === 'email') {
    await sendEmail(
      [target],
      subject,
      `<div style="font-family:Inter,Arial,sans-serif">${text}</div>`,
      text
    );
    await log(null, 'Prueba manual', 'email', [target], null, 'sent');
  } else {
    await sendTelegram([target], `*✅ SOC PNNC*\n${text}`);
    await log(null, 'Prueba manual', 'telegram', [target], null, 'sent');
  }
}

/** Historial reciente de notificaciones. */
export async function recentLog(limit = 50) {
  return query(
    `SELECT id, rule_name, channel, recipients, matched_count, status, error, created_at
       FROM notification_log ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : 'error desconocido';
}
