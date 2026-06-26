/**
 * Motor de notificaciones por correo: settings, contador diario con tope de
 * seguridad, anti-flood (misma regla+origen en 30 min) y registro.
 * Las plantillas HTML llevan identidad PNNC.
 */
import { query } from '../../config/db';
import { env } from '../../config/env';
import { sendEmail, isEmailConfigured, type MailAttachment } from './email.service';

export interface NotifySettings {
  recipients: string[];
  immediateEnabled: boolean;
  digestEnabled: boolean;
  digestHour: number;
}

interface SettingsRow {
  recipients: string[];
  immediate_enabled: boolean;
  digest_enabled: boolean;
  digest_hour: number;
}

/** Lee la configuracion (singleton). Si recipients esta vacio, usa ALERT_RECIPIENTS del env. */
export async function getSettings(): Promise<NotifySettings> {
  const rows = await query<SettingsRow>(
    `SELECT recipients, immediate_enabled, digest_enabled, digest_hour
       FROM notification_settings WHERE id = 1`
  );
  const r = rows[0];
  const envRecipients = env.ALERT_RECIPIENTS.split(',').map((s) => s.trim()).filter(Boolean);
  if (!r) {
    return { recipients: envRecipients, immediateEnabled: true, digestEnabled: true, digestHour: 8 };
  }
  return {
    recipients: r.recipients.length > 0 ? r.recipients : envRecipients,
    immediateEnabled: r.immediate_enabled,
    digestEnabled: r.digest_enabled,
    digestHour: r.digest_hour,
  };
}

export async function updateSettings(s: Partial<NotifySettings>): Promise<NotifySettings> {
  await query(
    `UPDATE notification_settings SET
       recipients = COALESCE($1, recipients),
       immediate_enabled = COALESCE($2, immediate_enabled),
       digest_enabled = COALESCE($3, digest_enabled),
       digest_hour = COALESCE($4, digest_hour),
       updated_at = now()
     WHERE id = 1`,
    [s.recipients ?? null, s.immediateEnabled ?? null, s.digestEnabled ?? null, s.digestHour ?? null]
  );
  return getSettings();
}

// ---------------- contador diario / tope de seguridad ----------------

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Cuenta de correos enviados hoy y si el tope esta alcanzado. */
export async function dailyStatus(): Promise<{ sent: number; cap: number; capReached: boolean }> {
  const rows = await query<{ enviados: number }>(
    'SELECT enviados FROM daily_counter WHERE fecha = $1',
    [today()]
  );
  const sent = rows[0]?.enviados ?? 0;
  return { sent, cap: env.NOTIFY_DAILY_CAP, capReached: sent >= env.NOTIFY_DAILY_CAP };
}

/** Incrementa el contador del dia y devuelve el nuevo total. */
async function incrementDaily(n = 1): Promise<number> {
  const rows = await query<{ enviados: number }>(
    `INSERT INTO daily_counter (fecha, enviados) VALUES ($1, $2)
     ON CONFLICT (fecha) DO UPDATE SET enviados = daily_counter.enviados + $2
     RETURNING enviados`,
    [today(), n]
  );
  return rows[0].enviados;
}

/** Marca que ya se aviso del tope hoy (para no repetir el aviso). */
async function markCapWarned(): Promise<boolean> {
  const rows = await query<{ cap_avisado: boolean }>(
    `INSERT INTO daily_counter (fecha, enviados, cap_avisado) VALUES ($1, 0, TRUE)
     ON CONFLICT (fecha) DO UPDATE SET cap_avisado = TRUE
     WHERE daily_counter.cap_avisado = FALSE
     RETURNING cap_avisado`,
    [today()]
  );
  return rows.length > 0; // true si acabamos de marcarlo (no estaba avisado)
}

// ---------------- anti-flood ----------------

/** True si ya se notifico esta regla+origen en la ventana anti-flood. */
export async function recentlyNotified(ruleId: string, origen: string): Promise<boolean> {
  const rows = await query<{ id: string }>(
    `SELECT id FROM notification_log
      WHERE tipo = 'immediate' AND status = 'sent'
        AND alert_rule_id = $1 AND origen = $2
        AND created_at > now() - ($3 || ' minutes')::interval
      LIMIT 1`,
    [ruleId, origen, String(env.NOTIFY_FLOOD_MINUTES)]
  );
  return rows.length > 0;
}

// ---------------- registro ----------------

export async function logNotification(opts: {
  tipo: string;
  ruleId?: string;
  ruleName?: string;
  origen?: string;
  recipients: string[];
  status: 'sent' | 'failed' | 'skipped';
  error?: string;
}): Promise<void> {
  await query(
    `INSERT INTO notification_log
       (tipo, alert_rule_id, rule_name, origen, channel, recipients, status, error)
     VALUES ($1,$2,$3,$4,'email',$5,$6,$7)`,
    [opts.tipo, opts.ruleId ?? null, opts.ruleName ?? null, opts.origen ?? null,
     opts.recipients, opts.status, opts.error ?? null]
  );
}

// ---------------- envio con tope ----------------

/**
 * Envia un correo respetando el tope diario. Si el tope esta alcanzado, no
 * envia y (una sola vez al dia) manda un aviso de "limite alcanzado".
 * Devuelve true si se envio.
 */
export async function sendCapped(
  to: string[],
  subject: string,
  html: string,
  text: string,
  meta: { tipo: string; ruleId?: string; ruleName?: string; origen?: string },
  attachments?: MailAttachment[]
): Promise<boolean> {
  if (!isEmailConfigured()) {
    await logNotification({ ...meta, recipients: to, status: 'failed', error: 'SMTP no configurado' });
    return false;
  }
  const status = await dailyStatus();
  if (status.capReached) {
    // Aviso unico de tope alcanzado
    if (await markCapWarned()) {
      try {
        await sendEmail(to, '[SOC PNNC] Limite diario de correos alcanzado',
          capWarningHtml(status.sent, status.cap), `Se alcanzo el tope de ${status.cap} correos hoy.`);
      } catch { /* nada */ }
      await logNotification({ tipo: 'cap', recipients: to, status: 'sent' });
    }
    await logNotification({ ...meta, recipients: to, status: 'skipped', error: 'tope diario alcanzado' });
    return false;
  }
  try {
    await sendEmail(to, subject, html, text, attachments);
    await incrementDaily(1);
    await logNotification({ ...meta, recipients: to, status: 'sent' });
    return true;
  } catch (err) {
    await logNotification({ ...meta, recipients: to, status: 'failed', error: err instanceof Error ? err.message : 'error' });
    return false;
  }
}

// ---------------- plantillas HTML PNNC ----------------

const esc = (s: string) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function shell(title: string, accent: string, bodyHtml: string): string {
  return `<div style="font-family:Inter,Arial,sans-serif;max-width:640px;margin:auto;background:#0f1613;color:#e6f2ec;border-radius:12px;overflow:hidden;border:1px solid #1d2b25">
    <div style="background:#16294f;padding:16px 24px;border-bottom:3px solid ${accent}">
      <h2 style="margin:0;font-size:15px;color:#fff">Centro de Operaciones de Seguridad &middot; PNNC</h2>
      <p style="margin:2px 0 0;font-size:11px;color:#c5d2ea">Parques Nacionales Naturales de Colombia &middot; GOV.CO</p>
    </div>
    <div style="padding:22px 24px">${bodyHtml}</div>
    <div style="padding:12px 24px;border-top:1px solid #1d2b25;color:#6b7c74;font-size:10px;display:flex;justify-content:space-between">
      <span>${esc(title)}</span><span>Confidencial &middot; Uso interno</span>
    </div>
  </div>`;
}

export interface ImmediateAlert {
  level: number;
  ruleId: string;
  description: string;
  agent: string;
  origin?: string;
  geo?: { country: string; city: string } | null;
  reputation?: { abuseScore: number; totalReports: number } | null;
  timestamp: string;
}

export function immediateEmail(a: ImmediateAlert): { subject: string; html: string; text: string } {
  const critical = a.level >= 12;
  const accent = critical ? '#ef4444' : '#f97316';
  const sevLabel = critical ? 'CRITICA' : 'ALTA';
  const subject = `[SOC PNNC] ${sevLabel}: ${a.description.slice(0, 80)}`;
  const fecha = new Date(a.timestamp).toLocaleString('es-CO', { timeZone: env.DIGEST_TZ });
  const rows: [string, string][] = [
    ['Severidad', `nivel ${a.level} (${sevLabel})`],
    ['Regla', `${a.ruleId} — ${esc(a.description)}`],
    ['Agente', esc(a.agent)],
  ];
  if (a.origin) rows.push(['IP origen', esc(a.origin)]);
  if (a.geo) rows.push(['Geolocalizacion', esc([a.geo.country, a.geo.city].filter(Boolean).join(' · '))]);
  if (a.reputation && a.reputation.totalReports > 0)
    rows.push(['Reputacion AbuseIPDB', `${a.reputation.abuseScore}/100 · ${a.reputation.totalReports} reportes`]);
  rows.push(['Fecha', fecha]);

  const table = rows.map(([k, v]) =>
    `<tr><td style="padding:5px 8px;color:#9fb3aa;white-space:nowrap;vertical-align:top">${k}</td><td style="padding:5px 8px">${v}</td></tr>`
  ).join('');

  const body = `
    <p style="color:${accent};font-weight:700;font-size:18px;margin:0 0 12px">⚠ Alerta ${sevLabel}</p>
    <table style="width:100%;border-collapse:collapse;font-size:13px">${table}</table>
    <a href="${env.PUBLIC_DASHBOARD_URL}/respuesta" style="display:inline-block;margin-top:18px;background:#1f7a4d;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-size:13px">Revisar en el dashboard</a>`;
  const text = `[SOC PNNC] ${sevLabel}: ${a.description}\nNivel ${a.level} | Regla ${a.ruleId} | Agente ${a.agent}` +
    (a.origin ? ` | IP ${a.origin}` : '') + `\n${fecha}\n${env.PUBLIC_DASHBOARD_URL}/respuesta`;
  return { subject, html: shell(subject, accent, body), text };
}

function capWarningHtml(sent: number, cap: number): string {
  return shell('Tope diario', '#eab308',
    `<p style="color:#facc15;font-weight:700">Limite diario de correos alcanzado</p>
     <p>Se alcanzo el tope de seguridad de <b>${cap}</b> correos hoy (enviados: ${sent}). Para proteger la cuota de la cuenta institucional, no se enviaran mas correos individuales hoy; las alertas siguen visibles en el dashboard y se incluiran en el resumen diario.</p>`);
}

export { shell };
