/**
 * Notificaciones de Salud del SIEM. Avisa por correo y Telegram cuando un
 * componente cambia de estado (fallo o recuperacion). El monitor garantiza que
 * solo se llama en TRANSICIONES (anti-flood: una vez al fallar, una al recuperarse).
 */
import { query } from '../../config/db';
import { getSettings } from '../notifications/notify.engine';
import { sendEmail, isEmailConfigured } from '../notifications/email.service';
import { sendTelegram, isTelegramConfigured } from '../notifications/telegram.service';
import type { HealthComponent } from './siem-health.service';

async function telegramChatIds(): Promise<string[]> {
  try {
    const rows = await query<{ telegram_chat_ids: string[] }>(
      'SELECT telegram_chat_ids FROM notification_settings WHERE id = 1'
    );
    return rows[0]?.telegram_chat_ids ?? [];
  } catch {
    return [];
  }
}

const ESTADO_TXT: Record<string, string> = { ok: 'OPERATIVO', warn: 'ADVERTENCIA', fail: 'FALLO' };

function emailHtml(c: HealthComponent, kind: 'alerta' | 'recuperacion', prev: string): string {
  const recup = kind === 'recuperacion';
  const color = recup ? '#16a34a' : c.estado === 'fail' ? '#dc2626' : '#d97706';
  const titulo = recup ? 'Componente recuperado' : 'Alerta de salud del SIEM';
  return `<!DOCTYPE html><html lang="es"><body style="margin:0;background:#0b1220;font-family:Segoe UI,Arial,sans-serif;color:#e5e7eb">
  <div style="max-width:560px;margin:0 auto;padding:24px">
    <div style="background:linear-gradient(135deg,#0a3d2e,#0b2a4a);border-radius:12px 12px 0 0;padding:18px 22px">
      <div style="font-size:12px;letter-spacing:2px;color:#7dd3a8">SOC · PARQUES NACIONALES NATURALES DE COLOMBIA</div>
      <div style="font-size:18px;font-weight:700;margin-top:4px">Salud del SIEM</div>
    </div>
    <div style="background:#0f172a;border:1px solid #1e293b;border-top:0;border-radius:0 0 12px 12px;padding:22px">
      <div style="display:inline-block;background:${color};color:#fff;font-weight:700;border-radius:6px;padding:6px 12px;font-size:13px">${titulo}</div>
      <h2 style="margin:16px 0 6px;font-size:20px">${c.nombre}</h2>
      <p style="margin:0 0 14px;color:#94a3b8">Estado: <b style="color:${color}">${ESTADO_TXT[c.estado] ?? c.estado}</b>
        <span style="color:#64748b">(antes: ${ESTADO_TXT[prev] ?? prev})</span></p>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:8px 0;color:#94a3b8;width:120px">Resumen</td><td style="padding:8px 0">${c.resumen}</td></tr>
        ${c.detalle ? `<tr><td style="padding:8px 0;color:#94a3b8">Detalle</td><td style="padding:8px 0">${c.detalle}</td></tr>` : ''}
        <tr><td style="padding:8px 0;color:#94a3b8">Hora</td><td style="padding:8px 0">${new Date().toLocaleString('es-CO', { timeZone: 'America/Bogota' })}</td></tr>
      </table>
      <p style="margin:18px 0 0;font-size:12px;color:#64748b">Mensaje automatico del modulo de Salud del SIEM. No responder.</p>
    </div>
  </div></body></html>`;
}

/** Notifica una transicion de estado de un componente. */
export async function notifyHealthChange(
  c: HealthComponent,
  prev: string,
  kind: 'alerta' | 'recuperacion'
): Promise<void> {
  const estadoTxt = ESTADO_TXT[c.estado] ?? c.estado;
  const subject = kind === 'recuperacion'
    ? `[SOC PNNC] RECUPERADO: ${c.nombre} de nuevo OPERATIVO`
    : `[SOC PNNC] ALERTA SALUD: ${c.nombre} en estado ${estadoTxt}`;
  const linea = `${c.nombre}: ${estadoTxt}. ${c.resumen}${c.detalle ? ` — ${c.detalle}` : ''}`;

  // Correo
  try {
    const { recipients } = await getSettings();
    if (isEmailConfigured() && recipients.length) {
      await sendEmail(recipients, subject, emailHtml(c, kind, prev), `${subject}\n\n${linea}`);
    }
  } catch {
    /* el correo no debe tumbar el monitor */
  }

  // Telegram
  try {
    const chats = await telegramChatIds();
    if (isTelegramConfigured() && chats.length) {
      const icon = kind === 'recuperacion' ? '✅' : c.estado === 'fail' ? '🔴' : '🟠';
      await sendTelegram(chats, `${icon} <b>Salud del SIEM</b>\n${subject}\n\n${linea}`);
    }
  } catch {
    /* idem */
  }
}
