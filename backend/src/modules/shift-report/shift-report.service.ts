/**
 * Orquestador del PARTE DE ESTADO: recolecta datos -> arma HTML -> PDF -> envia
 * por Telegram. Destino "interno-primero": por defecto usa TELEGRAM_CHAT_ID (el
 * chat del equipo) para revisar antes de apuntar al cliente. Cuando se defina
 * SHIFT_REPORT_CHAT_IDS, se envia a esa lista (el canal del cliente).
 */
import { collectShiftData, type Turno, type ShiftReportData } from './shift-report.data';
import { renderShiftReport } from './shift-report.template';
import { htmlToPdf } from '../reports/pdf.service';
import { sendTelegramDocument, isTelegramConfigured } from '../notifications/telegram.service';
import { env } from '../../config/env';
import { logger } from '../../config/logger';

/** Chats destino: SHIFT_REPORT_CHAT_IDS (cliente) o, si vacío, el interno. */
export function shiftChatIds(): string[] {
  const raw = process.env.SHIFT_REPORT_CHAT_IDS || env.TELEGRAM_CHAT_ID || '';
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

/** True si el envío apunta al chat interno (sin lista de cliente configurada). */
export function isInternalOnly(): boolean {
  return !process.env.SHIFT_REPORT_CHAT_IDS;
}

export interface ShiftResult {
  data: ShiftReportData;
  pdf: Buffer;
  filename: string;
}

/** Genera el parte (datos + HTML + PDF) sin enviarlo. */
export async function buildShiftReport(turno?: Turno): Promise<ShiftResult & { html: string }> {
  const data = await collectShiftData(turno);
  const html = renderShiftReport(data);
  const pdf = await htmlToPdf(html);
  const fechaCorta = data.generadoEn.slice(0, 10);
  const filename = `HexWatch_Parte_${data.turno === 'am' ? 'Manana' : 'Tarde'}_${fechaCorta}.pdf`;
  return { data, pdf, filename, html };
}

/** Genera y ENVÍA el parte por Telegram. Devuelve a quién se envió. */
export async function sendShiftReport(turno?: Turno): Promise<{ sentTo: string[]; internal: boolean; filename: string }> {
  if (!isTelegramConfigured()) throw new Error('Telegram no configurado (define TELEGRAM_BOT_TOKEN en el .env)');
  const chats = shiftChatIds();
  if (chats.length === 0) throw new Error('Sin chats destino: define SHIFT_REPORT_CHAT_IDS o TELEGRAM_CHAT_ID en el .env');

  const { data, pdf, filename } = await buildShiftReport(turno);
  const internal = isInternalOnly();
  const emoji = data.incidentesCriticos === 0 ? '🟢' : '🟠';
  const caption =
    `${emoji} *HexWatch · ${data.turnoLabel}* — ${data.fecha}\n` +
    `Estaciones: ${data.wkEnLinea} en línea · ${data.wkApagadas} apagadas · ${data.wkAtencion} en atención\n` +
    `Eventos ${data.ventanaLabel}: ${new Intl.NumberFormat('es-CO').format(data.eventos12h)} · Incidentes críticos: ${data.incidentesCriticos}` +
    (internal ? '\n\n_Envío interno de revisión (aún no va al cliente)._' : '');

  await sendTelegramDocument(chats, pdf, filename, caption);
  logger.info({ turno: data.turno, chats: chats.length, internal }, 'Parte de estado enviado');
  return { sentTo: chats, internal, filename };
}
