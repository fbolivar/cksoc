/**
 * Envio de mensajes por Telegram usando la Bot API (HTTP, sin polling).
 * Solo se usa para enviar; no requiere la libreria pesada con long-polling.
 */
import axios from 'axios';
import { env } from '../../config/env';

export function isTelegramConfigured(): boolean {
  return Boolean(env.TELEGRAM_BOT_TOKEN);
}

const apiUrl = () => `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}`;

/** Envia un mensaje (Markdown) a uno o varios chats. */
export async function sendTelegram(chatIds: string[], text: string): Promise<void> {
  if (!isTelegramConfigured()) {
    throw new Error('Telegram no configurado (define TELEGRAM_BOT_TOKEN en el .env)');
  }
  for (const chatId of chatIds) {
    await axios.post(`${apiUrl()}/sendMessage`, {
      chat_id: chatId,
      text,
      parse_mode: 'Markdown',
      disable_web_page_preview: true,
    });
  }
}

/**
 * Envia un documento (p.ej. un PDF) a uno o varios chats con un pie opcional.
 * Usa multipart/form-data (sendDocument) con el buffer en memoria.
 */
export async function sendTelegramDocument(
  chatIds: string[],
  file: Buffer,
  filename: string,
  caption?: string
): Promise<void> {
  if (!isTelegramConfigured()) {
    throw new Error('Telegram no configurado (define TELEGRAM_BOT_TOKEN en el .env)');
  }
  for (const chatId of chatIds) {
    const form = new FormData();
    form.append('chat_id', chatId);
    if (caption) {
      form.append('caption', caption.slice(0, 1024));
      form.append('parse_mode', 'Markdown');
    }
    form.append('document', new Blob([file], { type: 'application/pdf' }), filename);
    await axios.post(`${apiUrl()}/sendDocument`, form, {
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    });
  }
}

/** Verifica el token del bot (getMe) para el boton de prueba. */
export async function verifyTelegram(): Promise<{ username: string }> {
  if (!isTelegramConfigured()) throw new Error('Telegram no configurado');
  const { data } = await axios.get<{ ok: boolean; result: { username: string } }>(
    `${apiUrl()}/getMe`
  );
  return { username: data.result.username };
}
